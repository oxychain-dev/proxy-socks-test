mod input;
mod interface;
mod model;
mod store;
mod subscription;
mod validate;

use anyhow::{anyhow, Context, Result};
use model::{BatchResult, IpMetadata, ProbeMetrics, StageResult, TestProfile};
use reqwest::{Client, Url};
use std::{
    collections::{BTreeMap, HashSet},
    env, fmt,
    net::IpAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs,
    io::{AsyncWriteExt, BufWriter},
    task::JoinSet,
};

#[derive(Clone, Debug)]
pub struct BatchOptions {
    pub proxy_files: Vec<String>,
    pub source_lists: Vec<String>,
    pub source_urls: Vec<String>,
    pub inline_proxy_sources: Vec<(String, String)>,
    pub inline_source_lists: Vec<(String, String)>,
    pub output: String,
    pub write_tsv: bool,
    pub valid_output: Option<String>,
    pub database: String,
    pub interfaces: Vec<String>,
    pub all_interfaces: bool,
    pub default_protocol: String,
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub check_url: String,
    pub profile: String,
    pub latency_samples: usize,
    pub download_url: String,
    pub upload_url: String,
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub ip_info_url_template: Option<String>,
    pub subscription_id: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) enum ProxyProtocol {
    Auto,
    Socks4,
    Socks4a,
    Socks5,
}

impl ProxyProtocol {
    pub(super) fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "socks4" => Ok(Self::Socks4),
            "socks4a" => Ok(Self::Socks4a),
            "socks5" | "socks5h" => Ok(Self::Socks5),
            _ => Err(anyhow!("unsupported SOCKS protocol: {value}")),
        }
    }

    pub(super) fn scheme(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Socks4 => "socks4",
            Self::Socks4a => "socks4a",
            Self::Socks5 => "socks5",
        }
    }

    pub(super) fn reqwest_scheme(self) -> &'static str {
        match self {
            Self::Socks4 => "socks4",
            Self::Socks4a => "socks4a",
            Self::Socks5 | Self::Auto => "socks5h",
        }
    }
}

impl fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.scheme())
    }
}

#[derive(Clone, Debug)]
pub(super) struct ProxySpec {
    pub(super) raw: String,
    pub(super) source: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) username: Option<String>,
    pub(super) password: Option<String>,
    pub(super) protocol: ProxyProtocol,
}

impl ProxySpec {
    pub(super) fn dedupe_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.protocol,
            self.host.to_ascii_lowercase(),
            self.port,
            self.username.as_deref().unwrap_or_default(),
            self.password.as_deref().unwrap_or_default()
        )
    }

    pub(super) fn proxy_url(&self, protocol: ProxyProtocol, tested_ip: IpAddr) -> Result<Url> {
        if protocol != ProxyProtocol::Socks5 && self.username.is_some() {
            return Err(anyhow!("credentials are supported only for SOCKS5 batch validation"));
        }

        let host = match tested_ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        let mut url =
            Url::parse(&format!("{}://{}:{}", protocol.reqwest_scheme(), host, self.port))?;
        if let Some(username) = &self.username {
            url.set_username(username).map_err(|_| anyhow!("invalid proxy username"))?;
            url.set_password(Some(self.password.as_deref().unwrap_or_default()))
                .map_err(|_| anyhow!("invalid proxy password"))?;
        }
        Ok(url)
    }

    pub(super) fn report_input(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let scheme = if self.raw.contains("://") {
            format!("{}://", self.protocol.scheme())
        } else {
            String::new()
        };
        format!("{scheme}{host}:{}", self.port)
    }

    pub(super) fn report_source(&self) -> String {
        redact_source(&self.source)
    }

    pub(super) fn normalized(&self, protocol: ProxyProtocol) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let auth = match (&self.username, &self.password) {
            (Some(user), Some(pass)) => format!("{user}:{pass}@"),
            (Some(user), None) => format!("{user}@"),
            _ => String::new(),
        };
        format!("{}://{}{}:{}", protocol.scheme(), auth, host, self.port)
    }
}

impl BatchResult {
    fn tsv_row(&self, target: &interface::InterfaceTarget, tester_ip: Option<IpAddr>) -> String {
        let tester_ip = tester_ip.map(|ip| ip.to_string()).unwrap_or_default();
        let protocol = self
            .metrics
            .as_ref()
            .map(|m| m.protocol.to_string())
            .unwrap_or_else(|| self.proxy.protocol.to_string());
        let resolved_ips =
            self.resolved_ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
        let tested_ip = self.tested_ip.map(|ip| ip.to_string()).unwrap_or_default();
        let endpoint_connect_ms =
            self.endpoint_connect_ms.map(|value| value.to_string()).unwrap_or_default();
        let validation_latency_ms =
            self.metrics.as_ref().map(|m| m.validation_latency_ms.to_string()).unwrap_or_default();
        let exit_ip = self.metrics.as_ref().map(|m| m.exit_ip.to_string()).unwrap_or_default();
        let exit_changed =
            self.metrics.as_ref().map(|m| m.exit_ip_changed.to_string()).unwrap_or_default();
        let endpoint_info = self.endpoint_ip_info.as_ref();
        let exit_info = self.metrics.as_ref().and_then(|m| m.exit_ip_info.as_ref());

        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            tsv_escape(&self.proxy.report_source()),
            tsv_escape(&self.proxy.report_input()),
            tsv_escape(target.label()),
            tsv_escape(&target.local_ips_text()),
            tester_ip,
            tsv_escape(&self.proxy.host),
            resolved_ips,
            tested_ip,
            tsv_escape(self.reverse_dns.as_deref().unwrap_or_default()),
            self.proxy.port,
            self.valid(),
            protocol,
            endpoint_connect_ms,
            validation_latency_ms,
            format_metric(self.metrics.as_ref().and_then(|m| m.latency_p50_ms)),
            format_metric(self.metrics.as_ref().and_then(|m| m.latency_p95_ms)),
            format_metric(self.metrics.as_ref().and_then(|m| m.jitter_ms)),
            format_metric(self.metrics.as_ref().and_then(|m| m.download_mbps)),
            format_metric(self.metrics.as_ref().and_then(|m| m.upload_mbps)),
            exit_ip,
            exit_changed,
            tsv_escape(endpoint_info.and_then(|m| m.country.as_deref()).unwrap_or_default()),
            tsv_escape(endpoint_info.and_then(|m| m.asn.as_deref()).unwrap_or_default()),
            tsv_escape(
                endpoint_info
                    .and_then(|m| m.organization.as_deref())
                    .unwrap_or_default()
            ),
            tsv_escape(exit_info.and_then(|m| m.country.as_deref()).unwrap_or_default()),
            tsv_escape(exit_info.and_then(|m| m.asn.as_deref()).unwrap_or_default()),
            tsv_escape(
                exit_info
                    .and_then(|m| m.organization.as_deref())
                    .unwrap_or_default()
            ),
            tsv_escape(&stage_status_text(&self.stages)),
            tsv_escape(self.error.as_deref().unwrap_or_default())
        )
    }
}

#[derive(Default)]
struct SummaryAccumulator {
    tested: usize,
    valid: usize,
    protocol_counts: BTreeMap<String, usize>,
    stage_status_counts: BTreeMap<String, usize>,
    failure_stage_counts: BTreeMap<&'static str, usize>,
    latency_samples_ms: Vec<f64>,
    jitters_ms: Vec<f64>,
    download_mbps: Vec<f64>,
    upload_mbps: Vec<f64>,
    exit_ips: HashSet<IpAddr>,
    exit_ip_changed_checks: usize,
}

impl SummaryAccumulator {
    fn observe(&mut self, result: &BatchResult) {
        self.tested += 1;
        for stage in &result.stages {
            let key = format!("{}:{}:{}", stage.stage, stage.name, stage.status.as_str());
            *self.stage_status_counts.entry(key).or_default() += 1;
        }
        for failure in result.stage_failure_labels() {
            *self.failure_stage_counts.entry(failure).or_default() += 1;
        }

        let Some(metrics) = result.metrics.as_ref() else {
            return;
        };
        self.valid += 1;
        *self.protocol_counts.entry(metrics.protocol.to_string()).or_default() += 1;
        self.latency_samples_ms
            .extend(metrics.latency_samples_ms.iter().map(|value| *value as f64));
        if let Some(jitter) = metrics.jitter_ms {
            self.jitters_ms.push(jitter);
        }
        if let Some(download) = metrics.download_mbps {
            self.download_mbps.push(download);
        }
        if let Some(upload) = metrics.upload_mbps {
            self.upload_mbps.push(upload);
        }
        self.exit_ips.insert(metrics.exit_ip);
        if metrics.exit_ip_changed {
            self.exit_ip_changed_checks += 1;
        }
    }

    fn print(&self, label: &str) {
        println!("{}", self.render(label));
    }

    fn render(&self, label: &str) -> String {
        let invalid = self.tested.saturating_sub(self.valid);
        let latency_p50 = summary_percentile(&self.latency_samples_ms, 0.50);
        let latency_p95 = summary_percentile(&self.latency_samples_ms, 0.95);
        let jitter_avg = average(&self.jitters_ms);
        let download_avg = average(&self.download_mbps);
        let upload_avg = average(&self.upload_mbps);
        format!(
            "summary[{label}]: tested={} valid={} invalid={} protocols={} stages={} failures={} latency_p50_ms={} latency_p95_ms={} jitter_avg_ms={} download_avg_mbps={} upload_avg_mbps={} unique_exit_ips={} exit_ip_changed_checks={}",
            self.tested,
            self.valid,
            invalid,
            format_counts(&self.protocol_counts),
            format_counts(&self.stage_status_counts),
            format_counts(&self.failure_stage_counts),
            format_optional_metric(latency_p50),
            format_optional_metric(latency_p95),
            format_optional_metric(jitter_avg),
            format_optional_metric(download_avg),
            format_optional_metric(upload_avg),
            self.exit_ips.len(),
            self.exit_ip_changed_checks,
        )
    }
}

fn format_counts<K>(counts: &BTreeMap<K, usize>) -> String
where
    K: Ord + std::fmt::Display,
{
    if counts.is_empty() {
        return "-".to_owned();
    }
    counts.iter().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join(",")
}

fn summary_percentile(values: &[f64], percentile: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    let rank = ((values.len() - 1) as f64 * percentile.clamp(0.0, 1.0)).ceil() as usize;
    values.get(rank).copied()
}

fn average(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

fn format_optional_metric(value: Option<f64>) -> String {
    value.map(|value| format!("{value:.3}")).unwrap_or_else(|| "-".to_owned())
}

pub async fn run_subscription_command(
    matches: &clap::ArgMatches,
    database: &str,
) -> Result<()> {
    subscription::handle_subscription_command(matches, database).await
}

pub async fn run_service(
    database: &str,
    poll_seconds: u64,
    retention_days: u64,
    once: bool,
) -> Result<()> {
    subscription::run_service(database, poll_seconds, retention_days, once).await
}

#[derive(Clone, Copy, Debug)]
pub(super) struct BatchRunOutcome {
    pub(super) run_id: i64,
    pub(super) proxy_count: usize,
    pub(super) tested: usize,
    pub(super) valid: usize,
}

pub async fn run_batch(options: BatchOptions) -> Result<()> {
    run_batch_with_outcome(options).await.map(|_| ())
}

pub(super) async fn run_batch_with_outcome(options: BatchOptions) -> Result<BatchRunOutcome> {
    validate_options(&options)?;

    let check_url = Url::parse(&options.check_url).context("invalid --check-url")?;
    if !matches!(check_url.scheme(), "http" | "https") {
        return Err(anyhow!("--check-url must use http:// or https://"));
    }

    let targets = interface::select_targets(&options.interfaces, options.all_interfaces)?;
    println!(
        "network targets: {}",
        targets.iter().map(interface::InterfaceTarget::label).collect::<Vec<_>>().join(", ")
    );

    let default_protocol = ProxyProtocol::parse(&options.default_protocol)?;
    let _profile = TestProfile::parse(&options.profile)?;
    let source_client = Client::builder()
        .no_proxy()
        .user_agent(concat!("proxy-socks-test/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(options.timeout_secs.max(15)))
        .build()
        .context("failed to build source download client")?;

    let (proxies, load_stats) =
        input::load_proxies(&source_client, &options, default_protocol).await?;
    if proxies.is_empty() {
        return Err(anyhow!("no valid proxy entries found in the supplied inputs"));
    }

    println!(
        "loaded {} unique proxies ({} malformed skipped, {} source errors)",
        proxies.len(),
        load_stats.malformed_entries,
        load_stats.source_errors
    );

    let mut output = if options.write_tsv {
        let output_file = fs::File::create(&options.output)
            .await
            .with_context(|| format!("failed to create TSV output {}", options.output))?;
        let mut output = BufWriter::new(output_file);
        output
            .write_all(
                b"source\tinput\tinterface\tlocal_ips\ttester_ip\tproxy_host\tresolved_ips\ttested_ip\treverse_dns\tproxy_port\tvalid\tprotocol\ttcp_connect_ms\tvalidation_latency_ms\tlatency_p50_ms\tlatency_p95_ms\tjitter_ms\tdownload_mbps\tupload_mbps\texit_ip\texit_ip_changed\tendpoint_country\tendpoint_asn\tendpoint_org\texit_country\texit_asn\texit_org\tstages\terror\n",
            )
            .await?;
        Some(output)
    } else {
        None
    };

    let mut valid_output = if let Some(path) = &options.valid_output {
        Some(BufWriter::new(
            fs::File::create(path)
                .await
                .with_context(|| format!("failed to create valid proxy output {path}"))?,
        ))
    } else {
        None
    };

    let store = store::Store::open(&options.database)?;
    let run_id = store.start_run(&options, proxies.len(), targets.len())?;
    let shared = Arc::new(options);
    let total_checks = proxies.len().saturating_mul(targets.len());
    let mut tested = 0usize;
    let mut valid = 0usize;
    let mut valid_written = HashSet::new();
    let enrichment_cache = validate::new_ip_info_cache();
    let mut overall_summary = SummaryAccumulator::default();

    for target in targets {
        let target = Arc::new(target);
        let tester_ip = match validate::detect_tester_ip(&shared, &target).await {
            Ok(ip) => {
                println!("interface {} tester public IP: {ip}", target.label());
                Some(ip)
            }
            Err(err) => {
                eprintln!(
                    "warning: interface {} could not determine tester public IP: {err:#}",
                    target.label()
                );
                None
            }
        };
        let interface_run_id = store.start_interface_run(run_id, &target, tester_ip)?;
        let mut interface_summary = SummaryAccumulator::default();

        let mut iter = proxies.iter().cloned();
        let mut tasks = JoinSet::new();
        for _ in 0..shared.concurrency.min(proxies.len()) {
            if let Some(proxy) = iter.next() {
                spawn_validation(
                    &mut tasks,
                    proxy,
                    Arc::clone(&shared),
                    Arc::clone(&target),
                    Arc::clone(&enrichment_cache),
                );
            }
        }

        let mut interface_tested = 0usize;
        let mut interface_valid = 0usize;
        while let Some(joined) = tasks.join_next().await {
            let result = joined.context("proxy validation task failed")?;
            tested += 1;
            interface_tested += 1;
            if result.valid() {
                valid += 1;
                interface_valid += 1;
                if let (Some(writer), Some(metrics)) =
                    (valid_output.as_mut(), result.metrics.as_ref())
                {
                    let normalized = result.proxy.normalized(metrics.protocol);
                    if valid_written.insert(normalized.clone()) {
                        writer.write_all(format!("{normalized}\n").as_bytes()).await?;
                    }
                }
            }

            store.insert_result(interface_run_id, &result)?;
            interface_summary.observe(&result);
            overall_summary.observe(&result);
            if let Some(writer) = output.as_mut() {
                writer.write_all(result.tsv_row(&target, tester_ip).as_bytes()).await?;
            }

            if tested.is_multiple_of(100) || tested == total_checks {
                println!("progress: {tested}/{total_checks}, valid checks: {valid}");
            }
            if let Some(proxy) = iter.next() {
                spawn_validation(
                    &mut tasks,
                    proxy,
                    Arc::clone(&shared),
                    Arc::clone(&target),
                    Arc::clone(&enrichment_cache),
                );
            }
        }

        println!(
            "interface {} complete: tested={interface_tested}, valid={interface_valid}, invalid={}",
            target.label(),
            interface_tested.saturating_sub(interface_valid)
        );
        interface_summary.print(&format!("interface={}", target.label()));
    }

    if let Some(writer) = output.as_mut() {
        writer.flush().await?;
    }
    if let Some(writer) = valid_output.as_mut() {
        writer.flush().await?;
    }
    store.finish_run(run_id, valid, tested.saturating_sub(valid))?;

    println!(
        "batch complete: tested={tested}, valid={valid}, invalid={}, tsv={}, sqlite={}",
        tested.saturating_sub(valid),
        if shared.write_tsv { shared.output.as_str() } else { "disabled" },
        shared.database
    );
    overall_summary.print("overall");
    Ok(BatchRunOutcome {
        run_id,
        proxy_count: proxies.len(),
        tested,
        valid,
    })
}

fn validate_options(options: &BatchOptions) -> Result<()> {
    if options.proxy_files.is_empty()
        && options.source_lists.is_empty()
        && options.source_urls.is_empty()
        && options.inline_proxy_sources.is_empty()
        && options.inline_source_lists.is_empty()
    {
        return Err(anyhow!("batch mode requires --proxy-file, --source-list, or --source-url"));
    }
    if options.concurrency == 0 {
        return Err(anyhow!("--concurrency must be greater than zero"));
    }
    if options.timeout_secs == 0 {
        return Err(anyhow!("--timeout must be greater than zero"));
    }
    if options.latency_samples == 0 {
        return Err(anyhow!("--latency-samples must be greater than zero"));
    }
    TestProfile::parse(&options.profile)?;
    const MAX_BENCHMARK_BYTES: u64 = 100 * 1024 * 1024;
    if options.download_bytes == 0 || options.download_bytes > MAX_BENCHMARK_BYTES {
        return Err(anyhow!("--download-bytes must be between 1 and 104857600"));
    }
    if options.upload_bytes == 0 || options.upload_bytes > MAX_BENCHMARK_BYTES {
        return Err(anyhow!("--upload-bytes must be between 1 and 104857600"));
    }
    if let Some(template) = &options.ip_info_url_template {
        if !template.contains("{ip}") {
            return Err(anyhow!("--ip-info-url-template must contain {{ip}}"));
        }
        validate_http_url(&template.replace("{ip}", "127.0.0.1"), "--ip-info-url-template")?;
    }
    validate_http_url(
        &options.download_url.replace("{bytes}", &options.download_bytes.to_string()),
        "--download-url",
    )?;
    validate_http_url(&options.upload_url, "--upload-url")?;
    ensure_distinct_artifact_paths(
        options.write_tsv.then_some(options.output.as_str()),
        options.valid_output.as_deref(),
        &options.database,
    )
}

fn redact_source(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return value.to_owned();
    };
    if !matches!(url.scheme(), "http" | "https") {
        return value.to_owned();
    }

    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn ensure_distinct_artifact_paths(
    output: Option<&str>,
    valid_output: Option<&str>,
    database: &str,
) -> Result<()> {
    let mut artifacts = vec![("--database", normalized_output_path(database)?)];
    if let Some(output) = output {
        artifacts.push(("--output", normalized_output_path(output)?));
    }
    if let Some(valid_output) = valid_output {
        artifacts.push(("--valid-output", normalized_output_path(valid_output)?));
    }

    for left in 0..artifacts.len() {
        for right in (left + 1)..artifacts.len() {
            if artifacts[left].1 == artifacts[right].1 {
                return Err(anyhow!(
                    "{} and {} must refer to different files",
                    artifacts[left].0,
                    artifacts[right].0
                ));
            }
        }
    }
    Ok(())
}

fn normalized_output_path(value: &str) -> Result<PathBuf> {
    if value == ":memory:" {
        return Ok(PathBuf::from(":memory:"));
    }

    let path = Path::new(value);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir().context("failed to determine current directory")?.join(path)
    };

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }

    if normalized.exists() {
        return std::fs::canonicalize(&normalized).with_context(|| {
            format!("failed to canonicalize output path {}", normalized.display())
        });
    }

    if let (Some(parent), Some(name)) = (normalized.parent(), normalized.file_name()) {
        if let Ok(parent) = std::fs::canonicalize(parent) {
            return Ok(parent.join(name));
        }
    }
    Ok(normalized)
}

fn spawn_validation(
    tasks: &mut JoinSet<BatchResult>, proxy: ProxySpec, options: Arc<BatchOptions>,
    target: Arc<interface::InterfaceTarget>, enrichment_cache: validate::IpInfoCache,
) {
    tasks.spawn(async move {
        validate::validate_proxy(proxy, &options, &target, enrichment_cache).await
    });
}

fn validate_http_url(value: &str, flag: &str) -> Result<()> {
    let url = Url::parse(value).with_context(|| format!("invalid {flag}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(anyhow!("{flag} must use http:// or https://"));
    }
    Ok(())
}

fn format_metric(value: Option<f64>) -> String {
    value.map(|value| format!("{value:.3}")).unwrap_or_default()
}

fn stage_status_text(stages: &[StageResult]) -> String {
    stages
        .iter()
        .map(|stage| format!("{}:{}={}", stage.stage, stage.name, stage.status.as_str()))
        .collect::<Vec<_>>()
        .join(",")
}

fn tsv_escape(value: &str) -> String {
    value.replace(['\t', '\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_distinct_artifact_paths, redact_source, tsv_escape, ProbeMetrics, ProxyProtocol,
        ProxySpec, StageResult, SummaryAccumulator,
    };

    #[test]
    fn escapes_tsv_control_characters() {
        assert_eq!(tsv_escape("a\tb\nc"), "a b c");
    }

    #[test]
    fn report_input_never_exposes_proxy_credentials() {
        let proxy = ProxySpec {
            raw: "socks5://user:secret@example.com:1080".to_owned(),
            source: "test".to_owned(),
            host: "example.com".to_owned(),
            port: 1080,
            username: Some("user".to_owned()),
            password: Some("secret".to_owned()),
            protocol: ProxyProtocol::Socks5,
        };
        assert_eq!(proxy.report_input(), "socks5://example.com:1080");
        assert!(!proxy.report_input().contains("user"));
        assert!(!proxy.report_input().contains("secret"));
    }

    #[test]
    fn source_url_redacts_userinfo_query_and_fragment() {
        let value = redact_source("https://user:secret@example.com/list.txt?token=abc#frag");
        assert_eq!(value, "https://example.com/list.txt");
    }

    #[test]
    fn rejects_equivalent_output_paths() {
        let err = ensure_distinct_artifact_paths(
            Some("proxy-results.tsv"),
            Some("./proxy-results.tsv"),
            "proxy-socks-test.sqlite3",
        )
        .unwrap_err();
        assert!(err.to_string().contains("different files"));
    }

    #[test]
    fn rejects_database_output_collision() {
        let err =
            ensure_distinct_artifact_paths(Some("./results.tsv"), None, "results.tsv").unwrap_err();
        assert!(err.to_string().contains("--output"));
        assert!(err.to_string().contains("--database"));
    }

    #[test]
    fn professional_summary_reports_protocol_stage_latency_speed_and_exit_ip() {
        use std::net::{IpAddr, Ipv4Addr};
        use std::time::Duration;

        let result = super::BatchResult {
            proxy: ProxySpec {
                raw: "127.0.0.1:1080".into(),
                source: "test".into(),
                host: "127.0.0.1".into(),
                port: 1080,
                username: None,
                password: None,
                protocol: ProxyProtocol::Auto,
            },
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            tested_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            reverse_dns: None,
            endpoint_connect_ms: Some(1),
            endpoint_ip_info: None,
            metrics: Some(ProbeMetrics {
                protocol: ProxyProtocol::Socks5,
                validation_latency_ms: 10,
                exit_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                latency_samples_ms: vec![10, 20, 30],
                latency_p50_ms: Some(20.0),
                latency_p95_ms: Some(30.0),
                jitter_ms: Some(10.0),
                download_mbps: Some(50.0),
                upload_mbps: Some(25.0),
                exit_ip_changed: true,
                exit_ip_info: None,
            }),
            stages: vec![
                StageResult::pass(3, "proxy_http_validation", Duration::from_millis(10)),
                StageResult::fail(
                    5,
                    "download_throughput",
                    Duration::from_millis(1),
                    "fixture failure",
                ),
            ],
            error: None,
        };

        let mut summary = SummaryAccumulator::default();
        summary.observe(&result);
        let rendered = summary.render("fixture");
        assert!(rendered.contains("protocols=socks5=1"));
        assert!(rendered.contains("5:download_throughput:fail=1"));
        assert!(rendered.contains("failures=download_throughput=1"));
        assert!(rendered.contains("latency_p50_ms=20.000"));
        assert!(rendered.contains("latency_p95_ms=30.000"));
        assert!(rendered.contains("jitter_avg_ms=10.000"));
        assert!(rendered.contains("download_avg_mbps=50.000"));
        assert!(rendered.contains("upload_avg_mbps=25.000"));
        assert!(rendered.contains("unique_exit_ips=1"));
        assert!(rendered.contains("exit_ip_changed_checks=1"));
    }
}
