mod input;
mod validate;

use anyhow::{anyhow, Context, Result};
use reqwest::{Client, Url};
use std::{fmt, net::IpAddr, sync::Arc, time::Duration};
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
    pub output: String,
    pub valid_output: Option<String>,
    pub default_protocol: String,
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub check_url: String,
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
            // Remote DNS matches the legacy socks5_connect_hostname behavior.
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
            return Err(anyhow!(
                "credentials are supported only for SOCKS5 batch validation"
            ));
        }

        let host = match tested_ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        let mut url = Url::parse(&format!(
            "{}://{}:{}",
            protocol.reqwest_scheme(),
            host,
            self.port
        ))?;
        if let Some(username) = &self.username {
            url.set_username(username)
                .map_err(|_| anyhow!("invalid proxy username"))?;
            url.set_password(Some(self.password.as_deref().unwrap_or_default()))
                .map_err(|_| anyhow!("invalid proxy password"))?;
        }
        Ok(url)
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

#[derive(Debug)]
pub(super) struct ProbeMetrics {
    pub(super) protocol: ProxyProtocol,
    pub(super) latency_ms: u128,
    pub(super) exit_ip: IpAddr,
}

#[derive(Debug)]
pub(super) struct BatchResult {
    pub(super) proxy: ProxySpec,
    pub(super) tested_ip: Option<IpAddr>,
    pub(super) metrics: Option<ProbeMetrics>,
    pub(super) error: Option<String>,
}

impl BatchResult {
    fn valid(&self) -> bool {
        self.metrics.is_some()
    }

    fn tsv_row(&self) -> String {
        let protocol = self
            .metrics
            .as_ref()
            .map(|m| m.protocol.to_string())
            .unwrap_or_else(|| self.proxy.protocol.to_string());
        let tested_ip = self.tested_ip.map(|ip| ip.to_string()).unwrap_or_default();
        let latency_ms = self
            .metrics
            .as_ref()
            .map(|m| m.latency_ms.to_string())
            .unwrap_or_default();
        let exit_ip = self
            .metrics
            .as_ref()
            .map(|m| m.exit_ip.to_string())
            .unwrap_or_default();

        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            tsv_escape(&self.proxy.source),
            tsv_escape(&self.proxy.raw),
            protocol,
            tsv_escape(&self.proxy.host),
            tested_ip,
            self.proxy.port,
            self.valid(),
            latency_ms,
            exit_ip,
            tsv_escape(self.error.as_deref().unwrap_or_default())
        )
    }
}

pub async fn run_batch(options: BatchOptions) -> Result<()> {
    if options.proxy_files.is_empty()
        && options.source_lists.is_empty()
        && options.source_urls.is_empty()
    {
        return Err(anyhow!(
            "batch mode requires --proxy-file, --source-list, or --source-url"
        ));
    }
    if options.concurrency == 0 {
        return Err(anyhow!("--concurrency must be greater than zero"));
    }
    if options.timeout_secs == 0 {
        return Err(anyhow!("--timeout must be greater than zero"));
    }
    let check_url = Url::parse(&options.check_url).context("invalid --check-url")?;
    if !matches!(check_url.scheme(), "http" | "https") {
        return Err(anyhow!("--check-url must use http:// or https://"));
    }

    let default_protocol = ProxyProtocol::parse(&options.default_protocol)?;
    let source_client = Client::builder()
        .no_proxy()
        .user_agent("proxy-socks-test/0.2")
        .timeout(Duration::from_secs(options.timeout_secs.max(15)))
        .build()
        .context("failed to build source download client")?;

    let (proxies, load_stats) = input::load_proxies(&source_client, &options, default_protocol).await?;
    if proxies.is_empty() {
        return Err(anyhow!("no valid proxy entries found in the supplied inputs"));
    }

    println!(
        "loaded {} unique proxies ({} malformed skipped, {} source errors)",
        proxies.len(), load_stats.malformed_entries, load_stats.source_errors
    );

    let output_file = fs::File::create(&options.output)
        .await
        .with_context(|| format!("failed to create TSV output {}", options.output))?;
    let mut output = BufWriter::new(output_file);
    output
        .write_all(
            b"source\tinput\tprotocol\tproxy_host\ttested_ip\tproxy_port\tvalid\tlatency_ms\texit_ip\terror\n",
        )
        .await?;

    let mut valid_output = if let Some(path) = &options.valid_output {
        Some(BufWriter::new(
            fs::File::create(path)
                .await
                .with_context(|| format!("failed to create valid proxy output {path}"))?,
        ))
    } else {
        None
    };

    let total = proxies.len();
    let shared = Arc::new(options);
    let mut iter = proxies.into_iter();
    let mut tasks = JoinSet::new();
    for _ in 0..shared.concurrency.min(total) {
        if let Some(proxy) = iter.next() {
            spawn_validation(&mut tasks, proxy, Arc::clone(&shared));
        }
    }

    let mut tested = 0usize;
    let mut valid = 0usize;
    while let Some(joined) = tasks.join_next().await {
        let result = joined.context("proxy validation task failed")?;
        tested += 1;
        if result.valid() {
            valid += 1;
            if let (Some(writer), Some(metrics)) = (valid_output.as_mut(), result.metrics.as_ref()) {
                writer
                    .write_all(format!("{}\n", result.proxy.normalized(metrics.protocol)).as_bytes())
                    .await?;
            }
        }
        output.write_all(result.tsv_row().as_bytes()).await?;

        if tested % 100 == 0 || tested == total {
            println!("progress: {tested}/{total}, valid: {valid}");
        }
        if let Some(proxy) = iter.next() {
            spawn_validation(&mut tasks, proxy, Arc::clone(&shared));
        }
    }

    output.flush().await?;
    if let Some(writer) = valid_output.as_mut() {
        writer.flush().await?;
    }
    println!(
        "batch complete: tested={tested}, valid={valid}, invalid={}, tsv={}",
        tested.saturating_sub(valid),
        shared.output.as_str()
    );
    Ok(())
}

fn spawn_validation(tasks: &mut JoinSet<BatchResult>, proxy: ProxySpec, options: Arc<BatchOptions>) {
    tasks.spawn(async move { validate::validate_proxy(proxy, &options).await });
}

fn tsv_escape(value: &str) -> String {
    value
        .replace('\t', " ")
        .replace('\r', " ")
        .replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::tsv_escape;

    #[test]
    fn escapes_tsv_control_characters() {
        assert_eq!(tsv_escape("a\tb\nc"), "a b c");
    }
}
