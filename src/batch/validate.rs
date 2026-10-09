use super::{
    interface::{bind_client_builder, InterfaceTarget},
    BatchOptions, BatchResult, IpMetadata, ProbeMetrics, ProxyProtocol, ProxySpec, StageResult,
    TestProfile,
};
use anyhow::{anyhow, Context, Result};
use dns_lookup::lookup_addr;
use reqwest::{Client, Proxy};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::{lookup_host, TcpSocket},
    sync::Mutex,
    time::timeout,
};

pub(super) type IpInfoCache = Arc<Mutex<HashMap<IpAddr, IpMetadata>>>;

struct ProtocolProbe {
    protocol: ProxyProtocol,
    latency_ms: u128,
    exit_ip: IpAddr,
    client: Client,
}

pub(super) fn new_ip_info_cache() -> IpInfoCache {
    Arc::new(Mutex::new(HashMap::new()))
}

pub(super) async fn detect_tester_ip(
    options: &BatchOptions,
    target: &InterfaceTarget,
) -> Result<IpAddr> {
    let builder = Client::builder()
        .no_proxy()
        .user_agent(concat!("proxy-socks-test/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(options.timeout_secs));
    let client = bind_client_builder(builder, target)?.build()?;
    let response = client.get(&options.check_url).send().await?.error_for_status()?;
    let body = response.text().await?;
    parse_exit_ip(&body)
}

pub(super) async fn validate_proxy(
    proxy: ProxySpec,
    options: &BatchOptions,
    target: &InterfaceTarget,
    enrichment_cache: IpInfoCache,
) -> BatchResult {
    let profile =
        TestProfile::parse(&options.profile).expect("batch profile validated before task spawn");
    let mut stages = vec![StageResult::pass(
        0,
        "parse_deduplicate",
        Duration::ZERO,
    )];

    let resolve_started = Instant::now();
    let resolved_ips = match resolve_all_ips(&proxy.host, proxy.port, options.timeout_secs).await {
        Ok(ips) => ips,
        Err(err) => {
            let message = format!("proxy resolve failed: {err:#}");
            stages.push(StageResult::fail(
                1,
                "resolve_endpoint",
                resolve_started.elapsed(),
                &message,
            ));
            append_skipped_stages(&mut stages, 2, profile, "gated by endpoint resolution failure");
            return BatchResult {
                proxy,
                resolved_ips: Vec::new(),
                tested_ip: None,
                reverse_dns: None,
                endpoint_connect_ms: None,
                endpoint_ip_info: None,
                metrics: None,
                stages,
                error: Some(message),
            };
        }
    };

    let tested_ip = match select_tested_ip(&resolved_ips, target) {
        Ok(ip) => ip,
        Err(err) => {
            let message = format!("proxy address selection failed: {err:#}");
            stages.push(StageResult::fail(
                1,
                "resolve_endpoint",
                resolve_started.elapsed(),
                &message,
            ));
            append_skipped_stages(&mut stages, 2, profile, "gated by address-family mismatch");
            return BatchResult {
                proxy,
                resolved_ips,
                tested_ip: None,
                reverse_dns: None,
                endpoint_connect_ms: None,
                endpoint_ip_info: None,
                metrics: None,
                stages,
                error: Some(message),
            };
        }
    };
    stages.push(StageResult::pass(1, "resolve_endpoint", resolve_started.elapsed()));

    let connect_started = Instant::now();
    let endpoint_connect_ms =
        match tcp_connect_latency(tested_ip, proxy.port, target, options.timeout_secs).await {
            Ok(value) => value,
            Err(err) => {
                let message = format!("proxy endpoint connect failed: {err:#}");
                stages.push(StageResult::fail(
                    2,
                    "tcp_reachability",
                    connect_started.elapsed(),
                    &message,
                ));
                append_skipped_stages(
                    &mut stages,
                    3,
                    profile,
                    "gated by endpoint reachability failure",
                );
                return BatchResult {
                    proxy,
                    resolved_ips,
                    tested_ip: Some(tested_ip),
                    reverse_dns: None,
                    endpoint_connect_ms: None,
                    endpoint_ip_info: None,
                    metrics: None,
                    stages,
                    error: Some(message),
                };
            }
        };
    stages.push(StageResult::pass(
        2,
        "tcp_reachability",
        connect_started.elapsed(),
    ));

    let protocols: &[ProxyProtocol] = match proxy.protocol {
        ProxyProtocol::Auto if proxy.username.is_some() => &[ProxyProtocol::Socks5],
        ProxyProtocol::Auto => {
            &[ProxyProtocol::Socks5, ProxyProtocol::Socks4a, ProxyProtocol::Socks4]
        }
        ProxyProtocol::Socks4 => &[ProxyProtocol::Socks4],
        ProxyProtocol::Socks4a => &[ProxyProtocol::Socks4a],
        ProxyProtocol::Socks5 => &[ProxyProtocol::Socks5],
    };

    let validation_started = Instant::now();
    let mut protocol_errors = Vec::new();
    let mut successful_probe = None;
    for protocol in protocols {
        match probe_protocol(&proxy, tested_ip, *protocol, options, target).await {
            Ok(probe) => {
                successful_probe = Some(probe);
                break;
            }
            Err(err) => protocol_errors.push(format!("{protocol}: {err:#}")),
        }
    }

    let Some(probe) = successful_probe else {
        let message = protocol_errors.join(" | ");
        stages.push(StageResult::fail(
            3,
            "proxy_http_validation",
            validation_started.elapsed(),
            &message,
        ));
        append_skipped_stages(
            &mut stages,
            4,
            profile,
            "gated by proxy validation failure",
        );
        return BatchResult {
            proxy,
            resolved_ips,
            tested_ip: Some(tested_ip),
            reverse_dns: None,
            endpoint_connect_ms: Some(endpoint_connect_ms),
            endpoint_ip_info: None,
            metrics: None,
            stages,
            error: Some(message),
        };
    };
    stages.push(StageResult::pass(
        3,
        "proxy_http_validation",
        validation_started.elapsed(),
    ));

    let reverse_dns = reverse_lookup(tested_ip, options.timeout_secs).await;
    let endpoint_ip_info = fetch_ip_metadata(
        tested_ip,
        options,
        target,
        Arc::clone(&enrichment_cache),
    )
    .await
    .ok()
    .flatten();
    let exit_ip_info = fetch_ip_metadata(
        probe.exit_ip,
        options,
        target,
        Arc::clone(&enrichment_cache),
    )
    .await
    .ok()
    .flatten();

    let mut metrics = ProbeMetrics {
        protocol: probe.protocol,
        validation_latency_ms: probe.latency_ms,
        exit_ip: probe.exit_ip,
        latency_samples_ms: vec![probe.latency_ms],
        latency_p50_ms: None,
        latency_p95_ms: None,
        jitter_ms: None,
        download_mbps: None,
        upload_mbps: None,
        exit_ip_changed: false,
        exit_ip_info,
    };

    if profile.includes_stage(4) {
        let latency_started = Instant::now();
        let mut latency_errors = Vec::new();
        let mut seen_exit_ips = HashSet::from([probe.exit_ip]);

        for _ in 1..options.latency_samples {
            match http_check(&probe.client, &options.check_url).await {
                Ok((latency_ms, exit_ip)) => {
                    metrics.latency_samples_ms.push(latency_ms);
                    seen_exit_ips.insert(exit_ip);
                }
                Err(err) => latency_errors.push(err.to_string()),
            }
        }

        metrics.latency_p50_ms = percentile_ms(&metrics.latency_samples_ms, 0.50);
        metrics.latency_p95_ms = percentile_ms(&metrics.latency_samples_ms, 0.95);
        metrics.jitter_ms = jitter_ms(&metrics.latency_samples_ms);
        metrics.exit_ip_changed = seen_exit_ips.len() > 1;

        if latency_errors.is_empty() {
            stages.push(StageResult::pass(
                4,
                "latency_jitter",
                latency_started.elapsed(),
            ));
        } else {
            stages.push(StageResult::partial(
                4,
                "latency_jitter",
                latency_started.elapsed(),
                format!(
                    "{} of {} additional samples failed: {}",
                    latency_errors.len(),
                    options.latency_samples.saturating_sub(1),
                    latency_errors.join(" | ")
                ),
            ));
        }
    } else {
        stages.push(StageResult::skip(
            4,
            "latency_jitter",
            "not enabled by basic profile",
        ));
    }

    if profile.includes_stage(5) {
        let download_started = Instant::now();
        match download_benchmark(&probe.client, options).await {
            Ok(mbps) => {
                metrics.download_mbps = Some(mbps);
                stages.push(StageResult::pass(
                    5,
                    "download_throughput",
                    download_started.elapsed(),
                ));
            }
            Err(err) => stages.push(StageResult::fail(
                5,
                "download_throughput",
                download_started.elapsed(),
                format!("{err:#}"),
            )),
        }
    } else {
        stages.push(StageResult::skip(
            5,
            "download_throughput",
            "not enabled by selected profile",
        ));
    }

    if profile.includes_stage(6) {
        let upload_started = Instant::now();
        match upload_benchmark(&probe.client, options).await {
            Ok(mbps) => {
                metrics.upload_mbps = Some(mbps);
                stages.push(StageResult::pass(
                    6,
                    "upload_throughput",
                    upload_started.elapsed(),
                ));
            }
            Err(err) => stages.push(StageResult::fail(
                6,
                "upload_throughput",
                upload_started.elapsed(),
                format!("{err:#}"),
            )),
        }
    } else {
        stages.push(StageResult::skip(
            6,
            "upload_throughput",
            "not enabled by selected profile",
        ));
    }

    BatchResult {
        proxy,
        resolved_ips,
        tested_ip: Some(tested_ip),
        reverse_dns,
        endpoint_connect_ms: Some(endpoint_connect_ms),
        endpoint_ip_info,
        metrics: Some(metrics),
        stages,
        error: None,
    }
}

async fn probe_protocol(
    proxy: &ProxySpec,
    tested_ip: IpAddr,
    protocol: ProxyProtocol,
    options: &BatchOptions,
    target: &InterfaceTarget,
) -> Result<ProtocolProbe> {
    let proxy_url = proxy.proxy_url(protocol, tested_ip)?;
    let proxy_rule = Proxy::all(proxy_url.as_str())?;
    let builder = Client::builder()
        .proxy(proxy_rule)
        .user_agent(concat!("proxy-socks-test/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(options.timeout_secs));
    let client = bind_client_builder(builder, target)?.build()?;
    let (latency_ms, exit_ip) = http_check(&client, &options.check_url).await?;

    Ok(ProtocolProbe { protocol, latency_ms, exit_ip, client })
}

async fn http_check(client: &Client, check_url: &str) -> Result<(u128, IpAddr)> {
    let started = Instant::now();
    let response = client.get(check_url).send().await?.error_for_status()?;
    let body = response.text().await?;
    let exit_ip = parse_exit_ip(&body)?;
    Ok((started.elapsed().as_millis(), exit_ip))
}

async fn resolve_all_ips(host: &str, port: u16, timeout_secs: u64) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let resolved = timeout(Duration::from_secs(timeout_secs), lookup_host((host, port)))
        .await
        .map_err(|_| anyhow!("DNS lookup timed out"))??;
    let mut seen = HashSet::new();
    let ips = resolved
        .map(|addr| addr.ip())
        .filter(|ip| seen.insert(*ip))
        .collect::<Vec<_>>();

    if ips.is_empty() {
        return Err(anyhow!("DNS lookup returned no addresses"));
    }
    Ok(ips)
}

fn select_tested_ip(resolved_ips: &[IpAddr], target: &InterfaceTarget) -> Result<IpAddr> {
    if target.name.is_none() {
        return resolved_ips
            .first()
            .copied()
            .ok_or_else(|| anyhow!("no resolved proxy address"));
    }

    resolved_ips
        .iter()
        .copied()
        .find(|remote| {
            target
                .local_ips
                .iter()
                .any(|local| same_address_family(*local, *remote))
        })
        .ok_or_else(|| {
            anyhow!(
                "proxy resolved addresses do not match any address family on interface {}",
                target.label()
            )
        })
}

async fn tcp_connect_latency(
    ip: IpAddr,
    port: u16,
    target: &InterfaceTarget,
    timeout_secs: u64,
) -> Result<u128> {
    let socket = match ip {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };

    if target.name.is_some() {
        let local_ip = target
            .local_ips
            .iter()
            .copied()
            .find(|local| same_address_family(*local, ip))
            .ok_or_else(|| anyhow!("selected interface has no matching local address family"))?;
        socket
            .bind(SocketAddr::new(local_ip, 0))
            .with_context(|| format!("failed to bind TCP probe to local address {local_ip}"))?;
    }

    let started = Instant::now();
    timeout(
        Duration::from_secs(timeout_secs),
        socket.connect(SocketAddr::new(ip, port)),
    )
    .await
    .map_err(|_| anyhow!("TCP connect timed out"))??;
    Ok(started.elapsed().as_millis())
}

fn same_address_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

async fn reverse_lookup(ip: IpAddr, timeout_secs: u64) -> Option<String> {
    let wait = Duration::from_secs(timeout_secs.clamp(1, 3));
    let task = tokio::task::spawn_blocking(move || lookup_addr(&ip));
    match timeout(wait, task).await {
        Ok(Ok(Ok(name))) => Some(name),
        _ => None,
    }
}

async fn fetch_ip_metadata(
    ip: IpAddr,
    options: &BatchOptions,
    target: &InterfaceTarget,
    cache: IpInfoCache,
) -> Result<Option<IpMetadata>> {
    let Some(template) = options.ip_info_url_template.as_deref() else {
        return Ok(None);
    };

    if let Some(value) = cache.lock().await.get(&ip).cloned() {
        return Ok(Some(value));
    }

    let url = template.replace("{ip}", &ip.to_string());
    let builder = Client::builder()
        .no_proxy()
        .user_agent(concat!("proxy-socks-test/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(options.timeout_secs));
    let client = bind_client_builder(builder, target)?.build()?;
    let response = client.get(url).send().await?.error_for_status()?;
    if response.content_length().is_some_and(|size| size > 256 * 1024) {
        return Err(anyhow!("IP enrichment response is larger than 256 KiB"));
    }
    let bytes = response.bytes().await?;
    if bytes.len() > 256 * 1024 {
        return Err(anyhow!("IP enrichment response is larger than 256 KiB"));
    }
    let raw_json = String::from_utf8(bytes.to_vec()).context("IP enrichment was not UTF-8")?;
    let value: Value = serde_json::from_str(&raw_json).context("IP enrichment was not JSON")?;
    let metadata = IpMetadata {
        raw_json,
        country: json_field(&value, &["country", "country_name", "countryCode"]),
        region: json_field(&value, &["region", "regionName", "region_name"]),
        city: json_field(&value, &["city"]),
        organization: json_field(&value, &["org", "organization", "isp", "connection.org"]),
        asn: json_field(&value, &["asn", "as", "connection.asn"]),
        timezone: json_field(&value, &["timezone", "time_zone", "timezone.id"]),
    };
    cache.lock().await.insert(ip, metadata.clone());
    Ok(Some(metadata))
}

fn json_field(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        let mut current = value;
        let mut found = true;
        for part in key.split('.') {
            match current.get(part) {
                Some(next) => current = next,
                None => {
                    found = false;
                    break;
                }
            }
        }
        if !found || current.is_null() {
            continue;
        }
        if let Some(value) = current.as_str() {
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        } else if current.is_number() || current.is_boolean() {
            return Some(current.to_string());
        }
    }
    None
}

async fn download_benchmark(client: &Client, options: &BatchOptions) -> Result<f64> {
    let url = options.download_url.replace("{bytes}", &options.download_bytes.to_string());
    let started = Instant::now();
    let mut response = client.get(url).send().await?.error_for_status()?;
    let mut downloaded = 0u64;

    while let Some(chunk) = response.chunk().await? {
        let remaining = options.download_bytes.saturating_sub(downloaded);
        if remaining == 0 {
            break;
        }
        downloaded = downloaded.saturating_add((chunk.len() as u64).min(remaining));
        if downloaded >= options.download_bytes {
            break;
        }
    }

    if downloaded == 0 {
        return Err(anyhow!("download benchmark returned no payload"));
    }
    Ok(megabits_per_second(downloaded, started.elapsed()))
}

async fn upload_benchmark(client: &Client, options: &BatchOptions) -> Result<f64> {
    let payload_len = usize::try_from(options.upload_bytes)
        .map_err(|_| anyhow!("upload payload is too large for this platform"))?;
    let payload = vec![0u8; payload_len];
    let started = Instant::now();
    let response = client
        .post(&options.upload_url)
        .header("content-type", "application/octet-stream")
        .body(payload)
        .send()
        .await?
        .error_for_status()?;
    let _ = response.bytes().await?;
    Ok(megabits_per_second(options.upload_bytes, started.elapsed()))
}

fn megabits_per_second(bytes: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64().max(0.000_001);
    (bytes as f64 * 8.0) / seconds / 1_000_000.0
}

fn percentile_ms(samples: &[u128], percentile: f64) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut values = samples.iter().map(|value| *value as f64).collect::<Vec<_>>();
    values.sort_by(f64::total_cmp);
    let rank = ((values.len() - 1) as f64 * percentile.clamp(0.0, 1.0)).ceil() as usize;
    values.get(rank).copied()
}

fn jitter_ms(samples: &[u128]) -> Option<f64> {
    if samples.len() < 2 {
        return None;
    }
    let total = samples
        .windows(2)
        .map(|pair| pair[0].abs_diff(pair[1]) as f64)
        .sum::<f64>();
    Some(total / (samples.len() - 1) as f64)
}

fn append_skipped_stages(
    stages: &mut Vec<StageResult>,
    start_stage: u8,
    profile: TestProfile,
    gate_reason: &str,
) {
    for stage in start_stage..=6 {
        let reason = if profile.includes_stage(stage) {
            gate_reason
        } else {
            "not enabled by selected profile"
        };
        stages.push(StageResult::skip(stage, stage_name(stage), reason));
    }
}

fn stage_name(stage: u8) -> &'static str {
    match stage {
        0 => "parse_deduplicate",
        1 => "resolve_endpoint",
        2 => "tcp_reachability",
        3 => "proxy_http_validation",
        4 => "latency_jitter",
        5 => "download_throughput",
        6 => "upload_throughput",
        _ => "unknown",
    }
}

fn parse_exit_ip(body: &str) -> Result<IpAddr> {
    body.split(|c: char| c.is_whitespace() || matches!(c, ',' | '"' | '\'' | '[' | ']'))
        .find_map(|token| token.trim().parse::<IpAddr>().ok())
        .ok_or_else(|| anyhow!("IP-check response did not contain an IP address"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn extracts_ip_from_response() {
        assert_eq!(parse_exit_ip("203.0.113.9\n").unwrap().to_string(), "203.0.113.9");
    }

    #[test]
    fn selects_address_matching_interface_family() {
        let target = InterfaceTarget {
            name: Some("test0".into()),
            local_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        };
        let resolved = vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        ];
        assert_eq!(
            select_tested_ip(&resolved, &target).unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
        );
    }

    #[test]
    fn computes_percentiles_and_jitter() {
        let samples = [10, 20, 40];
        assert_eq!(percentile_ms(&samples, 0.50), Some(20.0));
        assert_eq!(percentile_ms(&samples, 0.95), Some(40.0));
        assert_eq!(jitter_ms(&samples), Some(15.0));
    }

    #[test]
    fn extracts_common_ip_metadata_fields() {
        let value: Value = serde_json::from_str(
            r#"{"country_name":"Example","city":"Test","connection":{"org":"ISP","asn":64500}}"#,
        )
        .unwrap();
        assert_eq!(json_field(&value, &["country", "country_name"]), Some("Example".into()));
        assert_eq!(json_field(&value, &["connection.org"]), Some("ISP".into()));
        assert_eq!(json_field(&value, &["connection.asn"]), Some("64500".into()));
    }
}
