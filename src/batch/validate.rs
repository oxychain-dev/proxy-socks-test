use super::{
    interface::{bind_client_builder, InterfaceTarget},
    BatchOptions, BatchResult, ProbeMetrics, ProxyProtocol, ProxySpec,
};
use anyhow::{anyhow, Result};
use reqwest::{Client, Proxy};
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::{net::lookup_host, time::timeout};

pub(super) async fn detect_tester_ip(
    options: &BatchOptions, target: &InterfaceTarget,
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
    proxy: ProxySpec, options: &BatchOptions, target: &InterfaceTarget,
) -> BatchResult {
    let tested_ip = match resolve_first_ip(&proxy.host, proxy.port, options.timeout_secs).await {
        Ok(ip) => ip,
        Err(err) => {
            return BatchResult {
                proxy,
                tested_ip: None,
                metrics: None,
                error: Some(format!("proxy resolve failed: {err:#}")),
            }
        }
    };

    let protocols: &[ProxyProtocol] = match proxy.protocol {
        ProxyProtocol::Auto if proxy.username.is_some() => &[ProxyProtocol::Socks5],
        ProxyProtocol::Auto => {
            &[ProxyProtocol::Socks5, ProxyProtocol::Socks4a, ProxyProtocol::Socks4]
        }
        ProxyProtocol::Socks4 => &[ProxyProtocol::Socks4],
        ProxyProtocol::Socks4a => &[ProxyProtocol::Socks4a],
        ProxyProtocol::Socks5 => &[ProxyProtocol::Socks5],
    };

    let mut errors = Vec::new();
    for protocol in protocols {
        match probe_proxy(&proxy, tested_ip, *protocol, options, target).await {
            Ok(metrics) => {
                return BatchResult {
                    proxy,
                    tested_ip: Some(tested_ip),
                    metrics: Some(metrics),
                    error: None,
                }
            }
            Err(err) => errors.push(format!("{protocol}: {err:#}")),
        }
    }

    BatchResult {
        proxy,
        tested_ip: Some(tested_ip),
        metrics: None,
        error: Some(errors.join(" | ")),
    }
}

async fn probe_proxy(
    proxy: &ProxySpec, tested_ip: IpAddr, protocol: ProxyProtocol, options: &BatchOptions,
    target: &InterfaceTarget,
) -> Result<ProbeMetrics> {
    let proxy_url = proxy.proxy_url(protocol, tested_ip)?;
    let proxy_rule = Proxy::all(proxy_url.as_str())?;
    let builder = Client::builder()
        .proxy(proxy_rule)
        .user_agent(concat!("proxy-socks-test/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(options.timeout_secs));
    let client = bind_client_builder(builder, target)?.build()?;

    let started = Instant::now();
    let response = client.get(&options.check_url).send().await?.error_for_status()?;
    let body = response.text().await?;
    let exit_ip = parse_exit_ip(&body)?;

    Ok(ProbeMetrics { protocol, latency_ms: started.elapsed().as_millis(), exit_ip })
}

async fn resolve_first_ip(host: &str, port: u16, timeout_secs: u64) -> Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let resolved = timeout(Duration::from_secs(timeout_secs), lookup_host((host, port)))
        .await
        .map_err(|_| anyhow!("DNS lookup timed out"))??;
    resolved.map(|addr| addr.ip()).next().ok_or_else(|| anyhow!("DNS lookup returned no addresses"))
}

fn parse_exit_ip(body: &str) -> Result<IpAddr> {
    body.split(|c: char| c.is_whitespace() || matches!(c, ',' | '"' | '\'' | '[' | ']'))
        .find_map(|token| token.trim().parse::<IpAddr>().ok())
        .ok_or_else(|| anyhow!("IP-check response did not contain an IP address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ip_from_response() {
        assert_eq!(parse_exit_ip("203.0.113.9\n").unwrap().to_string(), "203.0.113.9");
    }
}
