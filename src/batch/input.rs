use super::{BatchOptions, ProxyProtocol, ProxySpec};
use anyhow::{anyhow, Context, Result};
use reqwest::{Client, Url};
use std::collections::HashSet;
use tokio::fs;

#[derive(Default)]
pub(super) struct LoadStats {
    pub(super) malformed_entries: usize,
    pub(super) source_errors: usize,
}

pub(super) async fn load_proxies(
    client: &Client, options: &BatchOptions, default_protocol: ProxyProtocol,
) -> Result<(Vec<ProxySpec>, LoadStats)> {
    let mut proxies = Vec::new();
    let mut seen = HashSet::new();
    let mut stats = LoadStats::default();

    for source in &options.proxy_files {
        match read_text_source(client, source).await {
            Ok(text) => parse_proxy_text(
                source,
                &text,
                default_protocol,
                &mut proxies,
                &mut seen,
                &mut stats,
            ),
            Err(err) => {
                stats.source_errors += 1;
                eprintln!("warning: could not read proxy source {source}: {err:#}");
            }
        }
    }

    for source_list in &options.source_lists {
        match read_text_source(client, source_list).await {
            Ok(text) => {
                for url in meaningful_lines(&text) {
                    if !is_http_url(url) {
                        stats.source_errors += 1;
                        eprintln!("warning: source-list entry is not HTTP(S): {url}");
                        continue;
                    }
                    match fetch_url(client, url).await {
                        Ok(proxy_text) => parse_proxy_text(
                            url,
                            &proxy_text,
                            default_protocol,
                            &mut proxies,
                            &mut seen,
                            &mut stats,
                        ),
                        Err(err) => {
                            stats.source_errors += 1;
                            eprintln!("warning: could not fetch proxy-list URL {url}: {err:#}");
                        }
                    }
                }
            }
            Err(err) => {
                stats.source_errors += 1;
                eprintln!("warning: could not read source-list {source_list}: {err:#}");
            }
        }
    }

    for url in &options.source_urls {
        if !is_http_url(url) {
            stats.source_errors += 1;
            eprintln!("warning: --source-url is not HTTP(S): {url}");
            continue;
        }
        match fetch_url(client, url).await {
            Ok(text) => {
                parse_proxy_text(url, &text, default_protocol, &mut proxies, &mut seen, &mut stats)
            }
            Err(err) => {
                stats.source_errors += 1;
                eprintln!("warning: could not fetch proxy-list URL {url}: {err:#}");
            }
        }
    }

    Ok((proxies, stats))
}

async fn read_text_source(client: &Client, source: &str) -> Result<String> {
    if is_http_url(source) {
        fetch_url(client, source).await
    } else {
        fs::read_to_string(source).await.with_context(|| format!("failed to read {source}"))
    }
}

async fn fetch_url(client: &Client, url: &str) -> Result<String> {
    client
        .get(url)
        .send()
        .await
        .with_context(|| format!("request failed for {url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error for {url}"))?
        .text()
        .await
        .with_context(|| format!("failed to decode text from {url}"))
}

fn meaningful_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#'))
}

fn parse_proxy_text(
    source: &str, text: &str, default_protocol: ProxyProtocol, proxies: &mut Vec<ProxySpec>,
    seen: &mut HashSet<String>, stats: &mut LoadStats,
) {
    for line in meaningful_lines(text) {
        if let Ok(proxy) = parse_proxy_spec(line, source, default_protocol) {
            push_unique(proxy, proxies, seen);
            continue;
        }

        let mut found = false;
        for token in line.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
            if let Ok(proxy) = parse_proxy_spec(token, source, default_protocol) {
                push_unique(proxy, proxies, seen);
                found = true;
            }
        }
        if !found {
            stats.malformed_entries += 1;
        }
    }
}

fn push_unique(proxy: ProxySpec, proxies: &mut Vec<ProxySpec>, seen: &mut HashSet<String>) {
    if seen.insert(proxy.dedupe_key()) {
        proxies.push(proxy);
    }
}

fn parse_proxy_spec(raw: &str, source: &str, default_protocol: ProxyProtocol) -> Result<ProxySpec> {
    let raw = raw.trim().trim_matches(|c| c == '"' || c == '\'');
    if raw.is_empty() {
        return Err(anyhow!("empty proxy entry"));
    }

    // Common provider format: host:port:user:pass. Bracketed IPv6 is handled below.
    if !raw.contains("://") && !raw.contains('@') && !raw.starts_with('[') {
        let fields: Vec<&str> = raw.split(':').collect();
        if fields.len() == 4 {
            if let Ok(port) = fields[1].parse::<u16>() {
                if !fields[0].is_empty() && !fields[2].is_empty() {
                    return Ok(ProxySpec {
                        raw: raw.to_owned(),
                        source: source.to_owned(),
                        host: fields[0].to_owned(),
                        port,
                        username: Some(fields[2].to_owned()),
                        password: Some(fields[3].to_owned()),
                        protocol: default_protocol,
                    });
                }
            }
        }
    }

    let (protocol, url_text) = if let Some((scheme, _)) = raw.split_once("://") {
        let protocol = ProxyProtocol::parse(scheme)?;
        if protocol == ProxyProtocol::Auto {
            return Err(anyhow!("auto:// is not a valid proxy URL scheme"));
        }
        (protocol, raw.to_owned())
    } else {
        (default_protocol, format!("socks5://{raw}"))
    };

    let url = Url::parse(&url_text).with_context(|| format!("invalid proxy entry: {raw}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("proxy host is missing: {raw}"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = url.port().ok_or_else(|| anyhow!("proxy port is missing: {raw}"))?;
    let username = (!url.username().is_empty()).then(|| url.username().to_owned());
    let password = url.password().map(str::to_owned);

    Ok(ProxySpec {
        raw: raw.to_owned(),
        source: source.to_owned(),
        host,
        port,
        username,
        password,
        protocol,
    })
}

fn is_http_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_port_with_auto_protocol() {
        let proxy = parse_proxy_spec("1.2.3.4:1080", "test", ProxyProtocol::Auto).unwrap();
        assert_eq!(proxy.host, "1.2.3.4");
        assert_eq!(proxy.port, 1080);
        assert_eq!(proxy.protocol, ProxyProtocol::Auto);
    }

    #[test]
    fn parses_socks5_url_with_auth() {
        let proxy =
            parse_proxy_spec("socks5://user:pass@example.com:1080", "test", ProxyProtocol::Auto)
                .unwrap();
        assert_eq!(proxy.protocol, ProxyProtocol::Socks5);
        assert_eq!(proxy.host, "example.com");
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("pass"));
    }

    #[test]
    fn parses_colon_auth_format() {
        let proxy =
            parse_proxy_spec("1.2.3.4:1080:user:pass", "test", ProxyProtocol::Socks5).unwrap();
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("pass"));
    }

    #[test]
    fn rejects_http_proxy_scheme() {
        assert!(parse_proxy_spec("http://1.2.3.4:8080", "test", ProxyProtocol::Auto).is_err());
    }

    #[test]
    fn strips_brackets_from_ipv6_literal() {
        let proxy = parse_proxy_spec("[2001:db8::1]:1080", "test", ProxyProtocol::Socks5).unwrap();
        assert_eq!(proxy.host, "2001:db8::1");
        assert_eq!(proxy.port, 1080);
    }
}
