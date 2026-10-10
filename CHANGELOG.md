# Changelog

All notable changes to `proxy-socks-test` are documented here.

## 0.5.0

- Added SQLite-first TSV export without re-testing.
- Added stored valid-link export with explicit skipping of authenticated results whose credentials are intentionally not persisted.
- Added SQLite filters by run, subscription, interface, protocol, validity, and time range.
- Added latest/selected run reports with per-interface summaries, failure-stage breakdown, exit-IP statistics, and ranked valid proxies.
- Added persisted `auth_required` state through schema migration v5.
- Enforced the remote source 16 MiB limit while streaming chunked/unknown-length responses.
- Redacted remote source URL userinfo/query/fragment from warnings and fetch errors.
- Hardened SQLite main/WAL/SHM permissions on Unix.
- Hardened the legacy `src/sockstest.sh` helper by removing `eval`, quoting arguments, validating options, and no longer printing authentication values.
- Rewrote README with Linux installation, interface testing, Stage 0-6 profiles, SQLite, exports, reports, subscriptions, service, systemd, and security guidance.

## 0.4.0

- Added persistent subscriptions for direct proxy-list URLs and source-list URLs.
- Added ETag/Last-Modified conditional fetches and cached-payload reuse after HTTP 304.
- Added recurring `service` mode, `service --once`, SIGINT/SIGTERM handling, bounded retry backoff, and history retention.
- Added SQLite subscription-run leases to prevent duplicate concurrent runs across service processes.
- Added safe source-fetch failure persistence, including HTTP status without exposing source secrets.
- Added hardened example systemd unit for an unprivileged Linux service.
- Added controlled subscription/service integration coverage.

## 0.3.0

- Added staged validation profiles: `basic`, `standard`, and `full`.
- Added Stage 0-6 diagnostics: parse/deduplicate, resolution, TCP reachability, SOCKS/HTTP validity, latency/jitter, download throughput, and upload throughput.
- Added all resolved endpoint addresses, tested endpoint IP, reverse DNS, distinct tester/endpoint/exit IPs, and optional provider-neutral IP metadata enrichment.
- Added professional per-interface and overall summaries.
- Migrated SQLite to persist staged metrics and IP metadata.
- Added controlled full-profile SOCKS4/SOCKS4a/SOCKS5 smoke coverage.

## 0.2.0

- Added batch proxy ingestion from files, direct URLs, and source-list files/URLs.
- Added parsing/deduplication for SOCKS4, SOCKS4a, SOCKS5, credentials, and bracketed IPv6.
- Added `--interface` and `--all-interfaces` testing with per-interface tester IP/local addresses.
- Added SQLite as the durable run store and kept immediate TSV/valid-list compatibility output.
- Added credential-safe report identity and output-path collision checks.
- Added locked dependency resolution and controlled batch smoke tests.

## Earlier releases

Earlier repository history contains the original single-proxy SOCKS test cases and compatibility helper behavior. This changelog starts its detailed phase history with the batch/interface/SQLite development line.
