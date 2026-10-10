# proxy-socks-test

`proxy-socks-test` is a Rust CLI for collecting, validating, benchmarking, persisting, scheduling, and reporting SOCKS4, SOCKS4a, and SOCKS5 proxies.

Version 0.5 keeps the original single-proxy test cases, while the primary batch workflow adds:

- local files, direct proxy-list URLs, and lists of proxy-list URLs;
- per-interface or all-interface testing;
- staged validation from parsing through download/upload benchmarks;
- tester IP, proxy endpoint IPs, reverse DNS, proxy exit IP, and optional IP metadata;
- SQLite history in the current working directory by default;
- TSV and credential-free valid-link export from SQLite without re-testing;
- recurring subscriptions with conditional HTTP refresh, leases, backoff, and retention;
- human-readable run reports and proxy ranking;
- controlled local integration fixtures for SOCKS4/SOCKS4a/SOCKS5.

## Linux installation

### 1. Install build prerequisites

On Debian or Ubuntu:

```sh
sudo apt update
sudo apt install -y build-essential pkg-config git curl ca-certificates
```

Rust's recommended installer is `rustup`:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustc --version
cargo --version
```

The project uses rustls for HTTP TLS and builds SQLite from the bundled rusqlite/libsqlite3 source, so an OpenSSL development package or system SQLite development package is not required by the current Cargo configuration.

### 2. Build from source

```sh
git clone https://github.com/oxychain-dev/proxy-socks-test.git
cd proxy-socks-test
cargo build --release --locked
./target/release/proxy-socks-test --version
```

Install the binary system-wide if desired:

```sh
sudo install -m 0755 target/release/proxy-socks-test /usr/local/bin/proxy-socks-test
proxy-socks-test --version
```

To update an existing source checkout:

```sh
git pull --ff-only
cargo build --release --locked
sudo install -m 0755 target/release/proxy-socks-test /usr/local/bin/proxy-socks-test
proxy-socks-test --version
```

## Proxy inputs

Batch mode starts when at least one input flag is present:

- `--proxy-file <path-or-url>`: local file or HTTP(S) URL containing proxy entries.
- `--source-url <url>`: direct HTTP(S) proxy-list URL; repeat as needed.
- `--source-list <path-or-url>`: local file or HTTP(S) URL whose non-comment lines are proxy-list URLs.

Supported proxy entry forms:

```text
1.2.3.4:1080
1.2.3.4:1080:user:pass
socks5://user:pass@example.com:1080
socks4://example.com:1080
socks4a://example.com:1080
[2001:db8::1]:1080
```

Blank lines and lines beginning with `#` are ignored. Inputs are deduplicated before testing. HTTP(S) source bodies are limited to 16 MiB each.

For scheme-less entries, `--protocol auto` tries SOCKS5, SOCKS4a, then SOCKS4. A scheme-less entry containing credentials is tested as SOCKS5 only.

## Interface-aware testing

With no interface flag, the operating system's normal route selection is used.

Test one interface:

```sh
proxy-socks-test \
  --proxy-file proxies.txt \
  --interface eth0 \
  --profile standard \
  --database proxy-socks-test.sqlite3 \
  --output proxy-results.tsv
```

Test several named interfaces by repeating the option:

```sh
proxy-socks-test \
  --proxy-file proxies.txt \
  --interface eth0 \
  --interface wlan0 \
  --profile standard
```

Test every usable non-loopback interface:

```sh
proxy-socks-test \
  --proxy-file proxies.txt \
  --all-interfaces \
  --profile standard
```

For each interface the database/report records the interface name, local IP addresses, direct tester public IP, selected proxy endpoint IP, and proxied exit IP.

On supported operating systems reqwest binds by interface name. On platforms without that API, the implementation falls back to a matching local source address. Linux deployments should start unprivileged; if the host's kernel/security policy rejects interface binding with `EPERM`, see the capability note in `examples/proxy-socks-test.service` rather than running the whole service as root.

## Staged test profiles

Tests are gated: a failed cheap stage prevents later expensive work.

| Stage | Name | Purpose |
| --- | --- | --- |
| 0 | parse/deduplicate | Parse, normalize, attribute source, deduplicate. |
| 1 | resolve endpoint | Resolve all A/AAAA addresses and choose the tested IP. |
| 2 | TCP reachability | Measure direct TCP connect time to the proxy endpoint. |
| 3 | proxy HTTP validation | Negotiate SOCKS, request the check URL, obtain exit IP. |
| 4 | latency/jitter | Repeated proxied HTTP samples, p50/p95 latency and jitter. |
| 5 | download throughput | Bounded download benchmark. |
| 6 | upload throughput | Bounded upload benchmark. |

Profiles:

- `basic`: stages 0-3.
- `standard` (default): stages 0-4.
- `full`: stages 0-6.

Example full run:

```sh
proxy-socks-test \
  --source-url https://example.com/proxies.txt \
  --interface eth0 \
  --profile full \
  --latency-samples 5 \
  --download-bytes 1048576 \
  --upload-bytes 262144 \
  --database proxy-socks-test.sqlite3 \
  --output proxy-results.tsv
```

Defaults:

- IP check: `https://api.ipify.org`
- download: `https://speed.cloudflare.com/__down?bytes={bytes}`
- upload: `https://speed.cloudflare.com/__up`
- timeout: 10 seconds
- concurrency: 100

Override them with `--check-url`, `--download-url`, `--upload-url`, `--timeout`, and `--concurrency`.

### Optional IP enrichment

Use a provider-neutral JSON URL template containing `{ip}`:

```sh
proxy-socks-test \
  --proxy-file proxies.txt \
  --ip-info-url-template 'https://ip-info.example/api/{ip}' \
  --profile standard
```

Enrichment is optional and never determines proxy validity. The implementation stores the raw JSON plus common fields when present: country, region, city, organization, ASN, and timezone.

## SQLite persistence

The default database is:

```text
./proxy-socks-test.sqlite3
```

Override it with:

```sh
proxy-socks-test --database /path/to/proxy-socks-test.sqlite3 --proxy-file proxies.txt
```

SQLite is the durable history. It stores runs, interface runs, proxy checks, stage results, subscriptions, and subscription-run history. Schema migrations are automatic and versioned through SQLite `user_version`.

On Unix, the database and active WAL/SHM companion files are restricted to mode `0600`.

Disable immediate TSV generation when only SQLite persistence is wanted:

```sh
proxy-socks-test \
  --proxy-file proxies.txt \
  --database proxy-socks-test.sqlite3 \
  --no-tsv
```

## Immediate TSV and valid proxy output

A normal batch run writes `proxy-results.tsv` unless `--no-tsv` is supplied.

```sh
proxy-socks-test \
  --proxy-file proxies.txt \
  --output proxy-results.tsv \
  --valid-output valid-proxies.txt
```

The immediate TSV includes source/input in redacted form, interface/local addresses, tester IP, original proxy host, all resolved addresses, tested endpoint IP, reverse DNS, validity/protocol, TCP/HTTP/latency/jitter/speed metrics, exit IP, selected IP metadata, stage statuses, and errors.

`--valid-output` is generated during the live test and therefore can retain credentials for an authenticated proxy. Protect that file accordingly.

## Export stored SQLite results

### Export TSV without re-testing

```sh
proxy-socks-test \
  --database proxy-socks-test.sqlite3 \
  export tsv \
  --output stored-results.tsv \
  --run-id 42 \
  --valid true
```

Available TSV filters:

- `--run-id <id>`
- `--subscription-id <id>`
- `--interface <name>`
- `--protocol socks4|socks4a|socks5`
- `--valid true|false`
- `--since <datetime>`
- `--until <datetime>`

Time filters accept SQLite-compatible date/time values, for example `2026-10-10T15:30:00Z`.

The stored export contains only report-safe proxy identity. Authentication secrets are intentionally not persisted in result rows.

### Export reusable valid links

```sh
proxy-socks-test \
  --database proxy-socks-test.sqlite3 \
  export valid \
  --run-id 42 \
  --output valid-from-run.txt
```

Optional filters: `--interface` and `--protocol`.

Authenticated proxies are explicitly skipped because the result database does not store their reusable credentials. The command reports `skipped_auth_required=<count>` rather than fabricating credential-free links that would not work.

## Reports

Show the latest stored run:

```sh
proxy-socks-test --database proxy-socks-test.sqlite3 report
```

Show a specific run and the top 20 valid proxies:

```sh
proxy-socks-test \
  --database proxy-socks-test.sqlite3 \
  report --run-id 42 --limit 20
```

The report includes:

- run/profile/count metadata;
- per-interface tested/valid counts and average performance;
- failure-stage breakdown;
- unique/changed exit-IP summary;
- ranked valid proxies.

Ranking uses normalized available metrics and renormalizes when a metric is absent:

- latency: 40%, lower is better;
- download: 35%, higher is better;
- upload: 25%, higher is better.

The score is a comparison aid inside one run, not a guarantee of future proxy performance.

## Subscriptions

Subscriptions persist recurring source/test configuration in SQLite.

Add a direct proxy-list subscription:

```sh
proxy-socks-test \
  --database proxy-socks-test.sqlite3 \
  subscription add \
  --name public-socks \
  --url https://example.com/proxies.txt \
  --source-type proxy-list \
  --interval-seconds 3600 \
  --interface eth0 \
  --profile standard
```

Add a URL whose body is itself a list of proxy-list URLs:

```sh
proxy-socks-test \
  --database proxy-socks-test.sqlite3 \
  subscription add \
  --name source-index \
  --url https://example.com/sources.txt \
  --source-type source-list \
  --interval-seconds 3600 \
  --profile basic
```

Manage subscriptions:

```sh
proxy-socks-test --database proxy-socks-test.sqlite3 subscription list
proxy-socks-test --database proxy-socks-test.sqlite3 subscription show --id 1
proxy-socks-test --database proxy-socks-test.sqlite3 subscription run --id 1
proxy-socks-test --database proxy-socks-test.sqlite3 subscription disable --id 1
proxy-socks-test --database proxy-socks-test.sqlite3 subscription enable --id 1
proxy-socks-test --database proxy-socks-test.sqlite3 subscription remove --id 1
```

The scheduler uses ETag/Last-Modified conditional requests when provided by the source, reuses a cached payload after HTTP 304, applies bounded failure backoff, and uses a SQLite lease to prevent duplicate concurrent execution of the same subscription.

## Recurring service mode

Process all currently due subscriptions once:

```sh
proxy-socks-test \
  --database proxy-socks-test.sqlite3 \
  service --once
```

Run continuously:

```sh
proxy-socks-test \
  --database proxy-socks-test.sqlite3 \
  service --poll-seconds 5 --retention-days 30
```

`SIGINT` and `SIGTERM` stop the scheduler gracefully after current in-flight work. `--retention-days 0` disables age-based run-history pruning.

## systemd service on Linux

A hardened example unit is included at `examples/proxy-socks-test.service`. Its paths assume the binary is installed as `/usr/local/bin/proxy-socks-test` and state lives in `/var/lib/proxy-socks-test`.

Create the unprivileged service account and state directory:

```sh
sudo groupadd --system proxy-socks-test
sudo useradd \
  --system \
  --gid proxy-socks-test \
  --home-dir /var/lib/proxy-socks-test \
  --shell /usr/sbin/nologin \
  proxy-socks-test
sudo install -d -o proxy-socks-test -g proxy-socks-test -m 0750 /var/lib/proxy-socks-test
```

Install and verify the unit:

```sh
sudo install -m 0644 examples/proxy-socks-test.service /etc/systemd/system/proxy-socks-test.service
sudo systemd-analyze verify /etc/systemd/system/proxy-socks-test.service
sudo systemctl daemon-reload
sudo systemctl enable --now proxy-socks-test.service
sudo systemctl status proxy-socks-test.service
```

Follow logs:

```sh
sudo journalctl -u proxy-socks-test.service -f
```

Stop/restart:

```sh
sudo systemctl stop proxy-socks-test.service
sudo systemctl restart proxy-socks-test.service
```

The example unit starts with an empty capability bounding set. Do not run the service as root simply to test interface binding. If an interface-bound subscription specifically fails with `EPERM` on your Linux host, review the commented narrow `CAP_NET_RAW` fallback in the unit and apply only if your host policy requires it.

## Security and privacy

- Proxy credentials are used for live validation but are redacted from TSV/database report-safe identity.
- Subscription operational URLs and cached source payloads are stored in the protected SQLite database because they are needed for future refreshes. `subscription list/show` display a redacted URL.
- Remote-source errors and warnings redact URL userinfo/query/fragment.
- SQLite main/WAL/SHM files are restricted on Unix; still protect the parent directory and backups.
- `export valid` skips authenticated results because reusable secrets are not stored in result rows.
- `--valid-output` from a live run can contain authentication data; handle it as sensitive.
- An IP-enrichment provider receives the IP being enriched. Do not configure a third-party service unless that disclosure is acceptable.
- `full` profile consumes network bandwidth. Tune `--download-bytes`, `--upload-bytes`, concurrency, and subscription intervals intentionally.
- A public proxy is untrusted network infrastructure. Do not send private credentials or sensitive traffic through proxies merely because they pass these checks.

## Legacy single-proxy compatibility

The original test-case interface remains available:

```sh
proxy-socks-test \
  --proxyip 127.0.0.1 \
  --proxyport 1080 \
  --serverip 127.0.0.1 \
  --serverport 3307 \
  --casename socks5_connect \
  --debug
```

Legacy case names include SOCKS4/SOCKS4a/SOCKS5 connect, hostname, bind, UDP, and authenticated SOCKS5 cases supported by the existing implementation.

`src/sockstest.sh` is a compatibility helper for running several legacy cases. It no longer uses `eval` and does not print authentication values, but direct CLI usage is preferred for new automation.

## Development verification

Required Rust checks:

```sh
cargo fmt --all -- --check
cargo check --locked --all-targets
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
```

Controlled integration fixtures:

```sh
python3 tests/batch_smoke.py target/debug/proxy-socks-test
python3 tests/subscription_smoke.py target/debug/proxy-socks-test
python3 tests/query_smoke.py target/debug/proxy-socks-test
```

Shell helper syntax:

```sh
bash -n src/sockstest.sh
```

## License

MIT. See `LICENSE`.
