# AGENTS.md

## Project Identity

`proxy-socks-test` is a Rust 2021 CLI for legacy single-proxy SOCKS tests and production-oriented batch proxy collection, validation, benchmarking, persistence, subscriptions, exports, and reports.

Preserve legacy public flags unless a change explicitly authorizes a breaking migration.

## Architecture and Repository Map

- `src/main.rs` — Clap entry point plus the legacy single-proxy SOCKS4/SOCKS4a/SOCKS5 test cases and local TCP/UDP helpers.
- `src/batch/mod.rs` — batch orchestration, bounded concurrency, immediate TSV/valid output, summary aggregation, and public batch/subcommand entrypoints.
- `src/batch/input.rs` — local/remote source acquisition, 16 MiB streamed remote-source cap, source-list expansion, parsing, and deduplication.
- `src/batch/interface.rs` — interface enumeration/selection and reqwest interface/source-address binding.
- `src/batch/model.rs` — staged-test profiles, stage statuses/results, IP metadata, and batch result models.
- `src/batch/validate.rs` — DNS resolution, TCP reachability, SOCKS/HTTP validation, latency/jitter, download/upload benchmarks, reverse DNS, and optional IP enrichment.
- `src/batch/store.rs` — SQLite connection policy, schema migrations, run/interface/check/stage persistence, and file-permission hardening.
- `src/batch/subscription.rs` — subscription CRUD, conditional fetching, cached payloads, SQLite leases, retry backoff, retention, and scheduler/service lifecycle.
- `src/batch/query.rs` — SQLite-first TSV/valid-link export and human-readable run reporting/ranking.
- `tests/batch_smoke.py` — controlled SOCKS4/SOCKS4a/SOCKS5 staged network fixture.
- `tests/subscription_smoke.py` — controlled subscription/service/ETag/304/failure/retention/permissions/shutdown fixture.
- `tests/query_smoke.py` — controlled SQLite export/filter/auth-safety/report fixture.
- `examples/proxy-socks-test.service` — hardened Linux systemd example.
- `src/sockstest.sh` — hardened compatibility helper for legacy single-proxy cases; direct CLI usage is preferred for new automation.
- `README.md` — operator-facing installation, usage, security, SQLite, subscription, service, export, and report documentation.
- `TODO.md` — authoritative persistent remaining-work state.

## Data and Security Boundaries

- SQLite is the durable batch/service history. The default path is `./proxy-socks-test.sqlite3`.
- Schema changes must be additive/versioned through `PRAGMA user_version`; never silently rebuild or discard an existing database.
- Keep `foreign_keys=ON`, WAL, busy timeout, and existing indexes unless a verified requirement changes them.
- On Unix, keep the main database and active `-wal`/`-shm` files private.
- Proxy authentication values may be used in-memory for live probing but must not be copied into report-safe TSV/SQLite identity or logs.
- Persist `auth_required` separately so stored valid-link export can skip links that cannot be reconstructed safely.
- Subscription operational URLs/cached payloads are persistent sensitive state. User-facing list/show/error output must use redacted source representations.
- Do not echo HTTP userinfo, query strings, fragments, proxy passwords, subscription tokens, or equivalent secrets in errors.
- Remote proxy/source-list bodies are capped at 16 MiB while streaming; do not regress to unbounded buffering.
- IP enrichment is optional and must never determine proxy validity.

## Staged Validation Contract

Profiles gate expensive work:

- `basic`: stages 0-3.
- `standard`: stages 0-4.
- `full`: stages 0-6.

Stages:
0. parse/deduplicate/source attribution
1. endpoint DNS resolution / all A+AAAA / tested IP selection
2. TCP endpoint reachability
3. SOCKS + proxied HTTP validity / exit IP
4. repeated latency/jitter
5. download throughput
6. upload throughput

Do not run later expensive stages when an earlier required stage fails.

Keep tester public IP, proxy endpoint IP, and proxy exit IP semantically distinct.

## Interface Rules

- No interface flags means OS/default-route behavior.
- `--interface` is repeatable.
- `--all-interfaces` excludes loopback-only interfaces and conflicts with explicit interfaces.
- Bind reqwest traffic by interface where supported; fallback to a matching local address only on platforms without the named-interface API.
- Do not require root globally. Linux deployments start unprivileged; any capability exception must be narrow and evidence-driven.

## Subscription / Service Rules

- Supported source types: `proxy-list` and `source-list`.
- Honor ETag/Last-Modified conditional fetches and cached payload reuse after 304.
- Use SQLite lease claims to prevent duplicate concurrent execution across service processes.
- Release leases on success/failure.
- Preserve bounded exponential failure backoff.
- Handle SIGINT/SIGTERM without starting new work after shutdown is requested.
- Retention deletes historical run data only according to the explicit service setting; `0` disables age-based pruning.

## Query / Export Rules

- Stored TSV export must not re-test proxies.
- Preserve the documented stable TSV column contract.
- Filters must remain parameterized SQL; do not concatenate user values into SQL.
- Stored valid-link export must skip `auth_required=1` rows and report the skipped count. Never fabricate credential-free links for authenticated proxies.
- Report ranking formula is documented in README: latency 40%, download 35%, upload 25%, normalized per run and renormalized when metrics are missing.

## Development Workflow

Before editing:

1. Inspect branch/head/PR and `main...HEAD` divergence.
2. Read this file and `TODO.md`.
3. Inspect affected source/tests/documentation.
4. Preserve unrelated work and current public behavior.
5. Make the smallest coherent change.
6. Add/update focused tests.
7. Run required validation.
8. Review diff/state and synchronize `TODO.md` only with verified results.

Use locked dependencies for verification.

## Required Verification

For source changes:

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

Additional checks:

```sh
bash -n src/sockstest.sh
src/sockstest.sh --help
systemd-analyze verify examples/proxy-socks-test.service
git diff --check
```

The permanent GitHub Actions workflow should execute the supported checks above. A check is not “verified” merely because it is documented.

## Coding Conventions

- Keep async network work on Tokio and keep concurrency bounded.
- Keep source acquisition/parsing, interface logic, probing, persistence, subscriptions, and query/reporting in their dedicated modules.
- Use `anyhow` context for actionable errors, but sanitize network-source errors before persistence/display.
- Use parameterized rusqlite statements.
- Preserve IPv6 bracket handling at serialization boundaries.
- Preserve scheme-specific SOCKS semantics and do not silently treat unsupported schemes as SOCKS.
- Avoid unrelated dependency upgrades/refactors.
- Keep README/CHANGELOG/TODO/AGENTS synchronized with public behavior.

## Persistent State and Continuation

`TODO.md` is the authoritative remaining-work backlog. Completed historical details may be removed from TODO when verified; Git/PR history and recorded CI run IDs are the audit trail.

On `continue`:

1. Reinspect current repository/PR/check state.
2. Reconcile TODO against source and observed verification.
3. Resume the first incomplete unblocked authorized task.
4. Do not repeat verified work or restart the architecture from chat memory.
5. Before ending, record exact verification evidence and remaining work.

Never claim implementation or verification that was not observed.
