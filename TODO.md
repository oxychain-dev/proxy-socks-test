# Project TODO

> Persistent task state for AI agents.
> Keep this file synchronized with the verified repository state.
> Repository/Git evidence overrides this file when they disagree.

## Current Focus

* [~] **Phase 1 / v0.2.0 — secure interface-aware validation + SQLite foundation**
  * [~] Close current correctness/security defects before extending the probe engine.

## Next

### P0 — Critical

#### Phase 1 / v0.2.0 — Secure interface-aware validator + persistent database

* [x] Fix correctness and secret-handling defects already identified in PR review.
  * [x] Redact proxy credentials from TSV/report-safe input fields while preserving authentication for actual probing.
  * [x] Normalize bracketed IPv6 literals so endpoint resolution/probing works.
  * [x] Reject equivalent/colliding output paths before opening writers.
  * [x] Add regression tests for all three defects.
  * **Verify:** GitHub Actions run 37919598208 passed fmt/check/test/clippy/build, controlled SOCKS smoke, and diff validation.

* [ ] Add explicit network-interface selection.
  * [ ] `--interface <name>` repeatable for one or more selected interfaces.
  * [ ] `--all-interfaces` to enumerate usable non-loopback interfaces and test each independently.
  * [ ] Record interface name, local address/family, and tester public IP per interface.
  * [ ] Bind HTTP/proxy traffic to the selected interface on supported platforms; fail clearly when an interface cannot be bound.
  * [ ] Preserve current unbound/default-route behavior when no interface option is supplied.
  * **Verify:** unit tests for selection/filtering plus loopback-controlled integration coverage on Linux.

* [ ] Replace TSV-as-primary-state with SQLite as the durable run store.
  * [ ] Default database path is `./proxy-socks-test.sqlite3` in the current working directory.
  * [ ] Create schema/version metadata and idempotent migrations.
  * [ ] Store runs, interfaces, redacted proxy identity, endpoint resolution, stage results, metrics, and errors.
  * [ ] Enable WAL/busy-timeout/foreign-keys and create useful indexes.
  * [ ] Create the database with restrictive local permissions where supported.
  * [ ] Keep optional immediate TSV/valid-list compatibility exports.
  * **Verify:** database integration test validates schema, inserts, indexes/constraints, and report-safe credential handling.

* [ ] Align CLI/package versioning and help text for v0.2.0.
  * [ ] Remove hard-coded Clap `1.0` version drift and use Cargo package version.
  * [ ] Document v0.2.0 as the first interface-aware/SQLite-capable release.
  * **Verify:** `--version` matches Cargo metadata and CLI help spot-check is coherent.

#### Phase 2 / v0.3.0 — Staged diagnostic and performance pipeline

* [ ] Implement staged validation profiles so cheap checks gate expensive checks.
  * [ ] Stage 0: parse/deduplicate/source attribution.
  * [ ] Stage 1: resolve proxy host and retain every A/AAAA result plus selected tested IP.
  * [ ] Stage 2: endpoint reachability/connect timing.
  * [ ] Stage 3: SOCKS protocol/authentication + proxied HTTP validation + exit IP.
  * [ ] Stage 4: repeated latency/jitter samples and basic HTTP timing.
  * [ ] Stage 5: download throughput benchmark with configurable byte budget/URL.
  * [ ] Stage 6: upload throughput benchmark with configurable byte budget/URL.
  * [ ] Profiles: `basic`, `standard`, `full`, with explicit stage cutoffs.
  * [ ] Do not run expensive speed stages for proxies that fail earlier stages.
  * **Verify:** deterministic local fixtures cover stage gating and metric calculations.

* [ ] Add endpoint/domain/IP intelligence.
  * [ ] Preserve original hostname and all resolved IPs when the proxy input is a domain.
  * [ ] Add reverse-DNS lookup when available.
  * [ ] Capture tester IP, proxy endpoint IP, and proxy exit IP distinctly.
  * [ ] Add optional provider-neutral IP-enrichment URL template with cached raw JSON + normalized common fields when present.
  * [ ] Never make third-party enrichment mandatory for validity.
  * **Verify:** local JSON fixture + DNS/IP unit tests; failures degrade to nullable metadata without invalidating an otherwise valid proxy.

* [ ] Add professional per-run summaries.
  * [ ] Counts by interface/protocol/stage/failure reason.
  * [ ] p50/p95 latency and jitter where enough samples exist.
  * [ ] download/upload Mbps summaries.
  * [ ] exit-IP uniqueness/change indicators.
  * [ ] clear machine-readable stage status/error fields.
  * **Verify:** summary tests against a seeded SQLite fixture.

### P1 — Important

#### Phase 3 / v0.4.0 — Subscriptions, recurring tests, and service mode

* [ ] Add subscription management backed by SQLite.
  * [ ] Add/list/show/enable/disable/remove subscriptions.
  * [ ] Support direct proxy-list URLs and source-list URLs.
  * [ ] Store stable names, source type, interval, interface selector, profile, and benchmark settings.
  * [ ] Redact credentials/tokens from display/logging while retaining the operational source value in the protected database.
  * [ ] Record fetch status, ETag/Last-Modified when supplied, last success/error, and item counts.
  * **Verify:** CRUD + redaction + conditional-fetch tests.

* [ ] Add recurring scheduler/service mode.
  * [ ] Run enabled subscriptions at fixed intervals with bounded overlap.
  * [ ] Support one-shot `subscription run` and long-running `service` mode.
  * [ ] Graceful SIGINT/SIGTERM shutdown and in-flight run finalization.
  * [ ] Backoff after repeated source/network failures.
  * [ ] Prevent duplicate concurrent runs for the same subscription/interface.
  * **Verify:** short-interval integration test with controlled local source; graceful shutdown test.

* [ ] Add Linux service packaging guidance.
  * [ ] Example systemd unit using an unprivileged dedicated user.
  * [ ] WorkingDirectory/database path guidance.
  * [ ] Restart/backoff and hardening recommendations.
  * **Verify:** unit syntax is documented and command paths match installed binary behavior.

#### Phase 4 / v0.5.0 — Query/export/reporting and operator UX

* [ ] Add SQLite-first query/export commands.
  * [ ] Export TSV from stored runs without re-testing.
  * [ ] Filters for run/subscription/interface/protocol/validity/time range.
  * [ ] Export valid normalized proxy links from a selected stored run.
  * [ ] Stable column contract including staged metrics and interface fields.
  * **Verify:** seeded DB export golden tests.

* [ ] Add human-readable reporting commands.
  * [ ] Latest-run summary.
  * [ ] Per-interface comparison.
  * [ ] Best valid proxies by latency/download/upload score.
  * [ ] Failure-reason breakdown.
  * **Verify:** deterministic report tests from seeded DB data.

* [ ] Rewrite `README.md` for the production workflow.
  * [ ] Architecture and staged test model.
  * [ ] Linux prerequisites and installation from source.
  * [ ] Build/release binary installation commands.
  * [ ] Interface-specific and all-interface examples.
  * [ ] SQLite location/schema lifecycle and TSV export examples.
  * [ ] Subscription/service/systemd examples.
  * [ ] Security/privacy notes for credentials, IP enrichment, and speed-test bandwidth use.
  * [ ] Legacy single-proxy compatibility section.
  * **Verify:** every documented command matches `--help`/implemented flags.

### P2 — Normal / Cleanup

* [ ] Refactor the monolithic legacy CLI only where needed to keep new subcommands/modules maintainable without breaking legacy flags.
* [ ] Add source-download size limits and clearer malformed/source error accounting.
* [ ] Add permanent CI for fmt/check/test/clippy plus controlled integration fixtures once the expanded architecture stabilizes.
* [ ] Review `src/sockstest.sh` for quoting/eval/argument-parsing defects; either harden it or deprecate it in favor of direct CLI usage.
* [ ] Add changelog/release notes per usable phase (v0.2.0 through v0.5.0).

## Blocked

* None.

## Discovered During Work

* [ ] Confirm the exact reqwest interface-binding API used by the locked dependency during compilation and keep a source-IP fallback for unsupported platforms.
* [ ] Evaluate database growth/retention controls before v0.4.0 service mode is declared complete.

## Completed

* None for the new phased roadmap. Historical completed tasks were intentionally removed after reconciliation; Git history/PR history remains the audit trail.
