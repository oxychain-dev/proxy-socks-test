# Project TODO

> Persistent task state for AI agents.
> Keep this file synchronized with the verified repository state.
> Repository/Git evidence overrides this file when they disagree.
> Completed historical tasks are intentionally removed from this file; use Git/PR history and verification run IDs for audit history.

## Current Focus

* [~] **Phase 4 / v0.5.0 — SQLite query/export, reporting, operator UX, documentation, and final hardening**
  * [~] Make persisted results independently queryable/exportable and finish production-facing Linux/operator documentation.

## Next

### P0 — Critical

* None currently known.

### P1 — Important

#### Phase 4 / v0.5.0 — Query/export/reporting and operator UX

* [~] Add SQLite-first query/export commands.
  * [ ] Export TSV from stored results without re-testing.
  * [ ] Filters for run/subscription/interface/protocol/validity/time range.
  * [ ] Export credential-free valid normalized proxy links from a selected stored run.
  * [ ] Track whether a validated proxy required authentication so unusable credential-free links can be skipped explicitly.
  * [ ] Stable export column contract including run, interface, staged metrics, IP metadata, and errors.
  * **Verify:** seeded/controlled DB export tests, including filters and authenticated-proxy safety behavior.

* [ ] Add human-readable reporting commands.
  * [ ] Latest-run summary and explicit run selection.
  * [ ] Per-interface comparison.
  * [ ] Best valid proxies using a documented latency/download/upload score.
  * [ ] Failure-stage breakdown and exit-IP summary.
  * **Verify:** deterministic report tests against a controlled SQLite run.

* [ ] Rewrite `README.md` for the complete production workflow.
  * [ ] Architecture and Stage 0–6 test model.
  * [ ] Linux prerequisites and installation-from-source commands.
  * [ ] Binary installation/update commands and verification.
  * [ ] Interface-specific and all-interface examples.
  * [ ] SQLite default location, schema lifecycle, and export/report examples.
  * [ ] Subscription CRUD, conditional refresh, recurring service, retention, and systemd examples.
  * [ ] Security/privacy notes for proxy credentials, subscription URLs, IP enrichment, interface binding, and speed-test bandwidth.
  * [ ] Legacy single-proxy compatibility section.
  * **Verify:** every documented command matches implemented `--help` and controlled tests.

* [ ] Final reliability/security hardening for v0.5.0.
  * [ ] Stream remote source bodies with a hard 16 MiB cap instead of buffering an unbounded chunked response.
  * [ ] Redact remote source URLs in warning/error output, including nested source-list URLs.
  * [ ] Verify SQLite/WAL/SHM local permission behavior where applicable.
  * [ ] Review `src/sockstest.sh` for quoting/eval/argument-parsing defects; harden it or deprecate it in favor of direct CLI usage.
  * [ ] Add permanent CI for fmt/check/test/clippy/build plus controlled batch, subscription/service, query/export/report, and systemd fixtures.
  * [ ] Add release notes/changelog for v0.2.0 through v0.5.0.
  * [ ] Update `AGENTS.md` to the final module map and verification gates.
  * **Verify:** full permanent CI passes on the final branch and no temporary workflows remain.

### P2 — Normal / Cleanup

* [ ] Review whether additional DB retention/vacuum controls are useful after real service usage; do not add speculative maintenance behavior without evidence.
* [ ] Consider splitting the legacy single-proxy CLI from `src/main.rs` only if maintainability requires it; preserve compatibility.

## Blocked

* None.

## Discovered During Work

* [ ] Authentication secrets are intentionally not written to report-safe result rows; v0.5.0 export must explicitly handle authenticated valid proxies rather than fabricating reusable links.
* [ ] Source warning paths can still echo raw remote URLs; close this before production documentation claims secret-safe logging.
* [ ] The existing 16 MiB remote-source check must enforce the limit while streaming, not only after full buffering when Content-Length is absent.

## Completed

* Historical completed tasks are intentionally omitted from this backlog per project policy. Verified phase checkpoints are preserved in Git/PR history, including GitHub Actions runs 37919598208, 37920331362, 37921774924, 38064468094, and 38064575361.
