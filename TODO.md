# Project TODO

> Persistent task state for AI agents.
> Repository/Git evidence overrides this file when they disagree.
> Completed detailed tasks are intentionally removed after verification; Git/PR history and CI run IDs remain the audit trail.

## Current Focus

* None. The requested v0.2.0-v0.5.0 implementation scope is complete and verified.

## Open Required Work

* None currently known.

## Blocked

* None.

## Reviewed / Deferred

* Additional SQLite `VACUUM` automation is not currently justified. Service-mode age retention already bounds historical rows; add vacuum/size policy only when real operational evidence requires it.
* Splitting the legacy single-proxy implementation out of `src/main.rs` is not required for current correctness. Batch/interface/probe/store/subscription/query responsibilities are already isolated under `src/batch/`; avoid a compatibility-risk refactor without a concrete need.

## Verified Release Checkpoints

* v0.2.0 — secure interface-aware validation and SQLite foundation: GitHub Actions run `37920331362` (with security-hardening run `37919598208`).
* v0.3.0 — Stage 0-6 diagnostics, speed tests, DNS/IP intelligence, and summaries: run `37921774924`.
* v0.4.0 — subscriptions, conditional refresh, leases, service mode, retention, and systemd example: runs `38064468094` and `38064575361`.
* v0.5.0 — SQLite query/export/reporting, auth-safe exports, streamed source cap, logging/permission/shell hardening, README/CHANGELOG/AGENTS, and permanent CI: run `38065779413`.

## Maintenance Rules

* Add a task only when it is supported by a user requirement, repository evidence, a verified defect, or a clearly labeled approved improvement.
* Use only `[ ]`, `[~]`, `[!]`, and `[x]` while active tasks exist.
* Do not mark work complete until its acceptance criteria are observed in tests/checks.
* After verified completion, remove detailed completed tasks from the active backlog and retain compact verification evidence here plus full history in Git/PR.
* On `continue`, inspect the current branch/head, PR/checks, this file, and `AGENTS.md` before deciding whether any new work exists.
