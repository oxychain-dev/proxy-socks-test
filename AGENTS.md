# AGENTS.md

## Project Overview

`proxy-socks-test` is a Rust CLI for testing SOCKS proxies.

- `src/main.rs`: CLI entry point and the legacy single-proxy SOCKS4/SOCKS4a/SOCKS5 test cases. The legacy path starts local TCP/UDP echo services and runs the selected case.
- `src/batch/mod.rs`: batch-mode orchestration, bounded concurrency, TSV output, and optional normalized valid-proxy output.
- `src/batch/input.rs`: local/remote proxy-list loading, source-list expansion, parsing, and deduplication.
- `src/batch/validate.rs`: proxy endpoint resolution, tester public-IP detection, proxied egress-IP validation, and latency measurement.
- `src/sockstest.sh`: helper that runs the legacy test cases for one proxy.
- `README.md`: supported CLI modes and examples.

Batch mode accepts proxy files, files containing proxy-list URLs, and direct proxy-list URLs. It supports SOCKS4, SOCKS4a, SOCKS5, and SOCKS5 authentication.

## Development Workflow

Rust 2021 project; dependencies are defined in `Cargo.toml`.

Before changing code, inspect the affected module and preserve the existing legacy CLI unless the task explicitly requires a breaking change.

Required validation for source changes:

```sh
cargo fmt --all -- --check
cargo check --locked --all-targets
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

For batch/network changes, build the binary and run the controlled local smoke fixture:

```sh
cargo build --locked
python3 tests/batch_smoke.py target/debug/proxy-socks-test
```

For batch/network behavior changes, also inspect the generated TSV contract and exercise the relevant input/parser path when a suitable test fixture is available.

## Repository Conventions

- Keep legacy single-proxy behavior in `src/main.rs` separate from batch-list behavior in `src/batch/`.
- Keep source acquisition/parsing in `batch/input.rs`, network probing in `batch/validate.rs`, and orchestration/output in `batch/mod.rs`.
- Preserve the TSV column contract documented in `README.md` unless a requested change requires updating it.
- Continue using async Tokio primitives for concurrent network work.
- Prefer bounded concurrency; do not spawn an unbounded task per proxy.
- Do not silently treat unsupported proxy schemes as SOCKS.
- Do not expose proxy credentials in new logs or reports.
- Do not replace existing public CLI flags without an explicit migration requirement.

## Change Policy

- Prefer the smallest correct change.
- Avoid unrelated refactors or dependency changes.
- Do not overwrite unrelated work.
- Inspect existing behavior before replacing it.
- Keep documentation synchronized with CLI/output changes.

## Verification

Do not mark implementation complete until the relevant format, compile, test, and clippy checks have passed. If a check cannot be run, record the exact blocker in `TODO.md` and in the final status.

For network validation, distinguish:
- tester/origin public IP,
- resolved proxy endpoint IP,
- proxy egress IP observed by the check endpoint.

## Persistent Work State

`TODO.md` is the authoritative persistent task state for this repository. Keep it synchronized with verified Git/repository state after implementation or verification changes.

## Continuation / Recovery

When resuming interrupted work:

1. Inspect the current branch/head, PR state, and `main...HEAD` divergence.
2. Read `TODO.md` and verify every active/completed item against repository evidence.
3. Inspect recent commits and CI/check results for the current head.
4. Resume from the first incomplete unblocked item.
5. Preserve valid existing work; never reset or recreate completed work merely from conversation memory.
