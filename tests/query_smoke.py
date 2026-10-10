#!/usr/bin/env python3
"""Controlled SQLite query/export/report smoke test."""

from __future__ import annotations

import csv
import sqlite3
import tempfile
from pathlib import Path

from batch_smoke import (
    LOOPBACK_IP,
    Socks5Handler,
    run_checked,
    start_http_server,
    start_tcp_server,
)


def clone_check_as_authenticated(database: Path) -> None:
    with sqlite3.connect(database) as conn:
        columns = [
            row[1]
            for row in conn.execute("PRAGMA table_info(proxy_checks)")
            if row[1] != "id"
        ]
        select_parts = [
            "1 AS auth_required" if column == "auth_required" else column
            for column in columns
        ]
        conn.execute(
            f"INSERT INTO proxy_checks ({','.join(columns)}) "
            f"SELECT {','.join(select_parts)} FROM proxy_checks ORDER BY id LIMIT 1"
        )
        conn.commit()


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def run_smoke(binary: Path) -> None:
    socks5_server, _ = start_tcp_server(Socks5Handler)
    http_server = None
    try:
        socks5_port = int(socks5_server.server_address[1])
        http_server, _ = start_http_server(socks5_port, socks5_port)
        http_port = int(http_server.server_address[1])

        with tempfile.TemporaryDirectory(prefix="proxy-socks-query-") as temp_dir:
            temp = Path(temp_dir)
            database = temp / "query.sqlite3"
            proxy_file = temp / "proxies.txt"
            proxy_file.write_text(
                f"socks5://{LOOPBACK_IP}:{socks5_port}\n",
                encoding="utf-8",
            )

            run_checked(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "--no-tsv",
                    "--proxy-file",
                    str(proxy_file),
                    "--interface",
                    "lo",
                    "--profile",
                    "standard",
                    "--latency-samples",
                    "3",
                    "--check-url",
                    f"http://{LOOPBACK_IP}:{http_port}/ip",
                    "--timeout",
                    "5",
                    "--concurrency",
                    "2",
                ]
            )

            with sqlite3.connect(database) as conn:
                run_id = int(conn.execute("SELECT MAX(id) FROM runs").fetchone()[0])
                assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 5
                auth_required = int(
                    conn.execute(
                        "SELECT auth_required FROM proxy_checks ORDER BY id LIMIT 1"
                    ).fetchone()[0]
                )
                assert auth_required == 0

            clone_check_as_authenticated(database)

            tsv = temp / "stored.tsv"
            exported = run_checked(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "export",
                    "tsv",
                    "--output",
                    str(tsv),
                    "--run-id",
                    str(run_id),
                    "--interface",
                    "lo",
                    "--protocol",
                    "socks5",
                    "--valid",
                    "true",
                ]
            )
            assert "rows=2" in exported.stdout, exported.stdout
            rows = read_tsv(tsv)
            assert len(rows) == 2, rows
            assert {row["auth_required"] for row in rows} == {"false", "true"}, rows
            assert all(row["run_id"] == str(run_id) for row in rows), rows
            assert all(row["interface"] == "lo" for row in rows), rows
            assert all(row["protocol"] == "socks5" for row in rows), rows
            assert all(row["valid"] == "true" for row in rows), rows
            assert "stages" in rows[0], rows[0]

            valid_links = temp / "valid.txt"
            valid_export = run_checked(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "export",
                    "valid",
                    "--run-id",
                    str(run_id),
                    "--output",
                    str(valid_links),
                    "--interface",
                    "lo",
                    "--protocol",
                    "socks5",
                ]
            )
            assert "links=1" in valid_export.stdout, valid_export.stdout
            assert "skipped_auth_required=1" in valid_export.stdout, valid_export.stdout
            links = [
                line.strip()
                for line in valid_links.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            assert links == [f"socks5://{LOOPBACK_IP}:{socks5_port}"], links

            report = run_checked(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "report",
                    "--run-id",
                    str(run_id),
                    "--limit",
                    "5",
                ]
            ).stdout
            assert f"run_id={run_id}" in report, report
            assert "[interfaces]" in report, report
            assert "[failures]" in report, report
            assert "[exit_ips]" in report, report
            assert "[best_proxies]" in report, report
            assert "score_formula=weighted normalized components" in report, report
            assert "\tlo\tsocks5\t" in report, report

            latest_report = run_checked(
                [str(binary), "--database", str(database), "report", "--limit", "1"]
            ).stdout
            assert f"run_id={run_id}" in latest_report, latest_report

            invalid_time = run_checked_fail(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "export",
                    "tsv",
                    "--output",
                    str(temp / "bad.tsv"),
                    "--since",
                    "definitely-not-a-date",
                ]
            )
            assert "--since" in invalid_time, invalid_time

    finally:
        for server in (http_server, socks5_server):
            if server is not None:
                server.shutdown()
                server.server_close()


def run_checked_fail(command: list[str]) -> str:
    import subprocess

    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode == 0:
        raise AssertionError(f"command unexpectedly succeeded: {' '.join(command)}")
    return completed.stdout


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "binary",
        nargs="?",
        default="target/debug/proxy-socks-test",
        help="path to the built proxy-socks-test binary",
    )
    args = parser.parse_args()
    run_smoke(Path(args.binary).resolve())
    print(
        "query smoke test passed: SQLite TSV filters, valid-link auth safety, "
        "latest/selected reports, ranking, invalid-time rejection"
    )


if __name__ == "__main__":
    main()
