#!/usr/bin/env python3
"""Controlled end-to-end smoke test for subscriptions and service mode."""

from __future__ import annotations

import os
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from batch_smoke import LOOPBACK_IP, Socks5Handler, run_checked, start_tcp_server


ETAG = '"fixture-v1"'
LAST_MODIFIED = "Wed, 21 Oct 2015 07:28:00 GMT"


class SubscriptionFixtureHandler(BaseHTTPRequestHandler):
    socks5_port = 0
    http_port = 0
    direct_requests = 0
    direct_conditional_requests = 0
    source_list_requests = 0

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlsplit(self.path)

        if parsed.path == "/ip":
            self._send_text(f"{LOOPBACK_IP}\n")
            return

        if parsed.path == "/direct":
            type(self).direct_requests += 1
            if self.headers.get("If-None-Match") == ETAG:
                type(self).direct_conditional_requests += 1
                self.send_response(304)
                self.send_header("ETag", ETAG)
                self.send_header("Last-Modified", LAST_MODIFIED)
                self.end_headers()
                return
            self._send_text(
                f"{LOOPBACK_IP}:{self.socks5_port}\n",
                etag=ETAG,
                last_modified=LAST_MODIFIED,
            )
            return

        if parsed.path == "/oversize":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            chunk = b"x" * (1024 * 1024)
            for _ in range(17):
                self.wfile.write(chunk)
                self.wfile.flush()
            return

        if parsed.path == "/failure":
            self.send_response(503)
            payload = b"fixture unavailable"
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if parsed.path == "/source-list":
            type(self).source_list_requests += 1
            self._send_text(
                f"http://{LOOPBACK_IP}:{self.http_port}/nested.txt\n",
                etag='"sources-v1"',
                last_modified=LAST_MODIFIED,
            )
            return

        if parsed.path == "/nested.txt":
            self._send_text(f"{LOOPBACK_IP}:{self.socks5_port}\n")
            return

        self.send_error(404)

    def _send_text(
        self,
        body: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> None:
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if etag is not None:
            self.send_header("ETag", etag)
        if last_modified is not None:
            self.send_header("Last-Modified", last_modified)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *args: object) -> None:
        del args


def start_http_server(
    socks5_port: int,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer((LOOPBACK_IP, 0), SubscriptionFixtureHandler)
    http_port = int(server.server_address[1])
    SubscriptionFixtureHandler.socks5_port = socks5_port
    SubscriptionFixtureHandler.http_port = http_port
    SubscriptionFixtureHandler.direct_requests = 0
    SubscriptionFixtureHandler.direct_conditional_requests = 0
    SubscriptionFixtureHandler.source_list_requests = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def db_scalar(database: Path, query: str, params: tuple[object, ...] = ()) -> object:
    with sqlite3.connect(database) as conn:
        row = conn.execute(query, params).fetchone()
        if row is None:
            raise AssertionError(f"query returned no rows: {query}")
        return row[0]


def wait_for_subscription_runs(
    database: Path,
    subscription_id: int,
    minimum: int,
    timeout_seconds: float = 12.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if (
            int(
                db_scalar(
                    database,
                    "SELECT COUNT(*) FROM subscription_runs WHERE subscription_id = ?",
                    (subscription_id,),
                )
            )
            >= minimum
        ):
            return
        time.sleep(0.1)
    raise AssertionError(
        f"subscription {subscription_id} did not reach {minimum} recorded runs"
    )


def add_subscription(
    binary: Path,
    database: Path,
    *,
    name: str,
    url: str,
    source_type: str = "proxy-list",
    interval_seconds: int = 60,
    check_url: str,
) -> int:
    completed = run_checked(
        [
            str(binary),
            "--database",
            str(database),
            "subscription",
            "add",
            "--name",
            name,
            "--url",
            url,
            "--source-type",
            source_type,
            "--interval-seconds",
            str(interval_seconds),
            "--profile",
            "basic",
            "--protocol",
            "auto",
            "--interface",
            "lo",
            "--check-url",
            check_url,
            "--timeout",
            "5",
            "--concurrency",
            "4",
        ]
    )
    marker = "id="
    start = completed.stdout.index(marker) + len(marker)
    end = completed.stdout.index(" ", start)
    return int(completed.stdout[start:end])


def assert_redacted_management_output(
    binary: Path,
    database: Path,
    subscription_id: int,
    secret: str,
) -> None:
    listed = run_checked(
        [str(binary), "--database", str(database), "subscription", "list"]
    ).stdout
    shown = run_checked(
        [
            str(binary),
            "--database",
            str(database),
            "subscription",
            "show",
            "--id",
            str(subscription_id),
        ]
    ).stdout
    for output in (listed, shown):
        assert secret not in output, output
        assert "token=" not in output, output


def assert_sqlite_companion_permissions(database: Path) -> None:
    for path in (
        database,
        Path(str(database) + "-wal"),
        Path(str(database) + "-shm"),
    ):
        assert path.exists(), f"expected SQLite file while service is active: {path}"
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600, (path, oct(mode))


def assert_database_state(
    database: Path,
    direct_id: int,
    source_list_id: int,
) -> None:
    assert int(db_scalar(database, "PRAGMA user_version")) == 5
    assert int(db_scalar(database, "SELECT COUNT(*) FROM subscriptions")) == 2
    assert int(db_scalar(database, "SELECT COUNT(*) FROM runs")) >= 2
    assert (
        int(
            db_scalar(
                database,
                "SELECT COUNT(*) FROM runs WHERE subscription_id IN (?, ?)",
                (direct_id, source_list_id),
            )
        )
        >= 2
    )
    assert int(db_scalar(database, "SELECT COUNT(*) FROM proxy_checks WHERE valid = 1")) >= 2
    assert (
        db_scalar(
            database,
            "SELECT source_display FROM subscriptions WHERE id = ?",
            (direct_id,),
        )
        == f"http://{LOOPBACK_IP}:{SubscriptionFixtureHandler.http_port}/direct"
    )
    assert (
        db_scalar(database, "SELECT etag FROM subscriptions WHERE id = ?", (direct_id,))
        == ETAG
    )
    assert (
        db_scalar(
            database,
            "SELECT last_modified FROM subscriptions WHERE id = ?",
            (direct_id,),
        )
        == LAST_MODIFIED
    )
    assert int(
        db_scalar(
            database,
            "SELECT lease_until FROM subscriptions WHERE id = ?",
            (direct_id,),
        )
    ) == 0

    mode = os.stat(database).st_mode & 0o777
    assert mode == 0o600, oct(mode)


def run_smoke(binary: Path) -> None:
    if not binary.is_file():
        raise FileNotFoundError(f"binary not found: {binary}")

    socks5_server, _ = start_tcp_server(Socks5Handler)
    http_server: ThreadingHTTPServer | None = None

    try:
        socks5_port = int(socks5_server.server_address[1])
        http_server, _ = start_http_server(socks5_port)
        http_port = int(http_server.server_address[1])
        check_url = f"http://{LOOPBACK_IP}:{http_port}/ip"

        with tempfile.TemporaryDirectory(prefix="proxy-socks-subscription-") as temp_dir:
            database = Path(temp_dir) / "subscriptions.sqlite3"
            secret = "fixture-secret"
            direct_url = (
                f"http://{LOOPBACK_IP}:{http_port}/direct"
                f"?token={secret}"
            )
            source_list_url = f"http://{LOOPBACK_IP}:{http_port}/source-list"

            direct_id = add_subscription(
                binary,
                database,
                name="direct-fixture",
                url=direct_url,
                interval_seconds=1,
                check_url=check_url,
            )
            source_list_id = add_subscription(
                binary,
                database,
                name="source-list-fixture",
                url=source_list_url,
                source_type="source-list",
                interval_seconds=60,
                check_url=check_url,
            )

            assert_redacted_management_output(binary, database, direct_id, secret)

            run_checked(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "service",
                    "--once",
                    "--poll-seconds",
                    "1",
                    "--retention-days",
                    "30",
                ]
            )
            assert_database_state(database, direct_id, source_list_id)
            assert SubscriptionFixtureHandler.direct_requests >= 1
            assert SubscriptionFixtureHandler.source_list_requests >= 1

            run_checked(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "subscription",
                    "run",
                    "--id",
                    str(direct_id),
                ]
            )
            assert SubscriptionFixtureHandler.direct_conditional_requests >= 1
            assert (
                int(
                    db_scalar(
                        database,
                        "SELECT COUNT(*) FROM subscription_runs "
                        "WHERE subscription_id = ? AND http_status = 304 "
                        "AND not_modified = 1",
                        (direct_id,),
                    )
                )
                >= 1
            )

            run_checked(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "subscription",
                    "disable",
                    "--id",
                    str(source_list_id),
                ]
            )

            baseline = int(
                db_scalar(
                    database,
                    "SELECT COUNT(*) FROM subscription_runs WHERE subscription_id = ?",
                    (direct_id,),
                )
            )
            time.sleep(1.1)
            service = subprocess.Popen(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "service",
                    "--poll-seconds",
                    "1",
                    "--retention-days",
                    "30",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            try:
                wait_for_subscription_runs(database, direct_id, baseline + 1)
                assert_sqlite_companion_permissions(database)
                service.send_signal(signal.SIGTERM)
                stdout, _ = service.communicate(timeout=8)
            finally:
                if service.poll() is None:
                    service.kill()
                    service.wait(timeout=5)

            assert service.returncode == 0, stdout
            assert "service shutdown requested" in stdout, stdout

            run_checked(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "subscription",
                    "enable",
                    "--id",
                    str(source_list_id),
                ]
            )
            run_checked(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "subscription",
                    "remove",
                    "--id",
                    str(source_list_id),
                ]
            )
            assert int(db_scalar(database, "SELECT COUNT(*) FROM subscriptions")) == 1

            failure_secret = "failure-secret"
            failure_id = add_subscription(
                binary,
                database,
                name="failure-fixture",
                url=(
                    f"http://{LOOPBACK_IP}:{http_port}/failure"
                    f"?token={failure_secret}"
                ),
                interval_seconds=60,
                check_url=check_url,
            )
            failure = subprocess.run(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "subscription",
                    "run",
                    "--id",
                    str(failure_id),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            assert failure.returncode != 0, failure.stdout
            assert failure_secret not in failure.stdout, failure.stdout
            assert "token=" not in failure.stdout, failure.stdout
            assert (
                int(
                    db_scalar(
                        database,
                        "SELECT last_fetch_status FROM subscriptions WHERE id = ?",
                        (failure_id,),
                    )
                )
                == 503
            )
            stored_error = str(
                db_scalar(
                    database,
                    "SELECT last_error FROM subscriptions WHERE id = ?",
                    (failure_id,),
                )
            )
            assert "503" in stored_error, stored_error
            assert failure_secret not in stored_error, stored_error
            assert "token=" not in stored_error, stored_error
            assert (
                int(
                    db_scalar(
                        database,
                        "SELECT consecutive_failures FROM subscriptions WHERE id = ?",
                        (failure_id,),
                    )
                )
                == 1
            )
            assert (
                int(
                    db_scalar(
                        database,
                        "SELECT lease_until FROM subscriptions WHERE id = ?",
                        (failure_id,),
                    )
                )
                == 0
            )
            assert_redacted_management_output(
                binary,
                database,
                failure_id,
                failure_secret,
            )

            oversize_secret = "oversize-secret"
            oversize_id = add_subscription(
                binary,
                database,
                name="oversize-fixture",
                url=(
                    f"http://{LOOPBACK_IP}:{http_port}/oversize"
                    f"?token={oversize_secret}"
                ),
                interval_seconds=60,
                check_url=check_url,
            )
            oversize = subprocess.run(
                [
                    str(binary),
                    "--database",
                    str(database),
                    "subscription",
                    "run",
                    "--id",
                    str(oversize_id),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            assert oversize.returncode != 0, oversize.stdout
            assert "exceeds maximum size" in oversize.stdout, oversize.stdout
            assert oversize_secret not in oversize.stdout, oversize.stdout
            assert "token=" not in oversize.stdout, oversize.stdout
    finally:
        for server in (http_server, socks5_server):
            if server is not None:
                server.shutdown()
                server.server_close()


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
        "subscription smoke test passed: CRUD, redaction, proxy-list/source-list, "
        "ETag/304 cache, recurring service, safe HTTP failures, streaming source cap, "
        "SQLite/WAL/SHM permissions, SIGTERM"
    )


if __name__ == "__main__":
    main()
