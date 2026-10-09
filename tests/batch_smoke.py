#!/usr/bin/env python3
"""Controlled end-to-end smoke test for batch SOCKS proxy validation.

Uses only the Python standard library. The test starts local SOCKS4/SOCKS4a
and SOCKS5 forwarding proxies plus a local HTTP server used both as the
IP-check endpoint and as a proxy-list source.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import select
import socket
import socketserver
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


LOOPBACK_IP = "127.0.0.1"


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("unexpected EOF")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_until_nul(sock: socket.socket, limit: int = 4096) -> bytes:
    data = bytearray()
    while len(data) < limit:
        byte = recv_exact(sock, 1)
        if byte == b"\x00":
            return bytes(data)
        data.extend(byte)
    raise ValueError("NUL-terminated field exceeded limit")


def relay(client: socket.socket, upstream: socket.socket) -> None:
    sockets = (client, upstream)
    for sock in sockets:
        sock.settimeout(30)

    while True:
        readable, _, _ = select.select(sockets, (), (), 30)
        if not readable:
            return
        for source in readable:
            data = source.recv(65536)
            if not data:
                return
            target = upstream if source is client else client
            target.sendall(data)


class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Socks4Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        upstream: socket.socket | None = None
        try:
            header = recv_exact(client, 8)
            version, command = header[0], header[1]
            if version != 4 or command != 1:
                raise ValueError("unsupported SOCKS4 request")

            port = int.from_bytes(header[2:4], "big")
            address = header[4:8]
            recv_until_nul(client)  # USERID

            if address[:3] == b"\x00\x00\x00" and address[3] != 0:
                host = recv_until_nul(client).decode("idna")
            else:
                host = socket.inet_ntoa(address)

            upstream = socket.create_connection((host, port), timeout=10)
            client.sendall(b"\x00\x5a" + header[2:8])
            relay(client, upstream)
        except Exception:
            try:
                client.sendall(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
        finally:
            if upstream is not None:
                upstream.close()


class Socks5Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        upstream: socket.socket | None = None
        try:
            version, methods_count = recv_exact(client, 2)
            if version != 5:
                raise ValueError("unsupported SOCKS version")

            methods = recv_exact(client, methods_count)
            if 0 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x00")

            version, command, _reserved, address_type = recv_exact(client, 4)
            if version != 5 or command != 1:
                raise ValueError("unsupported SOCKS5 request")

            if address_type == 1:
                host = socket.inet_ntoa(recv_exact(client, 4))
            elif address_type == 3:
                length = recv_exact(client, 1)[0]
                host = recv_exact(client, length).decode("idna")
            elif address_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
            else:
                raise ValueError("unsupported SOCKS5 address type")

            port = int.from_bytes(recv_exact(client, 2), "big")
            upstream = socket.create_connection((host, port), timeout=10)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            relay(client, upstream)
        except Exception:
            try:
                client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
        finally:
            if upstream is not None:
                upstream.close()


class FixtureHttpHandler(BaseHTTPRequestHandler):
    socks4_port = 0
    socks5_port = 0
    http_port = 0

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        routes = {
            "/ip": f"{LOOPBACK_IP}\n",
            "/socks4.txt": f"socks4://{LOOPBACK_IP}:{self.socks4_port}\n",
            "/socks4a.txt": f"socks4a://{LOOPBACK_IP}:{self.socks4_port}\n",
            "/socks5.txt": f"{LOOPBACK_IP}:{self.socks5_port}\n",
            "/sources.txt": f"http://{LOOPBACK_IP}:{self.http_port}/socks5.txt\n",
        }
        body = routes.get(self.path)
        if body is None:
            self.send_error(404)
            return

        encoded = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format: str, *args: object) -> None:
        del args


def start_tcp_server(
    handler: type[socketserver.BaseRequestHandler],
) -> tuple[ReusableThreadingTCPServer, threading.Thread]:
    server = ReusableThreadingTCPServer((LOOPBACK_IP, 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def start_http_server(
    socks4_port: int, socks5_port: int
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer((LOOPBACK_IP, 0), FixtureHttpHandler)
    http_port = int(server.server_address[1])
    FixtureHttpHandler.socks4_port = socks4_port
    FixtureHttpHandler.socks5_port = socks5_port
    FixtureHttpHandler.http_port = http_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def run_checked(command: list[str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout}"
        )
    return completed


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def assert_row(
    row: dict[str, str],
    *,
    protocol: str,
    proxy_port: int,
) -> None:
    expected_columns = [
        "source",
        "input",
        "tester_ip",
        "protocol",
        "proxy_host",
        "tested_ip",
        "proxy_port",
        "valid",
        "latency_ms",
        "exit_ip",
        "error",
    ]
    assert list(row.keys()) == expected_columns, row
    assert row["protocol"] == protocol, row
    assert row["proxy_host"] == LOOPBACK_IP, row
    assert row["tested_ip"] == LOOPBACK_IP, row
    assert row["proxy_port"] == str(proxy_port), row
    assert row["valid"] == "true", row
    assert row["latency_ms"].isdigit(), row
    assert row["error"] == "", row
    assert ipaddress.ip_address(row["tester_ip"]).is_loopback, row
    assert ipaddress.ip_address(row["exit_ip"]).is_loopback, row


def assert_single_row(path: Path, *, protocol: str, proxy_port: int) -> None:
    rows = read_tsv(path)
    assert len(rows) == 1, rows
    assert_row(rows[0], protocol=protocol, proxy_port=proxy_port)


def build_common_args(binary: Path, check_url: str, output: Path) -> list[str]:
    return [
        str(binary),
        "--check-url",
        check_url,
        "--timeout",
        "10",
        "--concurrency",
        "4",
        "--output",
        str(output),
    ]


def run_smoke(binary: Path) -> None:
    if not binary.is_file():
        raise FileNotFoundError(f"binary not found: {binary}")

    socks4_server, _ = start_tcp_server(Socks4Handler)
    socks5_server, _ = start_tcp_server(Socks5Handler)
    http_server: ThreadingHTTPServer | None = None

    try:
        socks4_port = int(socks4_server.server_address[1])
        socks5_port = int(socks5_server.server_address[1])
        http_server, _ = start_http_server(socks4_port, socks5_port)
        http_port = int(http_server.server_address[1])

        ip_check_v4 = f"http://{LOOPBACK_IP}:{http_port}/ip"
        ip_check_hostname = f"http://localhost:{http_port}/ip"

        with tempfile.TemporaryDirectory(prefix="proxy-socks-test-") as temp_dir:
            temp = Path(temp_dir)

            local_proxy_file = temp / "socks4.txt"
            local_proxy_file.write_text(
                f"socks4://{LOOPBACK_IP}:{socks4_port}\n",
                encoding="utf-8",
            )
            socks4_tsv = temp / "socks4.tsv"
            run_checked(
                build_common_args(binary, ip_check_v4, socks4_tsv)
                + ["--proxy-file", str(local_proxy_file)]
            )
            assert_single_row(
                socks4_tsv,
                protocol="socks4",
                proxy_port=socks4_port,
            )

            socks4a_tsv = temp / "socks4a.tsv"
            run_checked(
                build_common_args(binary, ip_check_hostname, socks4a_tsv)
                + [
                    "--source-url",
                    f"http://{LOOPBACK_IP}:{http_port}/socks4a.txt",
                ]
            )
            assert_single_row(
                socks4a_tsv,
                protocol="socks4a",
                proxy_port=socks4_port,
            )

            socks5_tsv = temp / "socks5.tsv"
            valid_output = temp / "valid.txt"
            run_checked(
                build_common_args(binary, ip_check_v4, socks5_tsv)
                + [
                    "--source-list",
                    f"http://{LOOPBACK_IP}:{http_port}/sources.txt",
                    "--valid-output",
                    str(valid_output),
                ]
            )
            assert_single_row(
                socks5_tsv,
                protocol="socks5",
                proxy_port=socks5_port,
            )
            valid = {
                line.strip()
                for line in valid_output.read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
            assert valid == {f"socks5://{LOOPBACK_IP}:{socks5_port}"}, valid
    finally:
        for server in (http_server, socks4_server, socks5_server):
            if server is not None:
                server.shutdown()
                server.server_close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "binary",
        nargs="?",
        default="target/debug/proxy-socks-test",
        help="path to the built proxy-socks-test binary",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_smoke(Path(args.binary).resolve())
    print("batch smoke test passed: SOCKS4, SOCKS4a, SOCKS5")


if __name__ == "__main__":
    main()
