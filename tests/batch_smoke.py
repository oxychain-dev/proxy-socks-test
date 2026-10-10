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
from urllib.parse import parse_qs, urlsplit


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
        parsed = urlsplit(self.path)
        if parsed.path == "/download":
            requested = int(parse_qs(parsed.query).get("bytes", ["0"])[0])
            payload = b"x" * min(requested, 1024 * 1024)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if parsed.path.startswith("/ip-info/"):
            ip_value = parsed.path.removeprefix("/ip-info/")
            payload = (
                '{"ip":"'
                + ip_value
                + '","country":"LOOP","city":"Local","org":"FixtureNet","asn":"AS0"}'
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        routes = {
            "/ip": f"{LOOPBACK_IP}\n",
            "/socks4.txt": f"socks4://{LOOPBACK_IP}:{self.socks4_port}\n",
            "/socks4a.txt": f"socks4a://{LOOPBACK_IP}:{self.socks4_port}\n",
            "/socks5.txt": f"{LOOPBACK_IP}:{self.socks5_port}\n",
            "/sources.txt": f"http://{LOOPBACK_IP}:{self.http_port}/socks5.txt\n",
        }
        body = routes.get(parsed.path)
        if body is None:
            self.send_error(404)
            return

        encoded = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if urlsplit(self.path).path != "/upload":
            self.send_error(404)
            return
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        response = str(len(body)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

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
    interface: str = "default",
    full_profile: bool = False,
    enriched: bool = False,
) -> None:
    expected_columns = [
        "source",
        "input",
        "interface",
        "local_ips",
        "tester_ip",
        "proxy_host",
        "resolved_ips",
        "tested_ip",
        "reverse_dns",
        "proxy_port",
        "valid",
        "protocol",
        "tcp_connect_ms",
        "validation_latency_ms",
        "latency_p50_ms",
        "latency_p95_ms",
        "jitter_ms",
        "download_mbps",
        "upload_mbps",
        "exit_ip",
        "exit_ip_changed",
        "endpoint_country",
        "endpoint_asn",
        "endpoint_org",
        "exit_country",
        "exit_asn",
        "exit_org",
        "stages",
        "error",
    ]
    assert list(row.keys()) == expected_columns, row
    assert row["interface"] == interface, row
    if interface == "default":
        assert row["local_ips"] == "", row
    else:
        local_ips = [ipaddress.ip_address(value) for value in row["local_ips"].split(",")]
        assert local_ips, row
        assert all(ip.is_loopback for ip in local_ips), row
    assert row["protocol"] == protocol, row
    assert row["proxy_host"] == LOOPBACK_IP, row
    assert LOOPBACK_IP in row["resolved_ips"].split(","), row
    assert row["tested_ip"] == LOOPBACK_IP, row
    assert row["proxy_port"] == str(proxy_port), row
    assert row["valid"] == "true", row
    assert row["tcp_connect_ms"].isdigit(), row
    assert row["validation_latency_ms"].isdigit(), row
    assert float(row["latency_p50_ms"]) >= 0, row
    assert float(row["latency_p95_ms"]) >= 0, row
    assert float(row["jitter_ms"]) >= 0, row
    assert row["exit_ip_changed"] == "false", row
    assert row["error"] == "", row
    assert "3:proxy_http_validation=pass" in row["stages"], row
    assert ipaddress.ip_address(row["tester_ip"]).is_loopback, row
    assert ipaddress.ip_address(row["exit_ip"]).is_loopback, row
    if full_profile:
        assert float(row["download_mbps"]) > 0, row
        assert float(row["upload_mbps"]) > 0, row
        assert "5:download_throughput=pass" in row["stages"], row
        assert "6:upload_throughput=pass" in row["stages"], row
    else:
        assert row["download_mbps"] == "", row
        assert row["upload_mbps"] == "", row
    if enriched:
        assert row["endpoint_country"] == "LOOP", row
        assert row["endpoint_asn"] == "AS0", row
        assert row["endpoint_org"] == "FixtureNet", row
        assert row["exit_country"] == "LOOP", row
        assert row["exit_asn"] == "AS0", row
        assert row["exit_org"] == "FixtureNet", row


def assert_single_row(
    path: Path,
    *,
    protocol: str,
    proxy_port: int,
    interface: str = "default",
    full_profile: bool = False,
    enriched: bool = False,
) -> None:
    rows = read_tsv(path)
    assert len(rows) == 1, rows
    assert_row(
        rows[0],
        protocol=protocol,
        proxy_port=proxy_port,
        interface=interface,
        full_profile=full_profile,
        enriched=enriched,
    )


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
        "--database",
        ":memory:",
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
                + ["--proxy-file", str(local_proxy_file), "--interface", "lo"]
            )
            assert_single_row(
                socks4_tsv,
                protocol="socks4",
                proxy_port=socks4_port,
                interface="lo",
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
                    "--profile",
                    "full",
                    "--latency-samples",
                    "3",
                    "--download-url",
                    f"http://{LOOPBACK_IP}:{http_port}/download?bytes={{bytes}}",
                    "--upload-url",
                    f"http://{LOOPBACK_IP}:{http_port}/upload",
                    "--download-bytes",
                    "4096",
                    "--upload-bytes",
                    "2048",
                    "--ip-info-url-template",
                    f"http://{LOOPBACK_IP}:{http_port}/ip-info/{{ip}}",
                ]
            )
            assert_single_row(
                socks5_tsv,
                protocol="socks5",
                proxy_port=socks5_port,
                full_profile=True,
                enriched=True,
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
