## Overview

`proxy-socks-test` is a Rust-based SOCKS proxy testing tool designed to validate the functionality of SOCKS4, SOCKS4a, and SOCKS5 proxies.

## Features

+   **SOCKS4/SOCKS4a/SOCKS5 Proxy Testing**: Supports testing of SOCKS4, SOCKS4a, and SOCKS5 proxies.
    
## Usage

### Command-Line Arguments

+   `--proxyip <ipaddress>`: Set the proxy IP address.
    
+   `--proxyport <port>`: Set the proxy port.
    
+   `--serverip <ipaddress>`: Set the server IP address for testing.
    
+   `--serverport <port>`: Set the server port for testing (default: 3307).
    
+   `--auth <auth>`: Set the SOCKS username and password, separated by a colon.
    
+   `--casename <test case name>`: Specify the test case to run. Possible values include:
    
    +   `socks4_connect`
        
    +   `socks5_connect`
        
    +   `socks5_connect_hostname`
        
    +   `socks4a_connect_hostname`
        
    +   `socks4a_connect`
        
    +   `socks4_bind`
        
    +   `socks5_bind`
        
    +   `socks5_udp`
        
    +   `socks5_auth_connect`
        
    +   `socks5_auth_bind`
        
    +   `socks5_auth_udp`
        
+   `--debug`: Enable debug logging.
    

### Example

```sh
proxy-socks-test --proxyip 127.0.0.1 --proxyport 1080 --serverip 127.0.0.1 --serverport 3307 --casename socks5_connect --debug
```

## Batch Proxy-List Validation

The same executable can also collect, deduplicate, validate, and export SOCKS proxy lists.

Inputs can be combined in one run:

- `--proxy-file <path-or-url>`: a local file (or HTTP(S) URL) containing proxy entries.
- `--source-list <path-or-url>`: a local file (or HTTP(S) URL) whose non-comment lines are URLs of proxy lists.
- `--source-url <url>`: a direct proxy-list URL. Repeat the option to add more URLs.

Supported proxy entry forms include:

- `1.2.3.4:1080`
- `1.2.3.4:1080:user:pass`
- `socks5://user:pass@host:1080`
- `socks4://host:1080`
- `socks4a://host:1080`

For entries without a scheme, `--protocol auto` (the default) tries SOCKS5, then SOCKS4a, then SOCKS4. Authenticated scheme-less entries are tested as SOCKS5.

### Batch Example

```sh
proxy-socks-test \
  --proxy-file proxies.txt \
  --source-list proxy-sources.txt \
  --source-url https://example.com/socks.txt \
  --protocol auto \
  --concurrency 200 \
  --timeout 8 \
  --output proxy-results.tsv \
  --valid-output valid-proxies.txt
```

The default check endpoint is `https://api.ipify.org`; replace it with `--check-url <url>` when needed. The endpoint must return the caller IP in its response.

### TSV Output

The TSV contains:

`source, input, tester_ip, protocol, proxy_host, tested_ip, proxy_port, valid, latency_ms, exit_ip, error`

- `tester_ip` is the tester machine's public IP measured without a proxy.
- `tested_ip` is the resolved proxy endpoint IP that was actually tested.
- `exit_ip` is the public IP observed through the connected proxy.
- `latency_ms` is the end-to-end time for the validation request.
- `valid-output`, when supplied, receives only successful proxies in normalized SOCKS URL form.

### Controlled Batch Smoke Test

A self-contained local fixture verifies SOCKS4, SOCKS4a, SOCKS5, local proxy-file ingestion, direct proxy-list URLs, source-list URLs, TSV fields, and normalized valid-proxy output:

```sh
cargo build
python3 tests/batch_smoke.py target/debug/proxy-socks-test
```

The fixture uses only the Python standard library and local loopback services.

## Test Cases

### TCP Connect

+   **socks4_connect**: Tests SOCKS4 TCP connect.
    
+   **socks4a_connect**: Tests SOCKS4a TCP connect.
    
+   **socks5_connect**: Tests SOCKS5 TCP connect.
    
+   **socks5_auth_connect**: Tests authenticated SOCKS5 TCP connect.
    

### TCP Bind

+   **socks4_bind**: Tests SOCKS4 TCP bind.
    
+   **socks5_bind**: Tests SOCKS5 TCP bind.
    

### UDP

+   **socks5_udp**: Tests SOCKS5 UDP.
    

### Hostname Resolution

+   **socks4a_connect_hostname**: Tests SOCKS4a hostname resolution.
    
+   **socks5_connect_hostname**: Tests SOCKS5 hostname resolution.
    

## Dependencies

+   **libsocks_client**: SOCKS client library.
    
+   **tokio**: Asynchronous runtime.
    
+   **clap**: Command-line argument parsing.
    
+   **anyhow**: Error handling.
    
+   **colored**: Colored terminal output.
    

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/oxychain-dev/proxy-socks-test/blob/main/LICENSE) file for details.

## Repository

The source code is available on [GitHub](https://github.com/oxychain-dev/proxy-socks-test).

* * *
