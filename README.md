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
