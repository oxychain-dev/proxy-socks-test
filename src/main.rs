//! # `proxy-socks-test` Crate Documentation
//!
//! `proxy-socks-test` is a Rust-based SOCKS proxy testing tool designed to validate the functionality of SOCKS4, SOCKS4a, and SOCKS5 proxies.
//!
//! ## Features
//!
//! - **SOCKS4/SOCKS4a/SOCKS5 Proxy Testing**: Supports testing of SOCKS4, SOCKS4a, and SOCKS5 proxies.
//!
//! ## Usage
//!
//! ### Command-Line Arguments
//!
//! - `--proxyip <ipaddress>`: Set the proxy IP address.
//! - `--proxyport <port>`: Set the proxy port.
//! - `--serverip <ipaddress>`: Set the server IP address for testing.
//! - `--serverport <port>`: Set the server port for testing (default: 3307).
//! - `--auth <auth>`: Set the SOCKS username and password, separated by a colon.
//! - `--casename <test case name>`: Specify the test case to run. Possible values include:
//!   - `socks4_connect`
//!   - `socks5_connect`
//!   - `socks5_connect_hostname`
//!   - `socks4a_connect_hostname`
//!   - `socks4a_connect`
//!   - `socks4_bind`
//!   - `socks5_bind`
//!   - `socks5_udp`
//!   - `socks5_auth_connect`
//!   - `socks5_auth_bind`
//!   - `socks5_auth_udp`
//! - `--debug`: Enable debug logging.
//!
//! ### Example
//!
//! ```sh
//! proxy-socks-test --proxyip 127.0.0.1 --proxyport 1080 --serverip 127.0.0.1 --serverport 3307 --casename socks5_connect --debug
//! ```
//!
//! ## Test Cases
//!
//! ### TCP Connect
//!
//! - **socks4_connect**: Tests SOCKS4 TCP connect.
//! - **socks4a_connect**: Tests SOCKS4a TCP connect.
//! - **socks5_connect**: Tests SOCKS5 TCP connect.
//! - **socks5_auth_connect**: Tests authenticated SOCKS5 TCP connect.
//!
//! ### TCP Bind
//!
//! - **socks4_bind**: Tests SOCKS4 TCP bind.
//! - **socks5_bind**: Tests SOCKS5 TCP bind.
//!
//! ### UDP
//!
//! - **socks5_udp**: Tests SOCKS5 UDP.
//!
//! ### Hostname Resolution
//!
//! - **socks4a_connect_hostname**: Tests SOCKS4a hostname resolution.
//! - **socks5_connect_hostname**: Tests SOCKS5 hostname resolution.
//!
//! ## Dependencies
//!
//! - **libsocks_client**: SOCKS client library.
//! - **tokio**: Asynchronous runtime.
//! - **clap**: Command-line argument parsing.
//! - **anyhow**: Error handling.
//! - **colored**: Colored terminal output.
//!
//! ## License
//!
//! This project is licensed under the MIT License. See the [LICENSE](https://github.com/oxychain-dev/proxy-socks-test/blob/main/LICENSE) file for details.
//!
//! ## Repository
//!
//! The source code is available on [GitHub](https://github.com/oxychain-dev/proxy-socks-test).
//!
mod batch;

use anyhow::{anyhow, Result};
use colored::Colorize;
use libsocks_client::SocksClientBuilder;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::{net::SocketAddr, process::exit, sync::OnceLock};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::{timeout, Duration},
};

macro_rules! debuginfo {
    ($($arg:tt)*) => {
        if DEBUG_OPEN.load(std::sync::atomic::Ordering::SeqCst) {
            println!($($arg)*);
        }
    };
}

static TCP_READ_TIMEOUT: u64 = 10;
static USRPASS: OnceLock<String> = OnceLock::new();
static DATASIZE: OnceLock<String> = OnceLock::new();

fn init_auth(authstr: &str) {
    USRPASS.get_or_init(|| String::from(authstr));
}

fn get_auth() -> &'static str {
    USRPASS.get_or_init(|| String::from(""))
}

static DEBUG_OPEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[derive(Debug)]
struct Event {
    target_addr: SocketAddr,
    data: Vec<u8>,
}

fn set_test_case_pass(name: &str) {
    let okpass = format!("{} OK PASS", name);
    println!("{}", okpass.green());
}

fn set_test_case_failed(name: &str, reason: &str) {
    let failed = format!("{} ERR:{}", name, reason);
    println!("{}", failed.red());
}

fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

async fn socks4_connect_test(
    _tx: &tokio::sync::mpsc::Sender<Event>, serverip: &str, serverport: u16, proxyip: &str,
    proxyport: u16,
) -> Result<()> {
    let data = "socks4_connect_test\n".to_owned() + DATASIZE.get().unwrap();
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks4().build_tcp_client();
    let mut stream = client.connect(serverip, serverport).await?;
    debuginfo!("socks4_connect_test connect to {}:{} success!", serverip, serverport);
    stream.write_all(data.as_bytes()).await?;
    stream.shutdown().await?;
    debuginfo!(
        "socks4_connect_test write data len:{} to {}:{} success!",
        data.len(),
        serverip,
        serverport
    );
    let mut buf = vec![0; 128 + DATASIZE.get().unwrap().len()];
    let mut response_buffer = vec![];
    loop {
        let n = tokio::time::timeout(
            tokio::time::Duration::from_secs(TCP_READ_TIMEOUT),
            stream.read(&mut buf[..]),
        )
        .await??;
        if n == 0 {
            break;
        }
        response_buffer.extend(&buf[..n]);
    }
    debuginfo!(
        "socks4_connect_test read data len {} from {}:{} success!",
        response_buffer.len(),
        serverip,
        serverport
    );
    if response_buffer.eq(data.as_bytes()) {
        Ok(())
    } else {
        println!("Expected: {}", data);
        println!("Received: {}", String::from_utf8_lossy(&response_buffer));
        Err(anyhow!("socks4_connect_test data not equal"))
    }
}

async fn socks4a_connect_test(
    _tx: &tokio::sync::mpsc::Sender<Event>, serverip: &str, serverport: u16, proxyip: &str,
    proxyport: u16,
) -> Result<()> {
    let data = "socks4a_connect_test\n".to_owned() + DATASIZE.get().unwrap();
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks4a().build_tcp_client();
    let mut stream = client.connect(serverip, serverport).await?;
    debuginfo!("socks4a_connect_test connect to {}:{} success!", serverip, serverport);
    stream.write_all(data.as_bytes()).await?;
    stream.shutdown().await?;
    debuginfo!(
        "socks4a_connect_test write data len:{} to {}:{} success!",
        data.len(),
        serverip,
        serverport
    );
    let mut buf = vec![0; 128 + DATASIZE.get().unwrap().len()];
    let mut response_buffer = vec![];
    loop {
        let n = tokio::time::timeout(
            tokio::time::Duration::from_secs(TCP_READ_TIMEOUT),
            stream.read(&mut buf[..]),
        )
        .await??;
        if n == 0 {
            break;
        }
        response_buffer.extend(&buf[..n]);
    }
    debuginfo!(
        "socks4a_connect_test read data len {} from {}:{} success!",
        response_buffer.len(),
        serverip,
        serverport
    );
    if response_buffer.eq(data.as_bytes()) {
        Ok(())
    } else {
        println!("Expected: {}", data);
        println!("Received: {}", String::from_utf8_lossy(&response_buffer));
        Err(anyhow!("socks4a_connect_test data not equal"))
    }
}

async fn socks5_connect_test(
    _tx: &tokio::sync::mpsc::Sender<Event>, serverip: &str, serverport: u16, proxyip: &str,
    proxyport: u16,
) -> Result<()> {
    let data = "socks5_connect_test\n".to_owned() + DATASIZE.get().unwrap();
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks5().build_tcp_client();
    let mut stream = client.connect(serverip, serverport).await?;
    debuginfo!("socks5_connect_test connect to {}:{} success!", serverip, serverport);
    stream.write_all(data.as_bytes()).await?;
    stream.shutdown().await?;
    debuginfo!(
        "socks5_connect_test write data len:{} to {}:{} success!",
        data.len(),
        serverip,
        serverport
    );
    let mut buf = vec![0; 128 + DATASIZE.get().unwrap().len()];
    let mut response_buffer: Vec<u8> = vec![];
    loop {
        let n = tokio::time::timeout(
            tokio::time::Duration::from_secs(TCP_READ_TIMEOUT),
            stream.read(&mut buf[..]),
        )
        .await??;
        if n == 0 {
            break;
        }
        response_buffer.extend(&buf[..n]);
    }
    debuginfo!(
        "socks5_connect_test read data len {} from {}:{} success!",
        response_buffer.len(),
        serverip,
        serverport
    );
    if response_buffer.eq(data.as_bytes()) {
        Ok(())
    } else {
        println!("Expected: {}", data);
        println!("Received: {}", String::from_utf8_lossy(&buf));
        Err(anyhow!("socks5_connect_test data not equal"))
    }
}

async fn socks5_auth_connect_test(
    _tx: &tokio::sync::mpsc::Sender<Event>, serverip: &str, serverport: u16, proxyip: &str,
    proxyport: u16,
) -> Result<()> {
    let data = "socks5_auth_connect_test\n".to_owned() + DATASIZE.get().unwrap();
    let auth = get_auth();
    let mut authinfo = auth.split(':');
    let username = authinfo.next().unwrap_or_default();
    let password = authinfo.next().unwrap_or_default();
    let mut client = SocksClientBuilder::new(proxyip, proxyport)
        .socks5()
        .username(username)
        .password(password)
        .build_tcp_client();
    let mut stream = client.connect(serverip, serverport).await?;
    debuginfo!("socks5_auth_connect_test connect to {}:{} success!", serverip, serverport);
    stream.write_all(data.as_bytes()).await?;
    stream.shutdown().await?;
    debuginfo!(
        "socks5_auth_connect_test write data len:{} to {}:{} success!",
        data.len(),
        serverip,
        serverport
    );
    let mut buf = vec![0; 128 + DATASIZE.get().unwrap().len()];
    let mut response_buffer: Vec<u8> = vec![];
    loop {
        let n = tokio::time::timeout(
            tokio::time::Duration::from_secs(TCP_READ_TIMEOUT),
            stream.read(&mut buf[..]),
        )
        .await??;
        if n == 0 {
            break;
        }
        response_buffer.extend(&buf[..n]);
    }
    debuginfo!(
        "socks5_auth_connect_test read data len {} from {}:{} success!",
        response_buffer.len(),
        serverip,
        serverport
    );
    if response_buffer.eq(data.as_bytes()) {
        Ok(())
    } else {
        println!("Expected: {}", data);
        println!("Received: {}", String::from_utf8_lossy(&buf));
        Err(anyhow!("socks5_auth_connect_test data not equal"))
    }
}

async fn socks4a_connect_hostname_test(
    _tx: &tokio::sync::mpsc::Sender<Event>, _serverip: &str, _serverport: u16, proxyip: &str,
    proxyport: u16,
) -> Result<()> {
    const HTTP_REQUEST: &str = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks4a().build_tcp_client();
    let mut stream = client.connect_hostname("www.baidu.com", 80).await?;
    debuginfo!("socks4a_connect_hostname_test connect to {}:{} success!", "www.baidu.com", 80);
    stream.write_all(HTTP_REQUEST.as_bytes()).await?;
    stream.shutdown().await?;
    debuginfo!(
        "socks4a_connect_hostname_test write data len:{} to {}:{} success!",
        HTTP_REQUEST.len(),
        "www.baidu.com",
        80
    );
    let mut buf = vec![0; 128 + DATASIZE.get().unwrap().len()];
    let mut response_buffer = vec![];
    loop {
        let n = tokio::time::timeout(
            tokio::time::Duration::from_secs(TCP_READ_TIMEOUT),
            stream.read(&mut buf[..]),
        )
        .await??;
        if n == 0 {
            break;
        }
        response_buffer.extend(&buf[..n]);
    }
    debuginfo!(
        "socks4a_connect_hostname_test read data len {} from {}:{} success!",
        response_buffer.len(),
        "www.baidu.com",
        80
    );
    if response_buffer.starts_with("HTTP/1.".as_bytes()) {
        Ok(())
    } else {
        Err(anyhow!("socks4a_connect_hostname_test data not equal"))
    }
}

async fn socks5_connect_hostname_test(
    _tx: &tokio::sync::mpsc::Sender<Event>, _serverip: &str, _serverport: u16, proxyip: &str,
    proxyport: u16,
) -> Result<()> {
    const HTTP_REQUEST: &str = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks5().build_tcp_client();
    let mut stream = client.connect_hostname("www.baidu.com", 80).await?;
    debuginfo!("socks5_connect_hostname_test connect to {}:{} success!", "www.baidu.com", 80);
    stream.write_all(HTTP_REQUEST.as_bytes()).await?;
    stream.shutdown().await?;
    debuginfo!(
        "socks5_connect_hostname_test write data len:{} to {}:{} success!",
        HTTP_REQUEST.len(),
        "www.baidu.com",
        80
    );
    let mut buf = vec![0; 1024];
    let mut response_buffer = vec![];
    loop {
        let n = tokio::time::timeout(
            tokio::time::Duration::from_secs(TCP_READ_TIMEOUT),
            stream.read(&mut buf[..]),
        )
        .await??;
        if n == 0 {
            break;
        }
        response_buffer.extend(&buf[..n]);
    }
    debuginfo!(
        "socks5_connect_hostname_test read data len {} from {}:{} success!",
        response_buffer.len(),
        "www.baidu.com",
        80
    );
    if response_buffer.starts_with("HTTP/1.".as_bytes()) {
        Ok(())
    } else {
        Err(anyhow!("socks5_connect_hostname_test data not equal"))
    }
}

async fn socks4_bind_test(
    tx: &tokio::sync::mpsc::Sender<Event>, _serverip: &str, _serverport: u16, proxyip: &str,
    proxyport: u16,
) -> Result<()> {
    let data = "socks4_bind_test\n".to_owned() + DATASIZE.get().unwrap();
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks4().build_listen_client();
    client.bind("0.0.0.0", 0).await?;
    debuginfo!("socks4_bind_test bind success!");
    let addr = client.get_proxy_bind_addr().ok_or(anyhow!("get bind addr failed"))?;
    let event = Event { target_addr: addr, data: data.as_bytes().to_vec() };
    tx.send(event).await?;
    debuginfo!("socks4_bind_test bind notify {} success!", addr.to_string());
    let mut stream = client.accept().await?;
    debuginfo!("socks4_bind_test accept success!");

    let mut buf = vec![0; 128 + DATASIZE.get().unwrap().len()];

    let len = tokio::time::timeout(
        tokio::time::Duration::from_secs(TCP_READ_TIMEOUT),
        stream.read(&mut buf[..]),
    )
    .await??;

    debuginfo!("socks4_bind_test read len {} success!", len);
    if buf[..len].eq(data.as_bytes()) {
        Ok(())
    } else {
        println!("Expected: {}", data);
        println!("Received: {}", String::from_utf8_lossy(&buf));
        Err(anyhow!("socks4_bind_test data not equal"))
    }
}

async fn socks5_bind_test(
    tx: &tokio::sync::mpsc::Sender<Event>, serverip: &str, serverport: u16, proxyip: &str,
    proxyport: u16,
) -> Result<()> {
    let data = "socks5_bind_test\n".to_owned() + DATASIZE.get().unwrap();
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks5().build_listen_client();
    client.bind(serverip, serverport).await?;
    debuginfo!("socks5_bind_test bind success!");
    let addr = client.get_proxy_bind_addr().ok_or(anyhow!("get bind addr failed"))?;
    let event = Event { target_addr: addr, data: data.as_bytes().to_vec() };
    tx.send(event).await?;
    debuginfo!("socks5_bind_test bind notify {} success!", addr.to_string());
    let mut stream = client.accept().await?;
    debuginfo!("socks5_bind_test accept success!");
    let mut buf = vec![0; 128 + DATASIZE.get().unwrap().len()];
    let len = tokio::time::timeout(
        tokio::time::Duration::from_secs(TCP_READ_TIMEOUT),
        stream.read(&mut buf[..]),
    )
    .await??;
    debuginfo!("socks5_bind_test read len {} success!", len);
    if buf[..len].eq(data.as_bytes()) {
        Ok(())
    } else {
        println!("Expected: {}", data);
        println!("Received: {}", String::from_utf8_lossy(&buf));
        Err(anyhow!("socks5_bind_test data not equal"))
    }
}

async fn socks5_udp_test(
    _tx: &tokio::sync::mpsc::Sender<Event>, serverip: &str, serverport: u16, proxyip: &str,
    proxyport: u16,
) -> Result<()> {
    let udp_data = "UDP Data".to_owned() + DATASIZE.get().unwrap();
    let mut client = SocksClientBuilder::new(proxyip, proxyport).socks5().build_udp_client();
    client.udp_associate("0.0.0.0", 0).await?;
    debuginfo!("socks5_udp_test udp_associate success!");
    let mut udp = client.get_udp_socket("0.0.0.0:0").await?;
    debuginfo!("socks5_udp_test get_udp_socket {:?} success!", udp.get_proxy_udp_addr());

    udp.send_udp_data(udp_data.as_bytes(), &format!("{}:{}", serverip, serverport)).await?;
    debuginfo!("socks5_udp_test send_udp_data len {} success!", udp_data.len());

    let mut data = vec![];
    loop {
        let datatmp = udp.recv_udp_data(5).await?;
        debuginfo!("socks5_udp_test recv_udp_data len {} success!", datatmp.1.len());
        data.extend(datatmp.1);
        if data.len() >= udp_data.len() {
            break;
        }
    }

    if data.eq(udp_data.as_bytes()) {
        Ok(())
    } else {
        println!("Expected: {}", udp_data);
        println!("Received: {}", String::from_utf8_lossy(&data));
        Err(anyhow!("socks5_udp_test data not equal"))
    }
}

async fn run_socks_case<'a, F, S>(
    name: &str, tx: &'a tokio::sync::mpsc::Sender<Event>, serverip: &'static str, serverport: u16,
    proxyip: &'static str, proxyport: u16, run_case: F,
) -> Result<()>
where
    F: Fn(&'a tokio::sync::mpsc::Sender<Event>, &'static str, u16, &'static str, u16) -> S,
    F: Copy + Send + Sync + 'static,
    S: std::future::Future<Output = Result<()>> + Send + 'a,
{
    let r = run_case(tx, serverip, serverport, proxyip, proxyport).await;
    if r.is_ok() {
        set_test_case_pass(name);
    } else {
        set_test_case_failed(name, &r.err().unwrap().to_string());
    }
    Ok(())
}

async fn run_test_cace_client(
    tx: &tokio::sync::mpsc::Sender<Event>, case_name: &'static str, serverip: &'static str,
    serverport: u16, proxyip: &'static str, proxyport: u16,
) {
    match case_name {
        "socks4_connect" => {
            _ = run_socks_case(
                case_name,
                tx,
                serverip,
                serverport,
                proxyip,
                proxyport,
                socks4_connect_test,
            )
            .await;
        }
        "socks5_connect" => {
            _ = run_socks_case(
                case_name,
                tx,
                serverip,
                serverport,
                proxyip,
                proxyport,
                socks5_connect_test,
            )
            .await;
        }
        "socks4a_connect" => {
            _ = run_socks_case(
                case_name,
                tx,
                serverip,
                serverport,
                proxyip,
                proxyport,
                socks4a_connect_test,
            )
            .await;
        }
        "socks4a_connect_hostname" => {
            _ = run_socks_case(
                case_name,
                tx,
                serverip,
                serverport,
                proxyip,
                proxyport,
                socks4a_connect_hostname_test,
            )
            .await;
        }
        "socks5_connect_hostname" => {
            _ = run_socks_case(
                case_name,
                tx,
                serverip,
                serverport,
                proxyip,
                proxyport,
                socks5_connect_hostname_test,
            )
            .await;
        }
        "socks5_auth_connect" => {
            _ = run_socks_case(
                case_name,
                tx,
                serverip,
                serverport,
                proxyip,
                proxyport,
                socks5_auth_connect_test,
            )
            .await;
        }
        "socks4_bind" => {
            _ = run_socks_case(
                case_name,
                tx,
                serverip,
                serverport,
                proxyip,
                proxyport,
                socks4_bind_test,
            )
            .await;
        }
        "socks5_bind" => {
            _ = run_socks_case(
                case_name,
                tx,
                serverip,
                serverport,
                proxyip,
                proxyport,
                socks5_bind_test,
            )
            .await;
        }
        "socks5_udp" => {
            _ = run_socks_case(
                case_name,
                tx,
                serverip,
                serverport,
                proxyip,
                proxyport,
                socks5_udp_test,
            )
            .await;
        }
        _ => {}
    }
}

async fn run_udp_echo_server(ip: &str, port: u16) -> Result<()> {
    let sock = UdpSocket::bind(format!("{}:{}", ip, port)).await?;
    let datasize = DATASIZE.get().unwrap().len();
    let mut buf = vec![0u8; 1024 + datasize];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        let _len = sock.send_to(&buf[..len], addr).await?;
    }
}
async fn run_tcp_bind_server(rx: &mut tokio::sync::mpsc::Receiver<Event>) -> Result<()> {
    while let Some(event) = rx.recv().await {
        debuginfo!("run_tcp_bind_server received event success!");
        match timeout(Duration::from_secs(5), TcpStream::connect(&event.target_addr)).await {
            Ok(result) => match result {
                Ok(mut stream) => {
                    debuginfo!("run_tcp_bind_server connect {:?} success!", event.target_addr);
                    stream.write_all(&event.data).await?;
                    debuginfo!("run_tcp_bind_server send data success!");
                    let _x = stream.shutdown().await;
                }
                Err(_err) => return Err(anyhow!("tcp connect failed")),
            },
            Err(_err) => return Err(anyhow!("tcp connect timeout")),
        }
    }
    Ok(())
}

async fn run_tcp_echo_server(ip: &str, port: u16) -> Result<()> {
    let addr = format!("{}:{}", ip, port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    loop {
        match listener.accept().await {
            Ok((mut socket, _addr)) => {
                tokio::spawn(async move {
                    let (reader, mut writer) = socket.split();
                    let mut reader = tokio::io::BufReader::new(reader);
                    loop {
                        let mut msg = [0; 2048];
                        match reader.read(&mut msg).await {
                            Ok(bytes_size) => {
                                println!("recived bytes_size {}", bytes_size);
                                match writer.write_all(&msg[0..bytes_size]).await {
                                    Ok(()) => (),
                                    Err(err) => {
                                        print!("Err:{:?}", err);
                                        break;
                                    }
                                }
                                if bytes_size == 0 {
                                    break;
                                }
                            }
                            Err(err) => {
                                print!("Err:{:?}", err);
                                break;
                            }
                        }
                    }
                    // 关闭连接
                    if let Err(err) = socket.shutdown().await {
                        println!("Shutdown error: {:?}", err);
                    }
                });
            }
            Err(err) => {
                print!("Err:{:?}", err)
            }
        }
    }
}

fn subscription_command() -> clap::Command {
    let add = clap::Command::new("add")
        .about("add a periodically tested proxy subscription")
        .arg(clap::Arg::new("name").long("name").required(true).value_name("name"))
        .arg(clap::Arg::new("url").long("url").required(true).value_name("url"))
        .arg(
            clap::Arg::new("source-type")
                .long("source-type")
                .value_parser(["proxy-list", "source-list"])
                .default_value("proxy-list"),
        )
        .arg(
            clap::Arg::new("interval-seconds")
                .long("interval-seconds")
                .default_value("3600")
                .value_name("seconds"),
        )
        .arg(
            clap::Arg::new("interface")
                .long("interface")
                .value_name("name")
                .action(clap::ArgAction::Append)
                .conflicts_with("all-interfaces"),
        )
        .arg(
            clap::Arg::new("all-interfaces")
                .long("all-interfaces")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with("interface"),
        )
        .arg(
            clap::Arg::new("profile")
                .long("profile")
                .value_parser(["basic", "standard", "full"])
                .default_value("standard"),
        )
        .arg(
            clap::Arg::new("protocol")
                .long("protocol")
                .value_parser(["auto", "socks4", "socks4a", "socks5"])
                .default_value("auto"),
        )
        .arg(clap::Arg::new("concurrency").long("concurrency").default_value("100"))
        .arg(clap::Arg::new("timeout").long("timeout").default_value("10"))
        .arg(
            clap::Arg::new("check-url")
                .long("check-url")
                .default_value("https://api.ipify.org"),
        )
        .arg(
            clap::Arg::new("latency-samples")
                .long("latency-samples")
                .default_value("3"),
        )
        .arg(
            clap::Arg::new("download-url")
                .long("download-url")
                .default_value("https://speed.cloudflare.com/__down?bytes={bytes}"),
        )
        .arg(
            clap::Arg::new("upload-url")
                .long("upload-url")
                .default_value("https://speed.cloudflare.com/__up"),
        )
        .arg(
            clap::Arg::new("download-bytes")
                .long("download-bytes")
                .default_value("1048576"),
        )
        .arg(
            clap::Arg::new("upload-bytes")
                .long("upload-bytes")
                .default_value("262144"),
        )
        .arg(
            clap::Arg::new("ip-info-url-template")
                .long("ip-info-url-template")
                .value_name("url-template"),
        )
        .arg(
            clap::Arg::new("disabled")
                .long("disabled")
                .action(clap::ArgAction::SetTrue)
                .help("create the subscription disabled"),
        );

    let id_command = |name: &'static str, about: &'static str| {
        clap::Command::new(name)
            .about(about)
            .arg(clap::Arg::new("id").long("id").required(true).value_name("id"))
    };

    clap::Command::new("subscription")
        .about("manage persistent proxy-list subscriptions")
        .subcommand_required(true)
        .subcommand(add)
        .subcommand(clap::Command::new("list").about("list subscriptions using redacted sources"))
        .subcommand(id_command("show", "show one subscription without exposing source secrets"))
        .subcommand(id_command("enable", "enable a subscription"))
        .subcommand(id_command("disable", "disable a subscription"))
        .subcommand(id_command("remove", "remove a subscription"))
        .subcommand(id_command("run", "run one subscription immediately"))
}

fn service_command() -> clap::Command {
    clap::Command::new("service")
        .about("run due enabled subscriptions until a shutdown signal")
        .arg(
            clap::Arg::new("poll-seconds")
                .long("poll-seconds")
                .default_value("5")
                .value_name("seconds"),
        )
        .arg(
            clap::Arg::new("retention-days")
                .long("retention-days")
                .default_value("30")
                .value_name("days")
                .help("delete historical run data older than this; 0 disables retention"),
        )
        .arg(
            clap::Arg::new("once")
                .long("once")
                .action(clap::ArgAction::SetTrue)
                .help("process currently due subscriptions once, then exit"),
        )
}

fn parse_args() -> clap::ArgMatches {
    clap::Command::new("proxy-socks-test")
        .arg_required_else_help(true)
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            clap::Arg::new("proxyip")
                .long("proxyip")
                .value_name("ipaddress")
                .help("set proxy ipaddress")
                .required(false),
        )
        .arg(
            clap::Arg::new("proxyport")
                .long("proxyport")
                .value_name("port")
                .help("set proxy port")
                .required(false),
        )
        .arg(
            clap::Arg::new("serverip")
                .long("serverip")
                .value_name("ipaddress")
                .help("set proxy test running host ipaddress,default use 0.0.0.0")
                .required(false),
        )
        .arg(
            clap::Arg::new("serverport")
                .long("serverport")
                .value_name("port")
                .help("set proxy test running host port,default use 3307")
                .required(false)
                .default_value("3307"),
        )
        .arg(
            clap::Arg::new("auth")
                .long("auth")
                .value_name("auth")
                .help("set socks username and password,split with :")
                .required(false)
                .default_value(""),
        )
        .arg(
            clap::Arg::new("datasize")
                .long("datasize")
                .value_name("datasize")
                .help("set test data size")
                .required(false),
        )
        .arg(
            clap::Arg::new("casename")
                .long("casename")
                .value_name("test case name")
                .next_line_help(true)
                .value_parser([
                    "socks4_connect",
                    "socks5_connect",
                    "socks5_connect_hostname",
                    "socks4a_connect_hostname",
                    "socks4a_connect",
                    "socks4_bind",
                    "socks5_bind",
                    "socks5_udp",
                    "socks5_auth_connect",
                    "socks5_auth_bind",
                    "socks5_auth_udp",
                ])
                .hide_possible_values(false)
                .required(false),
        )
        .arg(
            clap::Arg::new("proxy-file")
                .long("proxy-file")
                .value_name("path-or-url")
                .action(clap::ArgAction::Append)
                .help("read proxy entries from a local file or HTTP(S) URL"),
        )
        .arg(
            clap::Arg::new("source-list")
                .long("source-list")
                .value_name("path-or-url")
                .action(clap::ArgAction::Append)
                .help("read a file/URL whose non-comment lines are proxy-list URLs"),
        )
        .arg(
            clap::Arg::new("source-url")
                .long("source-url")
                .value_name("url")
                .action(clap::ArgAction::Append)
                .help("download proxy entries directly from an HTTP(S) URL"),
        )
        .arg(
            clap::Arg::new("output")
                .long("output")
                .value_name("path")
                .default_value("proxy-results.tsv")
                .help("write batch validation results as TSV"),
        )
        .arg(
            clap::Arg::new("no-tsv")
                .long("no-tsv")
                .action(clap::ArgAction::SetTrue)
                .help("persist to SQLite without writing the immediate TSV file"),
        )
        .arg(
            clap::Arg::new("valid-output")
                .long("valid-output")
                .value_name("path")
                .help("optionally write valid normalized proxies, one per line"),
        )
        .arg(
            clap::Arg::new("database")
                .long("database")
                .value_name("path")
                .default_value("proxy-socks-test.sqlite3")
                .global(true)
                .help("persist batch, subscription, and service state to SQLite"),
        )
        .arg(
            clap::Arg::new("interface")
                .long("interface")
                .value_name("name")
                .action(clap::ArgAction::Append)
                .conflicts_with("all-interfaces")
                .help("bind validation traffic to this network interface; repeat to test several"),
        )
        .arg(
            clap::Arg::new("all-interfaces")
                .long("all-interfaces")
                .num_args(0)
                .action(clap::ArgAction::SetTrue)
                .conflicts_with("interface")
                .help("test every usable non-loopback network interface independently"),
        )
        .arg(
            clap::Arg::new("protocol")
                .long("protocol")
                .value_name("protocol")
                .value_parser(["auto", "socks4", "socks4a", "socks5"])
                .default_value("auto")
                .help("default protocol for entries without a scheme"),
        )
        .arg(
            clap::Arg::new("concurrency")
                .long("concurrency")
                .value_name("count")
                .default_value("100")
                .help("maximum concurrent proxy checks"),
        )
        .arg(
            clap::Arg::new("timeout")
                .long("timeout")
                .value_name("seconds")
                .default_value("10")
                .help("per-proxy request timeout in seconds"),
        )
        .arg(
            clap::Arg::new("check-url")
                .long("check-url")
                .value_name("url")
                .default_value("https://api.ipify.org")
                .help("HTTP(S) endpoint that returns the caller IP as plain text"),
        )
        .arg(
            clap::Arg::new("profile")
                .long("profile")
                .value_name("profile")
                .value_parser(["basic", "standard", "full"])
                .default_value("standard")
                .help("staged test profile: basic=validity, standard=latency/jitter, full=plus speed tests"),
        )
        .arg(
            clap::Arg::new("latency-samples")
                .long("latency-samples")
                .value_name("count")
                .default_value("3")
                .help("HTTP latency samples for standard/full profiles"),
        )
        .arg(
            clap::Arg::new("download-url")
                .long("download-url")
                .value_name("url-template")
                .default_value("https://speed.cloudflare.com/__down?bytes={bytes}")
                .help("full-profile download URL; {bytes} is replaced with the configured byte budget"),
        )
        .arg(
            clap::Arg::new("upload-url")
                .long("upload-url")
                .value_name("url")
                .default_value("https://speed.cloudflare.com/__up")
                .help("full-profile HTTP POST upload endpoint"),
        )
        .arg(
            clap::Arg::new("download-bytes")
                .long("download-bytes")
                .value_name("bytes")
                .default_value("1048576")
                .help("maximum requested download benchmark payload"),
        )
        .arg(
            clap::Arg::new("upload-bytes")
                .long("upload-bytes")
                .value_name("bytes")
                .default_value("262144")
                .help("upload benchmark payload size"),
        )
        .arg(
            clap::Arg::new("ip-info-url-template")
                .long("ip-info-url-template")
                .value_name("url-template")
                .help("optional JSON IP-enrichment URL containing {ip}; enrichment never affects validity"),
        )
        .subcommand(subscription_command())
        .subcommand(service_command())
        .arg(
            clap::Arg::new("debug")
                .long("debug")
                .num_args(0)
                .action(clap::ArgAction::SetTrue)
                .help("print debug message")
                .required(false),
        )
        .get_matches()
}

fn init_data_size(datasizeint: u16) {
    DATASIZE.get_or_init(|| {
        if datasizeint == 0 {
            String::from("")
        } else {
            let rng = thread_rng();
            rng.sample_iter(&Alphanumeric).take(datasizeint as usize).map(char::from).collect()
        }
    });
}

#[tokio::main]
async fn main() -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Event>(100);

    let matches = parse_args();
    let database = matches.get_one::<String>("database").expect("database").clone();

    match matches.subcommand() {
        Some(("subscription", subscription_matches)) => {
            return batch::run_subscription_command(subscription_matches, &database).await;
        }
        Some(("service", service_matches)) => {
            let poll_seconds = service_matches
                .get_one::<String>("poll-seconds")
                .expect("poll-seconds")
                .parse::<u64>()
                .map_err(|err| anyhow!("invalid --poll-seconds: {err}"))?;
            let retention_days = service_matches
                .get_one::<String>("retention-days")
                .expect("retention-days")
                .parse::<u64>()
                .map_err(|err| anyhow!("invalid --retention-days: {err}"))?;
            return batch::run_service(
                &database,
                poll_seconds,
                retention_days,
                service_matches.get_flag("once"),
            )
            .await;
        }
        _ => {}
    }

    let proxy_files = matches
        .get_many::<String>("proxy-file")
        .map(|values| values.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let source_lists = matches
        .get_many::<String>("source-list")
        .map(|values| values.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let source_urls = matches
        .get_many::<String>("source-url")
        .map(|values| values.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let interfaces = matches
        .get_many::<String>("interface")
        .map(|values| values.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let all_interfaces = matches.get_flag("all-interfaces");
    let batch_mode = !proxy_files.is_empty() || !source_lists.is_empty() || !source_urls.is_empty();

    if batch_mode {
        let concurrency = matches
            .get_one::<String>("concurrency")
            .expect("concurrency")
            .parse::<usize>()
            .map_err(|err| anyhow!("invalid --concurrency: {err}"))?;
        let timeout_secs = matches
            .get_one::<String>("timeout")
            .expect("timeout")
            .parse::<u64>()
            .map_err(|err| anyhow!("invalid --timeout: {err}"))?;
        let latency_samples = matches
            .get_one::<String>("latency-samples")
            .expect("latency-samples")
            .parse::<usize>()
            .map_err(|err| anyhow!("invalid --latency-samples: {err}"))?;
        let download_bytes = matches
            .get_one::<String>("download-bytes")
            .expect("download-bytes")
            .parse::<u64>()
            .map_err(|err| anyhow!("invalid --download-bytes: {err}"))?;
        let upload_bytes = matches
            .get_one::<String>("upload-bytes")
            .expect("upload-bytes")
            .parse::<u64>()
            .map_err(|err| anyhow!("invalid --upload-bytes: {err}"))?;

        return batch::run_batch(batch::BatchOptions {
            proxy_files,
            source_lists,
            source_urls,
            inline_proxy_sources: Vec::new(),
            inline_source_lists: Vec::new(),
            output: matches.get_one::<String>("output").expect("output").clone(),
            write_tsv: !matches.get_flag("no-tsv"),
            valid_output: matches.get_one::<String>("valid-output").cloned(),
            database,
            interfaces,
            all_interfaces,
            default_protocol: matches.get_one::<String>("protocol").expect("protocol").clone(),
            concurrency,
            timeout_secs,
            check_url: matches.get_one::<String>("check-url").expect("check-url").clone(),
            profile: matches.get_one::<String>("profile").expect("profile").clone(),
            latency_samples,
            download_url: matches.get_one::<String>("download-url").expect("download-url").clone(),
            upload_url: matches.get_one::<String>("upload-url").expect("upload-url").clone(),
            download_bytes,
            upload_bytes,
            ip_info_url_template: matches.get_one::<String>("ip-info-url-template").cloned(),
            subscription_id: None,
        })
        .await;
    }

    let proxyip = matches
        .get_one::<String>("proxyip")
        .ok_or_else(|| anyhow!("single-proxy mode requires --proxyip"))?
        .clone();
    let proxyipstr: &str = string_to_static_str(proxyip);

    let proxyport = matches
        .get_one::<String>("proxyport")
        .ok_or_else(|| anyhow!("single-proxy mode requires --proxyport"))?
        .clone();
    let proxyportint =
        proxyport.parse::<u16>().map_err(|err| anyhow!("invalid --proxyport: {err}"))?;

    let serverip = matches
        .get_one::<String>("serverip")
        .ok_or_else(|| anyhow!("single-proxy mode requires --serverip"))?
        .clone();
    let serveripstr: &str = string_to_static_str(serverip);

    let serverport = matches.get_one::<String>("serverport").expect("serverport").clone();
    let serverportint =
        serverport.parse::<u16>().map_err(|err| anyhow!("invalid --serverport: {err}"))?;

    let authinfo = matches.get_one::<String>("auth").expect("auth").clone();
    init_auth(&authinfo);

    let datasize = matches.get_one::<String>("datasize").map(|s| s.as_str()).unwrap_or_default();
    let datasizeint = datasize.parse::<u16>().unwrap_or_default();
    init_data_size(datasizeint);

    let debug: bool = matches.get_flag("debug");
    if debug {
        DEBUG_OPEN.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    let casename = matches
        .get_one::<String>("casename")
        .ok_or_else(|| anyhow!("single-proxy mode requires --casename"))?
        .clone();

    let casenamestr: &str = string_to_static_str(casename);

    let mut v = vec![];
    let mut set = JoinSet::new();
    let service_bind_server: JoinHandle<Result<()>> = tokio::task::spawn(async move {
        _ = run_tcp_bind_server(&mut rx).await;
        exit(1);
    });
    let service_udp_server: JoinHandle<Result<()>> = tokio::task::spawn(async move {
        _ = run_udp_echo_server(serveripstr, serverportint).await;
        exit(1);
    });
    let service_tcp_server: JoinHandle<Result<()>> = tokio::task::spawn(async move {
        _ = run_tcp_echo_server(serveripstr, serverportint).await;
        exit(1);
    });
    let case_run: JoinHandle<Result<()>> = tokio::task::spawn(async move {
        run_test_cace_client(
            &tx,
            casenamestr,
            serveripstr,
            serverportint,
            proxyipstr,
            proxyportint,
        )
        .await;
        exit(0);
    });

    v.push(service_bind_server);
    v.push(service_udp_server);
    v.push(service_tcp_server);
    v.push(case_run);

    for fut in v {
        set.spawn(fut);
    }

    while let Some(res) = set.join_next().await {
        println!("{:?}", res);
    }

    Ok(())
}
