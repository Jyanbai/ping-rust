use std::{
    env, fs,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct OriginGuard {
    address: SocketAddr,
    stopped: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Drop for OriginGuard {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn start_origin() -> io::Result<OriginGuard> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let stopped = Arc::new(AtomicBool::new(false));
    let thread_stopped = Arc::clone(&stopped);
    let thread = thread::spawn(move || {
        while !thread_stopped.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut request = [0_u8; 1024];
                    if stream.read(&mut request).is_ok() {
                        let body = b"ping-rust-chain-e2e";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.write_all(body);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    Ok(OriginGuard {
        address,
        stopped,
        thread: Some(thread),
    })
}

fn unused_ports(count: usize) -> io::Result<Vec<u16>> {
    let listeners = (0..count)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<io::Result<Vec<_>>>()?;
    listeners
        .iter()
        .map(|listener| listener.local_addr().map(|address| address.port()))
        .collect()
}

fn write_config(path: &Path, contents: &str) -> io::Result<()> {
    fs::write(path, contents.as_bytes())
}

fn validate_config(shoes: &Path, config: &Path) -> io::Result<()> {
    let status = Command::new(shoes)
        .arg("--dry-run")
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "shoes rejected {}",
            config.display()
        )))
    }
}

fn spawn_shoes(shoes: &Path, config: &Path) -> io::Result<ChildGuard> {
    Command::new(shoes)
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(ChildGuard)
}

fn wait_for_port(port: u16) -> io::Result<()> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("listener {address} did not become ready"),
    ))
}

fn read_socks_address(stream: &mut TcpStream, address_type: u8) -> io::Result<()> {
    let length = match address_type {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length)?;
            usize::from(length[0])
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SOCKS address type {other}"),
            ));
        }
    };
    let mut rest = vec![0_u8; length + 2];
    stream.read_exact(&mut rest)
}

fn request_through_socks(socks_port: u16, origin: SocketAddr) -> io::Result<String> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], socks_port)),
        Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(&[5, 1, 0])?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting)?;
    if greeting != [5, 0] {
        return Err(io::Error::other("SOCKS server rejected no-auth method"));
    }
    let SocketAddr::V4(origin) = origin else {
        return Err(io::Error::other("test origin must use IPv4"));
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&origin.ip().octets());
    request.extend_from_slice(&origin.port().to_be_bytes());
    stream.write_all(&request)?;
    let mut response = [0_u8; 4];
    stream.read_exact(&mut response)?;
    if response[0] != 5 || response[1] != 0 {
        return Err(io::Error::other(format!(
            "SOCKS CONNECT failed with code {}",
            response[1]
        )));
    }
    read_socks_address(&mut stream, response[3])?;
    stream.write_all(b"GET /probe HTTP/1.1\r\nHost: chain.test\r\nConnection: close\r\n\r\n")?;
    let _ = stream.shutdown(Shutdown::Write);
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[test]
fn chain_proxy_uses_authenticated_upstream_without_direct_fallback() -> io::Result<()> {
    let Some(shoes) = env::var_os("PING_RUST_SHOES_E2E_BIN") else {
        eprintln!("skipped: set PING_RUST_SHOES_E2E_BIN to run shoes traffic acceptance");
        return Ok(());
    };
    let shoes = Path::new(&shoes);
    if !shoes.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("shoes binary does not exist: {}", shoes.display()),
        ));
    }

    let origin = start_origin()?;
    let ports = unused_ports(3)?;
    let [upstream_port, downstream_port, client_port] = ports.as_slice() else {
        return Err(io::Error::other("failed to reserve three test ports"));
    };
    let directory = tempfile::tempdir()?;
    let upstream = directory.path().join("upstream.yaml");
    let downstream = directory.path().join("downstream.yaml");
    let client = directory.path().join("client.yaml");

    write_config(
        &upstream,
        &format!(
            "- address: 127.0.0.1:{upstream_port}\n  protocol:\n    type: socks\n    username: chain-user\n    password: chain-password\n    udp_enabled: false\n  rules:\n    - allow-all-direct\n"
        ),
    )?;
    write_config(
        &downstream,
        &format!(
            "- address: 127.0.0.1:{downstream_port}\n  protocol:\n    type: shadowsocks\n    cipher: aes-128-gcm\n    password: downstream-password\n    udp_enabled: false\n  rules:\n    - masks: 0.0.0.0/0\n      action: allow\n      client_chains:\n        address: 127.0.0.1:{upstream_port}\n        protocol:\n          type: socks\n          username: chain-user\n          password: chain-password\n"
        ),
    )?;
    write_config(
        &client,
        &format!(
            "- address: 127.0.0.1:{client_port}\n  protocol:\n    type: socks\n    udp_enabled: false\n  rules:\n    - masks: 0.0.0.0/0\n      action: allow\n      client_chains:\n        address: 127.0.0.1:{downstream_port}\n        protocol:\n          type: shadowsocks\n          cipher: aes-128-gcm\n          password: downstream-password\n          udp_enabled: false\n"
        ),
    )?;
    for config in [&upstream, &downstream, &client] {
        validate_config(shoes, config)?;
    }

    let _downstream = spawn_shoes(shoes, &downstream)?;
    let _client = spawn_shoes(shoes, &client)?;
    wait_for_port(*downstream_port)?;
    wait_for_port(*client_port)?;
    assert!(
        request_through_socks(*client_port, origin.address).is_err(),
        "request unexpectedly succeeded while the required upstream was offline"
    );

    let mut upstream_process = spawn_shoes(shoes, &upstream)?;
    wait_for_port(*upstream_port)?;
    let response = request_through_socks(*client_port, origin.address)?;
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("ping-rust-chain-e2e"));

    upstream_process.0.kill()?;
    upstream_process.0.wait()?;
    assert!(
        request_through_socks(*client_port, origin.address).is_err(),
        "request unexpectedly succeeded after the required upstream stopped"
    );
    Ok(())
}
