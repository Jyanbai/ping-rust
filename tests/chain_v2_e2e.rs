use std::{
    env, fs,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
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

struct SocksHop {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl SocksHop {
    fn start() -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_count = Arc::clone(&count);
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((incoming, _)) => {
                        worker_count.fetch_add(1, Ordering::Relaxed);
                        thread::spawn(move || {
                            let _ = serve_socks(incoming);
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            count,
            stop,
            worker: Some(worker),
        })
    }

    fn connections(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}

impl Drop for SocksHop {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn serve_socks(mut incoming: TcpStream) -> io::Result<()> {
    incoming.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut greeting = [0; 2];
    incoming.read_exact(&mut greeting)?;
    if greeting[0] != 5 {
        return Err(io::Error::other("invalid SOCKS version"));
    }
    let mut methods = vec![0; usize::from(greeting[1])];
    incoming.read_exact(&mut methods)?;
    incoming.write_all(&[5, 0])?;
    let mut request = [0; 4];
    incoming.read_exact(&mut request)?;
    if request[..3] != [5, 1, 0] {
        return Err(io::Error::other("unsupported SOCKS request"));
    }
    let host = match request[3] {
        1 => {
            let mut ip = [0; 4];
            incoming.read_exact(&mut ip)?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut len = [0];
            incoming.read_exact(&mut len)?;
            let mut name = vec![0; usize::from(len[0])];
            incoming.read_exact(&mut name)?;
            String::from_utf8(name).map_err(io::Error::other)?
        }
        _ => return Err(io::Error::other("unsupported SOCKS address")),
    };
    let mut port = [0; 2];
    incoming.read_exact(&mut port)?;
    let addresses = (host.as_str(), u16::from_be_bytes(port))
        .to_socket_addrs()?
        .collect::<Vec<_>>();
    let destination = addresses
        .iter()
        .find(|address| address.is_ipv4())
        .or_else(|| addresses.first())
        .copied()
        .ok_or_else(|| io::Error::other("unresolved SOCKS destination"))?;
    let mut outgoing = TcpStream::connect_timeout(&destination, Duration::from_secs(3))?;
    incoming.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])?;
    incoming.set_read_timeout(None)?;
    let mut from_client = incoming.try_clone()?;
    let mut to_server = outgoing.try_clone()?;
    let forward = thread::spawn(move || {
        let _ = io::copy(&mut from_client, &mut to_server);
        let _ = to_server.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut outgoing, &mut incoming);
    let _ = incoming.shutdown(Shutdown::Write);
    let _ = forward.join();
    Ok(())
}

fn ports(count: usize) -> io::Result<Vec<u16>> {
    let listeners = (0..count)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<io::Result<Vec<_>>>()?;
    listeners
        .iter()
        .map(|listener| listener.local_addr().map(|address| address.port()))
        .collect()
}

fn wait_port(port: u16) -> io::Result<()> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("listener {port} did not start"),
    ))
}

fn request(proxy: u16, target: &str, target_port: u16) -> io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(&[5, 1, 0])?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting)?;
    if greeting != [5, 0] {
        return Err(io::Error::other("SOCKS greeting rejected"));
    }
    let mut connect = vec![5, 1, 0];
    if let Ok(ip) = target.parse::<std::net::Ipv4Addr>() {
        connect.push(1);
        connect.extend_from_slice(&ip.octets());
    } else {
        connect.extend_from_slice(&[3, target.len() as u8]);
        connect.extend_from_slice(target.as_bytes());
    }
    connect.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&connect)?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply)?;
    if reply[1] != 0 {
        return Err(io::Error::other(format!(
            "SOCKS rejected with code {}",
            reply[1]
        )));
    }
    let address_len = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0];
            stream.read_exact(&mut len)?;
            usize::from(len[0])
        }
        _ => return Err(io::Error::other("invalid SOCKS reply")),
    };
    let mut rest = vec![0; address_len + 2];
    stream.read_exact(&mut rest)?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn ingress(port: u16, rules: &str) -> String {
    format!("- address: 127.0.0.1:{port}\n  protocol:\n    type: socks\n    udp_enabled: false\n  rules:\n{rules}\n")
}

fn chain(addresses: &[SocketAddr]) -> String {
    let hops = addresses
        .iter()
        .map(|address| {
            format!(
        "            - address: {address}\n              protocol:\n                type: socks\n"
    )
        })
        .collect::<String>();
    format!("        chain:\n{hops}")
}

fn rule(mask: &str, action: &str, chains: Option<&str>) -> String {
    let mut result = format!("    - masks: {mask}\n      action: {action}\n");
    if let Some(chains) = chains {
        result.push_str("      client_chains:\n");
        result.push_str(chains);
    }
    result
}

#[test]
fn chain_v2_local_routing_traffic() -> io::Result<()> {
    let Some(binary) = env::var_os("PING_RUST_SHOES_E2E_BIN") else {
        eprintln!("skipped: set PING_RUST_SHOES_E2E_BIN for pinned shoes traffic test");
        return Ok(());
    };
    let shoes = Path::new(&binary);
    if !shoes.is_file() {
        return Err(io::Error::other("pinned shoes binary is missing"));
    }
    let origin = TcpListener::bind("0.0.0.0:0")?;
    let origin_port = origin.local_addr()?.port();
    origin.set_nonblocking(true)?;
    let origin_stop = Arc::new(AtomicBool::new(false));
    let origin_worker_stop = Arc::clone(&origin_stop);
    let origin_worker = thread::spawn(move || {
        while !origin_worker_stop.load(Ordering::Relaxed) {
            match origin.accept() {
                Ok((mut stream, _)) => {
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut bytes = [0; 1024];
                        let _ = stream.read(&mut bytes);
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        );
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
    });
    struct StopOrigin(Arc<AtomicBool>, Option<thread::JoinHandle<()>>);
    impl Drop for StopOrigin {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
            if let Some(worker) = self.1.take() {
                let _ = worker.join();
            }
        }
    }
    let _origin_guard = StopOrigin(origin_stop, Some(origin_worker));

    let p = ports(9)?;
    let relay_a = SocksHop::start()?;
    let relay_b = SocksHop::start()?;
    let a = relay_a.address;
    let b = relay_b.address;
    let single_a = chain(&[a]);
    let single_b = chain(&[b]);
    let multi = chain(&[a, b]);
    let pool = format!("        chain:\n            - pool:\n                - address: {a}\n                  protocol:\n                    type: socks\n                - address: {b}\n                  protocol:\n                    type: socks\n");
    let rr = format!("        - chain:\n            - address: {a}\n              protocol:\n                type: socks\n        - chain:\n            - address: {b}\n              protocol:\n                type: socks\n");
    let mut yaml = String::new();
    yaml.push_str(&ingress(p[2], &rule("0.0.0.0/0", "allow", Some(&multi))));
    yaml.push_str(&ingress(p[3], &rule("0.0.0.0/0", "allow", Some(&pool))));
    yaml.push_str(&ingress(p[4], &rule("0.0.0.0/0", "allow", Some(&rr))));
    yaml.push_str(&ingress(
        p[5],
        &format!(
            "{}{}",
            rule("127.0.0.0/8", "allow", Some(&single_a)),
            rule(
                "0.0.0.0/0",
                "allow",
                Some("        protocol:\n          type: direct\n")
            )
        ),
    ));
    yaml.push_str(&ingress(
        p[6],
        &format!(
            "{}{}",
            rule("localhost", "allow", Some(&single_b)),
            rule(
                "0.0.0.0/0",
                "allow",
                Some("        protocol:\n          type: direct\n")
            )
        ),
    ));
    yaml.push_str(&ingress(
        p[7],
        &format!(
            "{}{}",
            rule(
                "127.0.0.1/32",
                "allow",
                Some("        protocol:\n          type: direct\n")
            ),
            rule("0.0.0.0/0", "allow", Some(&single_a))
        ),
    ));
    yaml.push_str(&ingress(
        p[8],
        &format!(
            "{}{}",
            rule("127.0.0.0/8", "block", None),
            rule(
                "0.0.0.0/0",
                "allow",
                Some("        protocol:\n          type: direct\n")
            )
        ),
    ));
    let directory = tempfile::tempdir()?;
    let config = directory.path().join("chain-v2.yaml");
    fs::write(&config, &yaml)?;
    let dry_run = Command::new(shoes).arg("--dry-run").arg(&config).output()?;
    assert!(
        dry_run.status.success(),
        "{}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let runtime_log = directory.path().join("runtime.log");
    let child = Command::new(shoes)
        .arg(&config)
        .env("RUST_LOG", "debug")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(&runtime_log)?)
        .spawn()?;
    let _shoes = ChildGuard(child);
    for port in &p[2..] {
        wait_port(*port)?;
    }
    let checked = |stage: &str, proxy: u16, target: &str| {
        let mut last_error = None;
        for _ in 0..3 {
            match request(proxy, target, origin_port) {
                Ok(response) => return Ok(response),
                Err(error) => {
                    last_error = Some(error);
                    thread::sleep(Duration::from_millis(30));
                }
            }
        }
        Err(io::Error::other(format!(
            "{stage}: {}; log:\n{}",
            last_error.expect("attempted request"),
            fs::read_to_string(&runtime_log).unwrap_or_default()
        )))
    };
    let direct_hop = checked("single-hop", p[5], "127.0.0.1")?;
    assert!(direct_hop.ends_with("ok"));
    let first = checked("multi-hop", p[2], "127.0.0.1")?;
    assert!(first.ends_with("ok"));
    assert!(
        relay_a.connections() > 0 && relay_b.connections() > 0,
        "multi-hop skipped a hop"
    );
    let a_before = relay_a.connections();
    let b_before = relay_b.connections();
    for _ in 0..16 {
        assert!(checked("pool", p[3], "127.0.0.1")?.ends_with("ok"));
    }
    assert!(
        relay_a.connections() > a_before && relay_b.connections() > b_before,
        "pool did not use both members"
    );
    let a_before = relay_a.connections();
    let b_before = relay_b.connections();
    for _ in 0..16 {
        assert!(checked("whole-chain RR", p[4], "127.0.0.1")?.ends_with("ok"));
    }
    assert!(
        relay_a.connections() > a_before && relay_b.connections() > b_before,
        "whole-chain RR did not use both chains"
    );
    let a_before = relay_a.connections();
    assert!(checked("CIDR", p[5], "127.0.0.1")?.ends_with("ok"));
    assert!(
        relay_a.connections() > a_before,
        "CIDR rule did not select chain"
    );
    let b_before = relay_b.connections();
    assert!(checked("hostname", p[6], "localhost")?.ends_with("ok"));
    assert!(
        relay_b.connections() > b_before,
        "hostname rule did not select chain"
    );
    let a_before = relay_a.connections();
    assert!(checked("DIRECT", p[7], "127.0.0.1")?.ends_with("ok"));
    assert_eq!(relay_a.connections(), a_before, "DIRECT used upstream");
    assert!(checked("default route", p[7], "127.0.0.2")?.ends_with("ok"));
    assert!(
        relay_a.connections() > a_before,
        "default route did not select chain"
    );
    assert!(
        request(p[8], "127.0.0.1", origin_port).is_err(),
        "BLOCK allowed connection"
    );
    Ok(())
}
