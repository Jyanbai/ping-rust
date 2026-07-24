#![cfg(target_os = "linux")]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const CONFIG_DIR: &str = "/etc/shoes";
const UNIT_PATH: &str = "/etc/systemd/system/shoes.service";
const ORIGIN_BODY: &str = "ping-rust-production-chain";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct ManagedChild {
    label: &'static str,
    child: Child,
    log_path: PathBuf,
}

impl ManagedChild {
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Origin {
    address: SocketAddr,
    peer: Arc<Mutex<Option<IpAddr>>>,
    stopped: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Origin {
    fn start(port: u16) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let peer = Arc::new(Mutex::new(None));
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_peer = Arc::clone(&peer);
        let thread_stopped = Arc::clone(&stopped);
        let thread = thread::spawn(move || {
            while !thread_stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, address)) => {
                        if let Ok(mut peer) = thread_peer.lock() {
                            *peer = Some(address.ip());
                        }
                        let _ = serve_origin_request(stream);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            peer,
            stopped,
            thread: Some(thread),
        })
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn clear_peer(&self) -> io::Result<()> {
        *self
            .peer
            .lock()
            .map_err(|_| io::Error::other("origin peer lock was poisoned"))? = None;
        Ok(())
    }

    fn wait_for_peer(&self, timeout: Duration) -> io::Result<Option<IpAddr>> {
        let deadline = Instant::now() + timeout;
        loop {
            let peer = *self
                .peer
                .lock()
                .map_err(|_| io::Error::other("origin peer lock was poisoned"))?;
            if peer.is_some() || Instant::now() >= deadline {
                return Ok(peer);
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], self.port())),
            Duration::from_millis(100),
        );
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Harness {
    work_dir: tempfile::TempDir,
    namespaces: Vec<String>,
    children: Vec<ManagedChild>,
    origin: Option<Origin>,
    stage: &'static str,
    host_claimed: bool,
}

impl Harness {
    fn new() -> io::Result<Self> {
        Ok(Self {
            work_dir: tempfile::tempdir()?,
            namespaces: Vec::new(),
            children: Vec::new(),
            origin: None,
            stage: "initializing",
            host_claimed: false,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.work_dir.path().join(name)
    }

    fn set_stage(&mut self, stage: &'static str) {
        self.stage = stage;
        eprintln!("chain acceptance: {stage}");
    }

    fn add_namespace(&mut self, name: &str) -> TestResult {
        run_status(
            Command::new("ip").args(["netns", "add", name]),
            "create namespace",
        )?;
        self.namespaces.push(name.to_owned());
        Ok(())
    }

    fn spawn_logged(&mut self, label: &'static str, command: &mut Command) -> TestResult {
        let log_path = self.path(&format!("{label}.log"));
        let stdout = File::create(&log_path)?;
        let stderr = stdout.try_clone()?;
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|error| format!("failed to start {label}: {error}"))?;
        self.children.push(ManagedChild {
            label,
            child,
            log_path,
        });
        Ok(())
    }

    fn stop_child(&mut self, label: &str) -> TestResult {
        let child = self
            .children
            .iter_mut()
            .find(|child| child.label == label)
            .ok_or_else(|| format!("managed child not found: {label}"))?;
        child.stop();
        Ok(())
    }

    fn origin(&self) -> TestResult<&Origin> {
        self.origin
            .as_ref()
            .ok_or_else(|| "origin is not running".into())
    }

    fn diagnostics(&self) {
        eprintln!("chain acceptance failed during '{}'", self.stage);
        for child in &self.children {
            if let Ok(log) = fs::read_to_string(&child.log_path) {
                if !log.is_empty() {
                    eprintln!("--- {}.log (last 80 lines) ---", child.label);
                    for line in log
                        .lines()
                        .rev()
                        .take(80)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                    {
                        eprintln!("{line}");
                    }
                }
            }
        }
        let _ = Command::new("journalctl")
            .args(["-u", "shoes.service", "--no-pager", "-n", "80"])
            .status();
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        for child in &mut self.children {
            child.stop();
        }
        self.origin.take();
        for namespace in self.namespaces.iter().rev() {
            let _ = Command::new("ip")
                .args(["netns", "delete", namespace])
                .status();
        }
        if self.host_claimed {
            let _ = Command::new("systemctl")
                .args(["disable", "--now", "shoes.service"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = fs::remove_file(UNIT_PATH);
            let _ = Command::new("systemctl")
                .arg("daemon-reload")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = fs::remove_dir_all(CONFIG_DIR);
        }
    }
}

fn serve_origin_request(mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = [0_u8; 2048];
    let length = stream.read(&mut request)?;
    let request = String::from_utf8_lossy(&request[..length]);
    if request.starts_with("GET /generate_204 ") {
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    } else {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            ORIGIN_BODY.len(),
            ORIGIN_BODY
        );
        stream.write_all(response.as_bytes())
    }
}

fn run_status(command: &mut Command, description: &str) -> TestResult {
    let status = command
        .status()
        .map_err(|error| format!("{description} could not start: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{description} failed with {status}").into())
    }
}

fn expect_failure(command: &mut Command, description: &str) -> TestResult {
    let status = command
        .status()
        .map_err(|error| format!("{description} could not start: {error}"))?;
    if status.success() {
        Err(format!("{description} unexpectedly succeeded").into())
    } else {
        Ok(())
    }
}

fn assert_root_and_clean_host() -> TestResult {
    let output = Command::new("id").arg("-u").output()?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "0" {
        return Err("chain systemd acceptance must run as root".into());
    }
    if Path::new(CONFIG_DIR).exists() || Path::new(UNIT_PATH).exists() {
        return Err(
            "refusing to overwrite an existing /etc/shoes or shoes.service; use an ephemeral host"
                .into(),
        );
    }
    for command in ["expect", "ip", "journalctl", "systemctl"] {
        if !command_exists(command) {
            return Err(format!("missing test dependency: {command}").into());
        }
    }
    Ok(())
}

fn command_exists(command: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path).any(|directory| {
                fs::metadata(directory.join(command)).is_ok_and(|metadata| {
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                })
            })
        })
        .unwrap_or(false)
}

fn required_file_from_env(name: &str, default: &str) -> TestResult<PathBuf> {
    let path = std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default));
    if !path.is_file() {
        return Err(format!("{name} does not point to a file: {}", path.display()).into());
    }
    Ok(path)
}

fn reserve_ports(count: usize) -> io::Result<Vec<u16>> {
    let listeners = (0..count)
        .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
        .collect::<io::Result<Vec<_>>>()?;
    listeners
        .iter()
        .map(|listener| listener.local_addr().map(|address| address.port()))
        .collect()
}

fn ip(args: &[&str], description: &str) -> TestResult {
    run_status(Command::new("ip").args(args), description)
}

fn configure_namespace(
    harness: &mut Harness,
    namespace: &str,
    root_interface: &str,
    peer_interface: &str,
    subnet: u8,
) -> TestResult {
    harness.add_namespace(namespace)?;
    ip(
        &[
            "link",
            "add",
            root_interface,
            "type",
            "veth",
            "peer",
            "name",
            peer_interface,
        ],
        "create veth pair",
    )?;
    ip(
        &["link", "set", peer_interface, "netns", namespace],
        "move veth peer into namespace",
    )?;
    let root_address = format!("10.231.{subnet}.1/30");
    let peer_address = format!("10.231.{subnet}.2/30");
    let gateway = format!("10.231.{subnet}.1");
    ip(
        &["address", "add", &root_address, "dev", root_interface],
        "assign root veth address",
    )?;
    ip(&["link", "set", root_interface, "up"], "enable root veth")?;
    ip(
        &["-n", namespace, "link", "set", "lo", "up"],
        "enable namespace loopback",
    )?;
    ip(
        &[
            "-n",
            namespace,
            "address",
            "add",
            &peer_address,
            "dev",
            peer_interface,
        ],
        "assign namespace veth address",
    )?;
    ip(
        &["-n", namespace, "link", "set", peer_interface, "up"],
        "enable namespace veth",
    )?;
    ip(
        &["-n", namespace, "route", "add", "default", "via", &gateway],
        "add namespace default route",
    )
}

fn write_upstream(path: &Path, port: u16, password: &str) -> io::Result<()> {
    fs::write(
        path,
        format!(
            "- address: 0.0.0.0:{port}\n  protocol:\n    type: shadowsocks\n    cipher: aes-128-gcm\n    password: {password}\n    udp_enabled: false\n  rules:\n    - allow-all-direct\n"
        ),
    )
}

fn validate_shoes(shoes: &Path, config: &Path) -> TestResult {
    run_status(
        Command::new(shoes)
            .arg("--dry-run")
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
        "shoes dry-run",
    )
}

fn wait_for_port(address: SocketAddr) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("listener did not become ready: {address}"),
    ))
}

fn run_menu(
    expect_script: &Path,
    ping_rust: &Path,
    action: &str,
    argument: Option<&str>,
    test_url: Option<&str>,
) -> TestResult {
    let mut command = Command::new("expect");
    command
        .arg(expect_script)
        .arg(ping_rust)
        .arg(action)
        .stdin(Stdio::null());
    if let Some(argument) = argument {
        command.arg(argument);
    }
    if let Some(test_url) = test_url {
        command.env("PING_RUST_CHAIN_TEST_URL", test_url);
    }
    run_status(&mut command, &format!("PTY chain menu action {action}"))
}

fn run_menu_expect_failure(
    expect_script: &Path,
    ping_rust: &Path,
    action: &str,
    argument: Option<&str>,
    test_url: &str,
) -> TestResult {
    let mut command = Command::new("expect");
    command
        .arg(expect_script)
        .arg(ping_rust)
        .arg(action)
        .env("PING_RUST_CHAIN_TEST_URL", test_url)
        .stdin(Stdio::null());
    if let Some(argument) = argument {
        command.arg(argument);
    }
    expect_failure(&mut command, &format!("PTY chain menu action {action}"))
}

fn assert_menu_test_peer(
    harness: &Harness,
    expect_script: &Path,
    ping_rust: &Path,
    url: &str,
    expected_peer: IpAddr,
    should_succeed: bool,
) -> TestResult {
    harness.origin()?.clear_peer()?;
    if should_succeed {
        run_menu(expect_script, ping_rust, "test", Some("1"), Some(url))?;
    } else {
        run_menu_expect_failure(expect_script, ping_rust, "test", Some("1"), url)?;
    }
    let actual = harness.origin()?.wait_for_peer(Duration::from_secs(2))?;
    if actual != Some(expected_peer) {
        return Err(format!(
            "unexpected origin peer after menu test: expected {expected_peer}, got {actual:?}"
        )
        .into());
    }
    Ok(())
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

fn request_through_socks(socks_port: u16, target: SocketAddr, path: &str) -> io::Result<String> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], socks_port)),
        Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(&[5, 1, 0])?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting)?;
    if greeting != [5, 0] {
        return Err(io::Error::other("SOCKS server rejected no-auth method"));
    }
    let SocketAddr::V4(target) = target else {
        return Err(io::Error::other("test target must use IPv4"));
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
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
    stream.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: chain.test\r\nConnection: close\r\n\r\n").as_bytes(),
    )?;
    let _ = stream.shutdown(Shutdown::Write);
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn probe_expect_peer(harness: &Harness, client_port: u16, expected_peer: IpAddr) -> TestResult {
    let origin = harness.origin()?;
    let target = SocketAddr::from(([10, 231, 1, 1], origin.port()));
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        origin.clear_peer()?;
        let result = request_through_socks(client_port, target, "/probe");
        if result.as_ref().is_ok_and(|response| {
            response.starts_with("HTTP/1.1 200 OK") && response.ends_with(ORIGIN_BODY)
        }) && origin.wait_for_peer(Duration::from_secs(1))? == Some(expected_peer)
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err(format!("proxy request did not use expected peer {expected_peer}").into())
}

fn probe_must_fail(harness: &Harness, client_port: u16) -> TestResult {
    let origin = harness.origin()?;
    origin.clear_peer()?;
    let target = SocketAddr::from(([10, 231, 1, 1], origin.port()));
    let result = request_through_socks(client_port, target, "/probe");
    if result.as_ref().is_ok_and(|response| {
        response.starts_with("HTTP/1.1 200 OK") && response.ends_with(ORIGIN_BODY)
    }) {
        return Err("request unexpectedly succeeded while active upstream was offline".into());
    }
    if origin.wait_for_peer(Duration::from_millis(750))?.is_some() {
        return Err("origin received a request while active upstream was offline".into());
    }
    Ok(())
}

fn write_reality_client(path: &Path, client_port: u16) -> TestResult {
    let state: Value =
        serde_json::from_slice(&fs::read(format!("{CONFIG_DIR}/ping-rust-state.json"))?)?;
    let profile = state
        .pointer("/profiles/0")
        .ok_or("managed state has no first profile")?;
    let credentials = profile
        .pointer("/credentials/Reality")
        .ok_or("first profile is not Reality")?;
    let port = profile
        .get("port")
        .and_then(Value::as_u64)
        .ok_or("Reality profile has no port")?;
    let string = |name: &str| -> TestResult<&str> {
        credentials
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Reality credentials have no {name}").into())
    };
    fs::write(
        path,
        format!(
            "- address: 127.0.0.1:{client_port}\n  protocol:\n    type: socks\n    udp_enabled: false\n  rules:\n    - masks: 0.0.0.0/0\n      action: allow\n      client_chain:\n        address: 127.0.0.1:{port}\n        protocol:\n          type: reality\n          public_key: {}\n          short_id: {}\n          sni_hostname: {}\n          vision: true\n          protocol:\n            type: vless\n            user_id: {}\n            udp_enabled: false\n",
            string("public_key")?,
            string("short_id")?,
            string("server_name")?,
            string("user_id")?,
        ),
    )?;
    Ok(())
}

fn assert_final_state() -> TestResult {
    let state: Value =
        serde_json::from_slice(&fs::read(format!("{CONFIG_DIR}/ping-rust-state.json"))?)?;
    let chain = state
        .get("chain_proxy")
        .ok_or("managed state has no chain_proxy")?;
    if chain.get("enabled").and_then(Value::as_bool) != Some(false) {
        return Err("chain_proxy.enabled is not false".into());
    }
    if chain
        .get("active_node")
        .is_some_and(|value| !value.is_null())
    {
        return Err("chain_proxy.active_node is not null".into());
    }
    if chain
        .get("nodes")
        .and_then(Value::as_array)
        .is_some_and(|nodes| !nodes.is_empty())
    {
        return Err("chain_proxy.nodes is not empty".into());
    }
    let aggregate = fs::read_to_string(format!("{CONFIG_DIR}/config.yaml"))?;
    if aggregate.contains("client_chain") {
        return Err("final aggregate config still contains client_chain".into());
    }
    Ok(())
}

fn systemctl(args: &[&str], description: &str) -> TestResult {
    run_status(Command::new("systemctl").args(args), description)
}

fn run_acceptance(harness: &mut Harness) -> TestResult {
    assert_root_and_clean_host()?;
    harness.host_claimed = true;
    let ping_rust = required_file_from_env("PING_RUST_BIN", "/usr/local/bin/ping-rust")?;
    let shoes = required_file_from_env("SHOES_BIN", "/usr/local/bin/shoes")?;
    let repo_dir = std::env::var_os("REPO_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let expect_script = repo_dir.join("tests/chain_menu.exp");
    if !expect_script.is_file() {
        return Err(format!("Expect menu driver is missing: {}", expect_script.display()).into());
    }

    let ports = reserve_ports(5)?;
    let [origin_port, upstream_one_port, upstream_two_port, client_port, server_port] =
        ports.as_slice()
    else {
        return Err("failed to reserve five ports".into());
    };
    let suffix = format!("{:05}", std::process::id() % 100_000);
    let namespace_one = format!("pr-chain-a-{suffix}");
    let namespace_two = format!("pr-chain-b-{suffix}");
    let root_one = format!("pra{suffix}");
    let peer_one = format!("pca{suffix}");
    let root_two = format!("prb{suffix}");
    let peer_two = format!("pcb{suffix}");

    harness.set_stage("creating isolated network exits");
    configure_namespace(harness, &namespace_one, &root_one, &peer_one, 1)?;
    configure_namespace(harness, &namespace_two, &root_two, &peer_two, 2)?;
    harness.origin = Some(Origin::start(*origin_port)?);

    let upstream_one = harness.path("upstream-one.yaml");
    let upstream_two = harness.path("upstream-two.yaml");
    write_upstream(&upstream_one, *upstream_one_port, "chain-one-password")?;
    write_upstream(&upstream_two, *upstream_two_port, "chain-two-password")?;
    validate_shoes(&shoes, &upstream_one)?;
    validate_shoes(&shoes, &upstream_two)?;
    harness.spawn_logged(
        "upstream-one",
        Command::new("ip")
            .args(["netns", "exec", &namespace_one])
            .arg(&shoes)
            .arg(&upstream_one),
    )?;
    harness.spawn_logged(
        "upstream-two",
        Command::new("ip")
            .args(["netns", "exec", &namespace_two])
            .arg(&shoes)
            .arg(&upstream_two),
    )?;
    wait_for_port(SocketAddr::from(([10, 231, 1, 2], *upstream_one_port)))?;
    wait_for_port(SocketAddr::from(([10, 231, 2, 2], *upstream_two_port)))?;

    harness.set_stage("generating deterministic managed Reality listener");
    let bootstrap_output = File::create(harness.path("bootstrap.out"))?;
    run_status(
        Command::new(&ping_rust)
            .args([
                "generate",
                "reality",
                "--name",
                "chain-entry",
                "--port",
                &server_port.to_string(),
                "--server-name",
                "www.cloudflare.com",
                "--dest",
                "www.cloudflare.com:443",
            ])
            .stdout(Stdio::from(bootstrap_output))
            .stderr(Stdio::null()),
        "generate managed Reality listener",
    )?;
    let _ = fs::remove_file(harness.path("bootstrap.out"));
    systemctl(
        &["is-active", "--quiet", "shoes.service"],
        "check active service",
    )?;
    systemctl(
        &["is-enabled", "--quiet", "shoes.service"],
        "check enabled service",
    )?;

    let encoded = |value: &str| STANDARD.encode(value.as_bytes());
    let uri_one = format!(
        "ss://{}@10.231.1.2:{upstream_one_port}#namespace-one",
        encoded("aes-128-gcm:chain-one-password")
    );
    let uri_two = format!(
        "ss://{}@10.231.2.2:{upstream_two_port}#namespace-two",
        encoded("aes-128-gcm:chain-two-password")
    );
    let uri_invalid = format!(
        "ss://{}@10.231.1.2:{upstream_one_port}#invalid-auth",
        encoded("aes-128-gcm:wrong-password")
    );
    let success_url = format!(
        "http://10.231.1.1:{}/generate_204",
        harness.origin()?.port()
    );
    let rejected_url = format!("http://10.231.1.1:{}/probe", harness.origin()?.port());

    harness.set_stage("adding first Shadowsocks chain node");
    run_menu(&expect_script, &ping_rust, "add", Some(&uri_one), None)?;
    harness.set_stage("testing first node with full protocol handshake");
    assert_menu_test_peer(
        harness,
        &expect_script,
        &ping_rust,
        &success_url,
        IpAddr::V4(Ipv4Addr::new(10, 231, 1, 2)),
        true,
    )?;
    harness.set_stage("rejecting HTTP 200 as a successful connectivity probe");
    assert_menu_test_peer(
        harness,
        &expect_script,
        &ping_rust,
        &rejected_url,
        IpAddr::V4(Ipv4Addr::new(10, 231, 1, 2)),
        false,
    )?;
    harness.set_stage("adding second Shadowsocks chain node");
    run_menu(&expect_script, &ping_rust, "add", Some(&uri_two), None)?;
    harness.set_stage("enabling first chain node");
    run_menu(&expect_script, &ping_rust, "enable", None, None)?;

    let client_config = harness.path("client.yaml");
    write_reality_client(&client_config, *client_port)?;
    validate_shoes(&shoes, &client_config)?;
    harness.spawn_logged("client", Command::new(&shoes).arg(&client_config))?;
    wait_for_port(SocketAddr::from(([127, 0, 0, 1], *client_port)))?;

    harness.set_stage("routing through first chain node");
    probe_expect_peer(
        harness,
        *client_port,
        IpAddr::V4(Ipv4Addr::new(10, 231, 1, 2)),
    )?;
    harness.set_stage("restarting systemd service");
    systemctl(&["restart", "shoes.service"], "restart shoes service")?;
    systemctl(
        &["is-active", "--quiet", "shoes.service"],
        "check active service",
    )?;
    harness.set_stage("routing through first node after systemd restart");
    probe_expect_peer(
        harness,
        *client_port,
        IpAddr::V4(Ipv4Addr::new(10, 231, 1, 2)),
    )?;

    harness.set_stage("verifying no direct fallback while first node is offline");
    harness.stop_child("upstream-one")?;
    probe_must_fail(harness, *client_port)?;

    harness.set_stage("switching to second chain node");
    run_menu(&expect_script, &ping_rust, "select", Some("2"), None)?;
    probe_expect_peer(
        harness,
        *client_port,
        IpAddr::V4(Ipv4Addr::new(10, 231, 2, 2)),
    )?;

    harness.set_stage("disabling chain proxy and restoring direct routing");
    run_menu(&expect_script, &ping_rust, "disable", None, None)?;
    probe_expect_peer(
        harness,
        *client_port,
        IpAddr::V4(Ipv4Addr::new(10, 231, 1, 1)),
    )?;

    harness.set_stage("deleting both chain nodes");
    run_menu(&expect_script, &ping_rust, "delete", Some("1"), None)?;
    run_menu(&expect_script, &ping_rust, "delete", Some("1"), None)?;
    harness.set_stage("rejecting reachable node with invalid credentials");
    run_menu(&expect_script, &ping_rust, "add", Some(&uri_invalid), None)?;
    run_menu_expect_failure(&expect_script, &ping_rust, "test", Some("1"), &success_url)?;
    harness.set_stage("removing invalid protocol node");
    run_menu(&expect_script, &ping_rust, "delete", Some("1"), None)?;
    assert_final_state()?;
    systemctl(&["restart", "shoes.service"], "final service restart")?;
    systemctl(
        &["is-active", "--quiet", "shoes.service"],
        "final active service check",
    )?;
    Ok(())
}

#[test]
#[ignore = "requires an ephemeral root Linux host with systemd and network namespaces"]
fn chain_systemd_acceptance() {
    if std::env::var_os("PING_RUST_CHAIN_SYSTEMD_E2E").as_deref() != Some(std::ffi::OsStr::new("1"))
    {
        panic!("set PING_RUST_CHAIN_SYSTEMD_E2E=1 to authorize destructive ephemeral-host testing");
    }
    let mut harness = Harness::new().expect("failed to create acceptance harness");
    if let Err(error) = run_acceptance(&mut harness) {
        harness.diagnostics();
        panic!("{error}");
    }
    eprintln!("chain systemd acceptance passed");
}
