use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    path::Path,
    process::Command,
    thread,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;

use crate::{installer, performance, utils};

pub const SERVICE_NAME: &str = "shoes.service";
const RESET_FAILED_COMMAND: &[&str] = &["reset-failed", SERVICE_NAME];
const ENABLE_NOW_COMMAND: &[&str] = &["enable", "--now", SERVICE_NAME];
const START_COMMAND: &[&str] = &["start", SERVICE_NAME];
const RESTART_COMMAND: &[&str] = &["restart", SERVICE_NAME];
const SHOES_V037_HOT_RELOAD_REVISION: &str = "ee44a397e6850193e86a1ae66639f037f963822d";

pub struct ServiceSnapshot {
    unit_contents: Option<Vec<u8>>,
    was_active: bool,
    was_enabled: bool,
    main_pid: Option<u32>,
}

impl ServiceSnapshot {
    pub fn was_active(&self) -> bool {
        self.was_active
    }
}

pub struct HotReloadSnapshot {
    pub main_pid: u32,
    pub listening_ports: BTreeSet<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HotReloadReason {
    ServiceNotRunning,
    UnitModified,
    ShoesSourceUnsupported(installer::ShoesProvenance),
    DropInPresent,
    ListenerSnapshotMismatch,
    InspectionFailed(String),
}

impl HotReloadReason {
    #[cfg(test)]
    pub fn restart_notice(&self) -> String {
        let reason = match self {
            Self::ServiceNotRunning => "shoes 服务未运行".to_owned(),
            Self::UnitModified => "shoes unit 内容或加载路径已被修改".to_owned(),
            Self::ShoesSourceUnsupported(shoes) if shoes.source == "github-release" => format!(
                "当前 shoes 来源为 GitHub Release {}，热重载需要固定 pin 构建",
                shoes.release_tag.as_deref().unwrap_or("（版本未知）")
            ),
            Self::ShoesSourceUnsupported(_) => {
                "shoes 来源或 revision 不满足固定 pin 验证要求".to_owned()
            }
            Self::DropInPresent => "shoes unit 存在 drop-in".to_owned(),
            Self::ListenerSnapshotMismatch => {
                "当前监听与受管配置不一致，无法验证监听变更".to_owned()
            }
            Self::InspectionFailed(error) => format!("热重载前置检查失败：{error}"),
        };
        let switch = if matches!(self, Self::ShoesSourceUnsupported(_)) {
            "可在 Update Center 中切换到固定 pin，或运行 sudo ping-rust update --method cargo；需要源码编译时间和足够内存。"
        } else {
            "请检查服务、unit 和日志中的热重载前置条件。"
        };
        format!("{reason}；本次使用受控重启。{switch}")
    }
}

pub enum HotReloadReadiness {
    Ready(HotReloadSnapshot),
    Unavailable(HotReloadReason),
}

impl HotReloadReadiness {
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    pub fn filter(self, predicate: impl FnOnce(&HotReloadSnapshot) -> bool) -> Self {
        match self {
            Self::Ready(snapshot) if !predicate(&snapshot) => {
                Self::Unavailable(HotReloadReason::ListenerSnapshotMismatch)
            }
            other => other,
        }
    }

    pub fn into_snapshot(self) -> Option<HotReloadSnapshot> {
        match self {
            Self::Ready(snapshot) => Some(snapshot),
            Self::Unavailable(_) => None,
        }
    }

    pub fn report_controlled_restart(&self, _was_active: bool) {
        if let Self::Unavailable(reason) = self {
            let _ = reason;
        }
        // Restart reasons remain available for diagnostics and decision tests.
    }
}

fn hot_reload_supported(shoes: &installer::ShoesProvenance) -> bool {
    shoes.source == "verified-pin"
        && shoes.revision.as_deref().is_some_and(|revision| {
            revision == installer::verified_pin() || revision == SHOES_V037_HOT_RELOAD_REVISION
        })
}

fn hot_reload_unavailable_reason(
    was_active: bool,
    unit_matches: bool,
    shoes: &installer::ShoesProvenance,
    drop_ins: &str,
) -> Option<HotReloadReason> {
    if !was_active {
        Some(HotReloadReason::ServiceNotRunning)
    } else if !unit_matches {
        Some(HotReloadReason::UnitModified)
    } else if !hot_reload_supported(shoes) {
        Some(HotReloadReason::ShoesSourceUnsupported(shoes.clone()))
    } else if !drop_ins.is_empty() && drop_ins != "-" {
        Some(HotReloadReason::DropInPresent)
    } else {
        None
    }
}

// shoes (v0.3.6 and v0.3.7, RELOAD_DEBOUNCE in src/process.rs) debounces
// parent-directory watcher events for five seconds.
const HOT_RELOAD_TIMEOUT: Duration = Duration::from_secs(10);
const HOT_RELOAD_POLL: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ServiceAction {
    Install,
    Start,
    Stop,
    Restart,
    Status,
    Enable,
    Disable,
}

pub fn unit_contents() -> String {
    format!(
        r#"[Unit]
Description=shoes proxy server managed by ping-rust
Documentation=https://github.com/cfal/shoes
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart={} {}
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ReadOnlyPaths={}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
"#,
        utils::SHOES_BIN,
        utils::CONFIG_FILE,
        utils::CONFIG_DIR
    )
}

pub fn install_unit(enable_now: bool) -> Result<()> {
    utils::require_linux_root()?;
    ensure_systemctl()?;
    let unit_exists = enable_now && Path::new(utils::SERVICE_FILE).exists();
    let was_active = unit_exists && systemctl_is_active()?;
    let was_failed = unit_exists && systemctl_is_failed()?;
    utils::atomic_write(
        Path::new(utils::SERVICE_FILE),
        unit_contents().as_bytes(),
        0o644,
    )?;
    systemctl(&["daemon-reload"])?;
    if enable_now {
        for command in activation_commands(was_active, was_failed) {
            systemctl(command)?;
        }
    }
    Ok(())
}

pub fn activate_and_verify() -> Result<()> {
    let _timer = performance::stage("systemd_activate");
    install_unit(true)?;
    verify_active_stable(systemctl_is_active, || {
        thread::sleep(Duration::from_millis(750))
    })
}

pub fn restart_and_verify() -> Result<()> {
    utils::require_linux_root()?;
    ensure_systemctl()?;
    systemctl_after_reset(RESTART_COMMAND)?;
    verify_active_stable(systemctl_is_active, || {
        thread::sleep(Duration::from_millis(750))
    })?;
    Ok(())
}

pub(crate) fn check_socks5_restart_scope() -> Result<()> {
    ensure_systemctl()?;
    if fs::read(utils::SERVICE_FILE).context("无法读取受管 shoes.service unit")?
        != unit_contents().as_bytes()
        || systemctl_show_value("FragmentPath")? != utils::SERVICE_FILE
        || !systemctl_show_value("DropInPaths")?.is_empty()
        || systemctl_show_value("NeedDaemonReload")? != "no"
    {
        bail!("SOCKS5 加固要求已加载的标准受管 shoes.service；请检查 unit、自定义 drop-in 或待重载配置");
    }
    check_restart_dependencies(systemctl_show_value)?;
    let pid = main_pid()?.context("shoes.service 缺少 MainPID")?;
    check_socks5_restart_executable(
        Path::new(&format!("/proc/{pid}/exe")),
        Path::new(utils::SHOES_BIN),
    )
}

fn check_restart_dependencies(
    mut property_value: impl FnMut(&str) -> Result<String>,
) -> Result<()> {
    // systemd 可在 unit 文件和 drop-in 之外添加 .requires / .wants 依赖。
    // 允许标准 unit 的网络和 PrivateTmp 依赖，以及 systemd 的默认依赖。
    let mounts = ["-.mount", "tmp.mount", "var.mount", "var-tmp.mount"];
    let requires = [mounts.as_slice(), &["sysinit.target", "system.slice"]].concat();
    let wants = [mounts.as_slice(), &["network-online.target"]].concat();
    for (property, allowed) in [
        ("Requires", requires.as_slice()),
        ("Wants", wants.as_slice()),
        ("Conflicts", &["shutdown.target"]),
        ("ConflictedBy", &["shutdown.target"]),
        ("RequiredBy", &[]),
        ("RequisiteOf", &[]),
        ("BindsTo", &[]),
        ("BoundBy", &[]),
        ("ConsistsOf", &[]),
        ("PropagatesStopTo", &[]),
        ("OnFailure", &[]),
        ("OnSuccess", &[]),
        ("TriggeredBy", &[]),
        ("Upholds", &[]),
        ("UpheldBy", &[]),
    ] {
        if property_value(property)?
            .split_whitespace()
            .any(|unit| !allowed.contains(&unit))
        {
            bail!("shoes.service 存在伴随服务或依赖关系（{property}），无法单独安全重启");
        }
    }
    Ok(())
}

fn verify_active_stable(
    mut probe: impl FnMut() -> Result<bool>,
    mut pause: impl FnMut(),
) -> Result<()> {
    if !probe()? {
        bail!("systemd 命令已返回成功，但 shoes.service 未处于 active 状态");
    }
    pause();
    if !probe()? {
        bail!("shoes.service 启动后未保持 active，可能已立即退出或进入自动重启");
    }
    Ok(())
}

pub fn capture_snapshot() -> Result<ServiceSnapshot> {
    utils::require_linux_root()?;
    ensure_systemctl()?;
    let path = Path::new(utils::SERVICE_FILE);
    let unit_contents = match fs::read(path) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("读取现有 systemd unit 失败"),
    };
    let unit_exists = unit_contents.is_some();
    let was_active = unit_exists && systemctl_is_active()?;
    Ok(ServiceSnapshot {
        unit_contents,
        was_active,
        was_enabled: unit_exists && systemctl_is_enabled()?,
        main_pid: was_active.then(main_pid).transpose()?.flatten(),
    })
}

pub fn capture_hot_reload_snapshot(snapshot: &ServiceSnapshot) -> Result<HotReloadReadiness> {
    if !snapshot.was_active {
        return Ok(HotReloadReadiness::Unavailable(
            HotReloadReason::ServiceNotRunning,
        ));
    }
    if snapshot.unit_contents.as_deref() != Some(unit_contents().as_bytes()) {
        return Ok(HotReloadReadiness::Unavailable(
            HotReloadReason::UnitModified,
        ));
    }
    if systemctl_show_value("FragmentPath")? != utils::SERVICE_FILE {
        return Ok(HotReloadReadiness::Unavailable(
            HotReloadReason::UnitModified,
        ));
    }
    let shoes = installer::load_provenance();
    let drop_ins = systemctl_show_value("DropInPaths")?;
    let reason = hot_reload_unavailable_reason(snapshot.was_active, true, &shoes, &drop_ins);
    if let Some(reason) = reason {
        return Ok(HotReloadReadiness::Unavailable(reason));
    }
    let main_pid = snapshot
        .main_pid
        .context("shoes.service active but MainPID is unavailable")?;
    if !same_executable(
        Path::new(&format!("/proc/{main_pid}/exe")),
        Path::new(utils::SHOES_BIN),
    )? {
        return Ok(HotReloadReadiness::Unavailable(
            HotReloadReason::InspectionFailed("运行中的 shoes 与已检测二进制不同".to_owned()),
        ));
    }
    let snapshot = HotReloadSnapshot {
        main_pid,
        listening_ports: listening_ports(main_pid)?,
    };
    Ok(HotReloadReadiness::Ready(snapshot))
}

// Atomic upgrades can leave a process running the unlinked old executable.
// Version/provenance for the on-disk file cannot establish that process's schema.
fn same_executable(running: &Path, installed: &Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let running = fs::metadata(running).context("无法检查运行中的 shoes 二进制")?;
        let installed = fs::metadata(installed).context("无法检查已安装 shoes 二进制")?;
        Ok(running.dev() == installed.dev() && running.ino() == installed.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = (running, installed);
        Ok(false)
    }
}

fn check_socks5_restart_executable(running: &Path, installed: &Path) -> Result<()> {
    let advice = "无法确认运行中的 shoes 与磁盘上的二进制一致；请先重启服务或完成升级";
    let target = fs::read_link(running).context(advice)?;
    let target = target.as_os_str().as_encoded_bytes();
    if target.ends_with(b" (deleted)") || !same_executable(running, installed).context(advice)? {
        bail!("{advice}");
    }
    Ok(())
}

pub fn hot_reload_and_verify(
    snapshot: HotReloadSnapshot,
    expected_ports: &BTreeSet<u16>,
    removed_ports: &BTreeSet<u16>,
) -> Result<()> {
    let deadline = std::time::Instant::now() + HOT_RELOAD_TIMEOUT;
    loop {
        let active = systemctl_is_active()?;
        let current_pid = main_pid()?.unwrap_or(0);
        let ports = if active && current_pid == snapshot.main_pid {
            listening_ports(current_pid)?
        } else {
            BTreeSet::new()
        };
        if reload_observation(
            snapshot.main_pid,
            current_pid,
            active,
            &ports,
            expected_ports,
            removed_ports,
        )? {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "shoes 热重载未在 {:?} 内达到预期监听端口；当前={ports:?}，期望新增={expected_ports:?}，期望删除={removed_ports:?}",
                HOT_RELOAD_TIMEOUT
            );
        }
        thread::sleep(HOT_RELOAD_POLL);
    }
}

fn reload_observation(
    original_pid: u32,
    current_pid: u32,
    active: bool,
    ports: &BTreeSet<u16>,
    expected_ports: &BTreeSet<u16>,
    removed_ports: &BTreeSet<u16>,
) -> Result<bool> {
    if !active || current_pid == 0 {
        bail!("shoes 热重载后服务未保持 active");
    }
    if current_pid != original_pid {
        bail!(
            "shoes 热重载触发了进程重启（旧 MainPID={}，新 MainPID={}）",
            original_pid,
            current_pid
        );
    }
    Ok(expected_ports.is_subset(ports) && removed_ports.is_disjoint(ports))
}

pub fn main_pid() -> Result<Option<u32>> {
    let value = systemctl_show_value("MainPID")?;
    let pid = value
        .parse::<u32>()
        .with_context(|| format!("systemd 返回了无效 MainPID：{value}"))?;
    Ok((pid != 0).then_some(pid))
}

fn systemctl_show_value(property: &str) -> Result<String> {
    let output = Command::new("systemctl")
        .args([
            "show",
            &format!("--property={property}"),
            "--value",
            SERVICE_NAME,
        ])
        .output()
        .with_context(|| format!("无法查询 shoes.service {property}"))?;
    if !output.status.success() {
        bail!(
            "查询 shoes.service {property} 失败（退出码：{}）",
            output.status
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn process_socket_inodes(pid: u32) -> Result<BTreeSet<u64>> {
    let fd_dir = format!("/proc/{pid}/fd");
    let mut socket_inodes = BTreeSet::new();
    for entry in fs::read_dir(&fd_dir).with_context(|| format!("读取 {fd_dir} 失败"))? {
        let entry = entry?;
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("读取 shoes socket fd 失败"),
        };
        if let Some(inode) = target
            .to_string_lossy()
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<u64>().ok())
        {
            socket_inodes.insert(inode);
        }
    }
    Ok(socket_inodes)
}

pub(crate) fn has_exclusive_tcp_listener(pid: u32, expected: SocketAddr) -> Result<bool> {
    let socket_inodes = process_socket_inodes(pid)?;
    let (tcp, tcp6) = read_tcp_listener_tables(pid)?;
    tcp_listeners_match(&tcp, &tcp6, &socket_inodes, expected)
}

pub(crate) fn tcp_listener_available_after_restart(pid: u32, expected: SocketAddr) -> Result<bool> {
    let socket_inodes = process_socket_inodes(pid)?;
    let (tcp, tcp6) = read_tcp_listener_tables(pid)?;
    check_tcp_listeners(
        &tcp,
        &tcp6,
        &socket_inodes,
        expected,
        TcpListenerCheck::AfterRestart,
    )
}

fn read_tcp_listener_tables(pid: u32) -> Result<(String, String)> {
    // Both tables list all sockets in the process's network namespace. The fd
    // inodes identify the ones held by the target process.
    let tcp_path = format!("/proc/{pid}/net/tcp");
    let tcp = fs::read_to_string(&tcp_path).with_context(|| format!("读取 {tcp_path} 失败"))?;
    let tcp6_path = format!("/proc/{pid}/net/tcp6");
    let tcp6 = match fs::read_to_string(&tcp6_path) {
        // Linux without IPv6 support does not expose this table.
        Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
        result => result.with_context(|| format!("读取 {tcp6_path} 失败"))?,
    };
    Ok((tcp, tcp6))
}

fn tcp_listeners_match(
    tcp: &str,
    tcp6: &str,
    socket_inodes: &BTreeSet<u64>,
    expected: SocketAddr,
) -> Result<bool> {
    check_tcp_listeners(
        tcp,
        tcp6,
        socket_inodes,
        expected,
        TcpListenerCheck::Exclusive,
    )
}

enum TcpListenerCheck {
    Exclusive,
    AfterRestart,
}

fn check_tcp_listeners(
    tcp: &str,
    tcp6: &str,
    socket_inodes: &BTreeSet<u64>,
    expected: SocketAddr,
    check: TcpListenerCheck,
) -> Result<bool> {
    let after_restart = matches!(check, TcpListenerCheck::AfterRestart);
    let expected_ip = match expected.ip() {
        IpAddr::V4(ip) => format!("{:08X}", u32::from_ne_bytes(ip.octets())),
        IpAddr::V6(ip) => {
            // /proc prints each 32-bit word in host byte order.
            let mut address = String::with_capacity(32);
            for &bytes in ip.octets().as_chunks::<4>().0 {
                let word = u32::from_ne_bytes(bytes);
                write!(address, "{word:08X}").unwrap();
            }
            address
        }
    };
    let expected_port = format!("{:04X}", expected.port());
    let mapped_word = u32::from_ne_bytes([0, 0, 255, 255]);
    let ipv4_mapped_prefix = format!("0000000000000000{mapped_word:08X}");
    let ipv4_mapped_wildcard = format!("{ipv4_mapped_prefix}00000000");
    let is_wildcard = |ip: &str| {
        matches!(ip, "*" | "00000000" | "00000000000000000000000000000000")
            || ip == ipv4_mapped_wildcard
    };
    let expected_is_wildcard = is_wildcard(&expected_ip);
    let expected_is_mapped = expected_ip.starts_with(&ipv4_mapped_prefix);
    let mut found = false;
    for line in tcp.lines().skip(1).chain(tcp6.lines().skip(1)) {
        let columns: Vec<_> = line.split_whitespace().collect();
        if *columns.get(3).context("TCP 监听表缺少状态")? != "0A" {
            continue;
        }
        let (ip, port) = columns[1].split_once(':').context("TCP 监听地址无效")?;
        if port != expected_port {
            continue;
        }
        let inode = columns
            .get(9)
            .context("TCP 监听表缺少 socket inode")?
            .parse::<u64>()
            .context("TCP 监听的 socket inode 无效")?;
        let owned = socket_inodes.contains(&inode);
        if owned && after_restart {
            continue;
        }
        let is_mapped = ip.starts_with(&ipv4_mapped_prefix);
        let wildcard = is_wildcard(ip);
        // A foreign native IPv6 bind cannot serve IPv4. An IPv6 wildcard may
        // be dual-stack, and /proc does not report IPV6_V6ONLY.
        if !owned && expected.is_ipv4() && ip.len() == 32 && !wildcard && !is_mapped {
            continue;
        }
        if !owned
            && ip != expected_ip
            && ip.len() == expected_ip.len()
            && is_mapped == expected_is_mapped
            && !wildcard
            && !expected_is_wildcard
        {
            continue;
        }
        if ip != expected_ip || !owned {
            return Ok(false);
        }
        found = true;
    }
    Ok(found || after_restart)
}

fn listening_ports(pid: u32) -> Result<BTreeSet<u16>> {
    let socket_inodes = process_socket_inodes(pid)?;
    let mut ports = BTreeSet::new();
    for (name, tcp) in [
        ("tcp", true),
        ("tcp6", true),
        ("udp", false),
        ("udp6", false),
    ] {
        let path = format!("/proc/{pid}/net/{name}");
        let table = fs::read_to_string(&path).with_context(|| format!("读取 {path} 失败"))?;
        ports.extend(parse_proc_net_ports(&table, &socket_inodes, tcp));
    }
    Ok(ports)
}

fn parse_proc_net_ports(table: &str, socket_inodes: &BTreeSet<u64>, tcp: bool) -> BTreeSet<u16> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let columns = line.split_whitespace().collect::<Vec<_>>();
            let local = *columns.get(1)?;
            let state = *columns.get(3)?;
            let inode = columns.get(9)?.parse::<u64>().ok()?;
            if !socket_inodes.contains(&inode) || (tcp && state != "0A") {
                return None;
            }
            let port = local.rsplit_once(':')?.1;
            u16::from_str_radix(port, 16).ok()
        })
        .collect()
}

pub fn restore_snapshot(snapshot: ServiceSnapshot) -> Result<()> {
    utils::require_linux_root()?;
    ensure_systemctl()?;
    let path = Path::new(utils::SERVICE_FILE);
    if path.exists() {
        let _ = Command::new("systemctl")
            .args(["disable", "--now", SERVICE_NAME])
            .status();
    }
    if let Some(contents) = snapshot.unit_contents {
        utils::atomic_write(path, &contents, 0o644)?;
    } else if path.exists() {
        fs::remove_file(path).context("删除回滚 systemd unit 失败")?;
    }
    systemctl(&["daemon-reload"])?;

    if path.exists() {
        if snapshot.was_enabled {
            systemctl(&["enable", SERVICE_NAME])?;
        } else {
            let _ = Command::new("systemctl")
                .args(["disable", SERVICE_NAME])
                .status();
        }
        if snapshot.was_active {
            systemctl_after_reset(START_COMMAND)?;
            verify_active_stable(systemctl_is_active, || {
                thread::sleep(Duration::from_millis(750))
            })?;
        } else {
            let _ = Command::new("systemctl")
                .args(["stop", SERVICE_NAME])
                .status();
        }
    }
    Ok(())
}

fn activation_commands(was_active: bool, was_failed: bool) -> Vec<&'static [&'static str]> {
    let mut commands = Vec::with_capacity(3);
    if was_active || was_failed {
        commands.push(RESET_FAILED_COMMAND);
    }
    commands.push(ENABLE_NOW_COMMAND);
    if was_active {
        commands.push(RESTART_COMMAND);
    }
    commands
}

pub fn execute(action: ServiceAction) -> Result<()> {
    utils::require_linux_root()?;
    ensure_systemctl()?;
    match action {
        ServiceAction::Install => install_unit(false),
        ServiceAction::Start => systemctl_after_reset(START_COMMAND),
        ServiceAction::Stop => systemctl(&["stop", SERVICE_NAME]),
        ServiceAction::Restart => systemctl_after_reset(RESTART_COMMAND),
        ServiceAction::Status => systemctl(&["status", "--no-pager", SERVICE_NAME]),
        ServiceAction::Enable => systemctl_after_reset(ENABLE_NOW_COMMAND),
        ServiceAction::Disable => systemctl(&["disable", "--now", SERVICE_NAME]),
    }
}

fn systemctl_after_reset(command: &[&str]) -> Result<()> {
    if systemctl_is_active()? || systemctl_is_failed()? {
        systemctl(RESET_FAILED_COMMAND)?;
    }
    systemctl(command)
}

pub fn logs(lines: usize) -> Result<()> {
    utils::require_linux()?;
    let status = Command::new("journalctl")
        .args(["-u", SERVICE_NAME, "--no-pager", "-n", &lines.to_string()])
        .status()
        .context("无法执行 journalctl")?;
    if !status.success() {
        bail!("journalctl 执行失败（退出码：{status}）");
    }
    Ok(())
}

pub fn uninstall_unit() -> Result<bool> {
    utils::require_linux_root()?;
    ensure_systemctl()?;
    let path = Path::new(utils::SERVICE_FILE);
    if !path.exists() {
        return Ok(false);
    }

    systemctl(&["disable", "--now", SERVICE_NAME])?;
    fs::remove_file(path).context("删除 systemd unit 失败")?;
    systemctl(&["daemon-reload"])?;
    Ok(true)
}

pub fn is_active() -> Result<bool> {
    utils::require_linux()?;
    ensure_systemctl()?;
    systemctl_is_active()
}

fn systemctl_is_active() -> Result<bool> {
    Ok(Command::new("systemctl")
        .args(["is-active", "--quiet", SERVICE_NAME])
        .status()
        .context("无法查询 systemd 服务状态")?
        .success())
}

fn systemctl_is_failed() -> Result<bool> {
    Ok(Command::new("systemctl")
        .args(["is-failed", "--quiet", SERVICE_NAME])
        .status()
        .context("无法查询 systemd 服务失败状态")?
        .success())
}

fn systemctl_is_enabled() -> Result<bool> {
    Ok(Command::new("systemctl")
        .args(["is-enabled", "--quiet", SERVICE_NAME])
        .status()
        .context("无法查询 systemd 服务启用状态")?
        .success())
}

fn systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("无法执行 systemctl {}", args.join(" ")))?;
    if !status.success() {
        bail!("systemctl {} 失败（退出码：{status}）", args.join(" "));
    }
    Ok(())
}

fn ensure_systemctl() -> Result<()> {
    if !utils::command_exists("systemctl") {
        bail!("未找到 systemctl；当前系统可能未使用 systemd");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn socks5_restart_rejects_replaced_or_deleted_executable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let installed = path.join("shoes");
        let script = path.join("hold.sh");
        fs::write(&script, "read -r line || :\n").unwrap();
        let mut child = Command::new("/bin/sh")
            .arg(&script)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let executable = std::path::PathBuf::from(format!("/proc/{}/exe", child.id()));
        // spawn 返回时 /proc/<pid>/exe 偶尔还没指向 sh（#164），等它稳定后再比较，
        // 断言本身不放宽：超时仍不是系统 sh 就失败。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let uses_system_shell = loop {
            let same = same_executable(&executable, Path::new("/bin/sh"));
            if matches!(same, Ok(true)) || std::time::Instant::now() >= deadline {
                break same;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let shell = fs::read_link(&executable).unwrap();
        std::os::unix::fs::symlink(&shell, &installed).unwrap();
        let matched = check_socks5_restart_executable(&executable, &installed);
        fs::remove_file(&installed).unwrap();
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &installed).unwrap();
        let replaced = check_socks5_restart_executable(&executable, &installed);
        fs::remove_file(&installed).unwrap();
        std::os::unix::fs::symlink(&shell, &installed).unwrap();
        let deleted_target = path.join("running (deleted)");
        std::os::unix::fs::symlink(&executable, &deleted_target).unwrap();
        let deleted_link = path.join("proc-exe");
        std::os::unix::fs::symlink(&deleted_target, &deleted_link).unwrap();
        let deleted = check_socks5_restart_executable(&deleted_link, &installed);
        let same_inode = same_executable(&deleted_link, &installed);
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        assert!(
            uses_system_shell.unwrap(),
            "测试必须直接由系统 sh 执行脚本，实际为 {}",
            shell.display()
        );
        assert!(same_inode.unwrap());
        matched.unwrap();
        for result in [replaced, deleted] {
            assert!(format!("{:#}", result.unwrap_err()).contains("先重启服务或完成升级"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn replaced_binary_cannot_prove_running_process_compatibility() {
        let directory = tempfile::tempdir().unwrap();
        let installed = directory.path().join("shoes");
        let running = directory.path().join("running-executable");
        fs::write(&installed, b"old kernel").unwrap();
        fs::hard_link(&installed, &running).unwrap();
        assert!(same_executable(&running, &installed).unwrap());
        let replacement = directory.path().join("new-shoes");
        fs::write(&replacement, b"new kernel").unwrap();
        fs::rename(&replacement, &installed).unwrap();
        assert!(!same_executable(&running, &installed).unwrap());
    }

    #[test]
    fn complete_release_metadata_does_not_change_existing_protocol_restart_policy() {
        let release = installer::ShoesProvenance {
            source: "github-release".into(),
            release_tag: Some("v0.3.6".into()),
            version: Some("0.3.6".into()),
            binary_sha256: Some("a".repeat(64)),
            ..Default::default()
        };
        assert!(matches!(
            hot_reload_unavailable_reason(true, true, &release, ""),
            Some(HotReloadReason::ShoesSourceUnsupported(_))
        ));
    }

    #[test]
    fn adding_vless_enc_release_requires_controlled_restart_even_with_complete_metadata() {
        let mut release = installer::ShoesProvenance {
            source: "github-release".into(),
            release_tag: Some("v0.3.6".into()),
            version: Some("0.3.6".into()),
            binary_sha256: Some("a".repeat(64)),
            ..Default::default()
        };
        assert!(matches!(
            hot_reload_unavailable_reason(true, true, &release, ""),
            Some(HotReloadReason::ShoesSourceUnsupported(_))
        ));
        release.release_tag = Some("v0.3.7".into());
        assert!(matches!(
            hot_reload_unavailable_reason(true, true, &release, ""),
            Some(HotReloadReason::ShoesSourceUnsupported(_))
        ));
        release.release_tag = Some(installer::SHOES_RELEASE_TAG.into());
        release.version = Some(installer::SHOES_RELEASE_TAG.trim_start_matches('v').into());
        assert!(matches!(
            hot_reload_unavailable_reason(true, true, &release, ""),
            Some(HotReloadReason::ShoesSourceUnsupported(_))
        ));
        release.release_tag = Some("v0.3.6".into());
        release.version = Some("0.3.6".into());
        release.binary_sha256 = None;
        assert!(matches!(
            hot_reload_unavailable_reason(true, true, &release, ""),
            Some(HotReloadReason::ShoesSourceUnsupported(_))
        ));
    }

    fn pin_provenance() -> installer::ShoesProvenance {
        installer::ShoesProvenance {
            source: "verified-pin".into(),
            revision: Some(installer::verified_pin().into()),
            ..Default::default()
        }
    }

    #[test]
    fn hot_reload_remains_available_for_v037_source_pin_after_manager_update() {
        let previous_pin = installer::ShoesProvenance {
            source: "verified-pin".into(),
            version: Some("0.3.7".into()),
            revision: Some("ee44a397e6850193e86a1ae66639f037f963822d".into()),
            binary_sha256: Some("a".repeat(64)),
            ..Default::default()
        };
        assert_eq!(
            hot_reload_unavailable_reason(true, true, &previous_pin, ""),
            None
        );

        let release = installer::ShoesProvenance {
            source: "github-release".into(),
            release_tag: Some("v0.3.7".into()),
            ..previous_pin
        };
        assert_eq!(
            hot_reload_unavailable_reason(true, true, &release, ""),
            Some(HotReloadReason::ShoesSourceUnsupported(release))
        );
    }

    #[test]
    fn hot_reload_reason_service_not_running() {
        assert_eq!(
            hot_reload_unavailable_reason(false, true, &pin_provenance(), ""),
            Some(HotReloadReason::ServiceNotRunning)
        );
    }

    #[test]
    fn hot_reload_reason_modified_unit() {
        assert_eq!(
            hot_reload_unavailable_reason(true, false, &pin_provenance(), ""),
            Some(HotReloadReason::UnitModified)
        );
    }

    #[test]
    fn hot_reload_reason_release_and_wrong_pin_remain_ineligible() {
        let release = installer::ShoesProvenance {
            source: "github-release".into(),
            release_tag: Some("v0.3.6".into()),
            ..Default::default()
        };
        assert_eq!(
            hot_reload_unavailable_reason(true, true, &release, ""),
            Some(HotReloadReason::ShoesSourceUnsupported(release))
        );
        let mut wrong_pin = pin_provenance();
        wrong_pin.revision = Some("different-revision".into());
        assert!(matches!(
            hot_reload_unavailable_reason(true, true, &wrong_pin, ""),
            Some(HotReloadReason::ShoesSourceUnsupported(_))
        ));
    }

    #[test]
    fn hot_reload_reason_drop_in() {
        assert_eq!(
            hot_reload_unavailable_reason(true, true, &pin_provenance(), "override.conf"),
            Some(HotReloadReason::DropInPresent)
        );
    }

    #[test]
    fn hot_reload_release_fallback_explains_source_and_switch() {
        let reason = HotReloadReason::ShoesSourceUnsupported(installer::ShoesProvenance {
            source: "github-release".into(),
            release_tag: Some("v0.3.6".into()),
            ..Default::default()
        });
        let message = reason.restart_notice();
        for expected in [
            "GitHub Release v0.3.6",
            "固定 pin",
            "受控重启",
            "Update Center",
            "update --method cargo",
        ] {
            assert!(message.contains(expected), "missing {expected}: {message}");
        }
    }

    #[test]
    fn unit_uses_expected_paths_and_hardening() {
        let unit = unit_contents();
        assert_eq!(
            unit,
            include_str!("../systemd/ping-rust.service").replace("\r\n", "\n")
        );
        assert!(unit.contains("ExecStart=/usr/local/bin/shoes /etc/shoes/config.yaml"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("ProtectControlGroups=true"));
        assert!(unit.contains("ProtectKernelModules=true"));
        assert!(unit.contains("ProtectKernelTunables=true"));
        assert!(unit.contains("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"));
        assert!(unit.contains("RestrictSUIDSGID=true"));
        assert!(unit.contains("LockPersonality=true"));
        assert!(unit.contains("MemoryDenyWriteExecute=true"));
        assert!(unit.contains("SystemCallArchitectures=native"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn activation_commands_cover_new_active_and_failed_units() {
        assert_eq!(activation_commands(false, false), vec![ENABLE_NOW_COMMAND]);
        assert_eq!(
            activation_commands(true, false),
            vec![RESET_FAILED_COMMAND, ENABLE_NOW_COMMAND, RESTART_COMMAND]
        );
        assert_eq!(
            activation_commands(false, true),
            vec![RESET_FAILED_COMMAND, ENABLE_NOW_COMMAND]
        );
    }

    #[test]
    fn stable_activation_requires_two_successful_probes() {
        let mut samples = [true, true].into_iter();
        verify_active_stable(|| Ok(samples.next().unwrap()), || {}).unwrap();

        let mut samples = [true, false].into_iter();
        assert!(verify_active_stable(|| Ok(samples.next().unwrap()), || {}).is_err());
    }

    #[test]
    fn hot_reload_requires_same_pid_and_exact_listener_delta() {
        let expected = BTreeSet::from([1001, 1003]);
        let removed = BTreeSet::from([1002]);
        assert!(reload_observation(42, 42, true, &expected, &expected, &removed).unwrap());
        assert!(!reload_observation(
            42,
            42,
            true,
            &BTreeSet::from([1001, 1002]),
            &expected,
            &removed
        )
        .unwrap());
        assert!(!reload_observation(
            42,
            42,
            true,
            &BTreeSet::from([1001, 1002, 1003]),
            &expected,
            &removed
        )
        .unwrap());
        assert!(reload_observation(42, 43, true, &expected, &expected, &removed).is_err());
        assert!(reload_observation(42, 0, false, &expected, &expected, &removed).is_err());
    }

    #[test]
    fn hot_reload_timeout_covers_shoes_v036_debounce_window() {
        // shoes v0.3.6/v0.3.7 use a five-second quiet period for parent-directory events.
        assert!(HOT_RELOAD_TIMEOUT > Duration::from_secs(5));
    }

    #[test]
    fn proc_net_parser_filters_pid_sockets_and_tcp_state() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n  0: 0100007F:1F90 00000000:0000 0A 00000000:0000 00:00000000 00000000   0        0 7001 1 0000000000000000 100 0 0 10 0\n  1: 0100007F:1F91 00000000:0000 01 00000000:0000 00:00000000 00000000   0        0 7002 1 0000000000000000 100 0 0 10 0\n";
        let ports = parse_proc_net_ports(table, &BTreeSet::from([7001, 7002]), true);
        assert_eq!(ports, BTreeSet::from([8080]));
    }

    #[test]
    fn proc_net_requires_the_exact_tcp_listener_and_owner() {
        let header = "sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode";
        let row = |address: &str, port, state, inode| {
            format!("0: {address}:{port:04X} 00000000:0000 {state} 0:0 0:0 0 0 0 {inode}")
        };
        let loopback = format!("{:08X}", u32::from_ne_bytes([127, 0, 0, 1]));
        let public = format!("{:08X}", u32::from_ne_bytes([203, 0, 113, 8]));
        let ipv6_loopback = format!("{:032X}", u32::from_ne_bytes([0, 0, 0, 1]));
        let ipv6_wildcard = "00000000000000000000000000000000";
        let inodes = BTreeSet::from([7001]);
        let expected = "127.0.0.1:1080".parse().unwrap();
        let good = row(&loopback, 1080, "0A", 7001);
        let established = row(&public, 1080, "01", 7002);
        let other_port = row(&public, 1081, "0A", 7002);
        let wrong_owner = row(&loopback, 1080, "0A", 7002);
        let wrong_address = row(&public, 1080, "0A", 7001);
        let wildcard = row(ipv6_wildcard, 1080, "0A", 7001);
        let loopback6 = row(&ipv6_loopback, 1080, "0A", 7001);
        let tcp = format!("{header}\n{good}\n{established}\n{other_port}");
        assert!(tcp_listeners_match(&tcp, header, &inodes, expected).unwrap());
        for bad in [&wrong_owner, &wrong_address] {
            assert!(
                !tcp_listeners_match(&format!("{tcp}\n{bad}"), header, &inodes, expected).unwrap()
            );
        }
        assert!(
            !tcp_listeners_match(&tcp, &format!("{header}\n{wildcard}"), &inodes, expected)
                .unwrap()
        );
        assert!(!tcp_listeners_match(
            &format!("{header}\n{established}\n{other_port}"),
            header,
            &inodes,
            expected
        )
        .unwrap());
        for (row, expected) in [(wildcard, "[::]:1080"), (loopback6, "[::1]:1080")] {
            assert!(tcp_listeners_match(
                header,
                &format!("{header}\n{row}"),
                &inodes,
                expected.parse().unwrap()
            )
            .unwrap());
        }
    }

    #[test]
    fn proc_net_only_rejects_overlapping_foreign_listeners_in_the_same_family() {
        let header = "sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode";
        let row =
            |ip: &str, inode| format!("\n0: {ip}:0438 00000000:0000 0A 0:0 0:0 0 0 0 {inode}");
        let address4 = |octets| format!("{:08X}", u32::from_ne_bytes(octets));
        let address6 = |last| {
            format!(
                "{}0000000000000000{}",
                address4([0x20, 1, 0x0d, 0xb8]),
                address4(last)
            )
        };
        let mapped = |octets| {
            format!(
                "0000000000000000{}{}",
                address4([0, 0, 255, 255]),
                address4(octets)
            )
        };
        let inodes = BTreeSet::from([7001]);
        for (expected, any, local, disjoint, wildcard) in [
            (
                "203.0.113.8:1080",
                "0.0.0.0:1080",
                address4([203, 0, 113, 8]),
                address4([127, 0, 0, 2]),
                "00000000".to_string(),
            ),
            (
                "[2001:db8::8]:1080",
                "[::]:1080",
                address6([0, 0, 0, 8]),
                address6([0, 0, 0, 9]),
                "00000000000000000000000000000000".to_string(),
            ),
            (
                "[::ffff:203.0.113.8]:1080",
                "[::ffff:0.0.0.0]:1080",
                mapped([203, 0, 113, 8]),
                mapped([127, 0, 0, 2]),
                mapped([0, 0, 0, 0]),
            ),
        ] {
            let matches = |rows: String, expected: &str| {
                let table = format!("{header}{rows}");
                let (tcp, tcp6) = if local.len() == 8 {
                    (table.as_str(), header)
                } else {
                    (header, table.as_str())
                };
                tcp_listeners_match(tcp, tcp6, &inodes, expected.parse().unwrap()).unwrap()
            };
            assert!(
                matches(row(&local, 7001) + &row(&disjoint, 7002), expected),
                "{expected}: 外部不相交的监听不应冲突"
            );
            assert!(!matches(row(&disjoint, 7002), expected));
            for overlapping in [local.as_str(), wildcard.as_str(), "*"] {
                assert!(!matches(
                    row(&local, 7001) + &row(overlapping, 7002),
                    expected
                ));
            }
            assert!(!matches(row(&wildcard, 7001) + &row(&local, 7002), any));
        }
    }

    #[test]
    fn proc_net_rejects_occupied_candidate_loopback_before_restart() {
        let header = "sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode";
        let row = |octets, inode| {
            let ip = u32::from_ne_bytes(octets);
            format!("\n0: {ip:08X}:0438 00000000:0000 0A 0:0 0:0 0 0 0 {inode}")
        };
        let inodes = BTreeSet::from([7001]);
        let target = "127.0.0.1:1080".parse().unwrap();
        let available = |tcp: &str| {
            check_tcp_listeners(tcp, header, &inodes, target, TcpListenerCheck::AfterRestart)
                .unwrap()
        };

        let original = format!("{header}{}", row([203, 0, 113, 8], 7001));
        let occupied = format!("{original}{}", row([127, 0, 0, 1], 7002));
        assert!(tcp_listeners_match(
            &occupied,
            header,
            &inodes,
            "203.0.113.8:1080".parse().unwrap(),
        )
        .unwrap());
        assert!(!available(&occupied));
        assert!(available(&original));

        let wildcard = format!("{header}{}", row([0, 0, 0, 0], 7001));
        assert!(available(&wildcard));
        let foreign_wildcard = format!("{original}{}", row([0, 0, 0, 0], 7002));
        assert!(!available(&foreign_wildcard));
    }

    #[test]
    fn proc_net_ignores_unrelated_native_ipv6_for_ipv4_socks5() {
        let header = "sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode";
        let address6 = |word, last| format!("0000000000000000{word:08X}{last:08X}");
        let ipv6_loopback = address6(0u32, u32::from_ne_bytes([0, 0, 0, 1]));
        let ipv6_mapped = address6(
            u32::from_ne_bytes([0, 0, 255, 255]),
            u32::from_ne_bytes([127, 0, 0, 1]),
        );
        let ipv6_wildcard = address6(0, 0);
        let row = |ip: &str, inode| {
            format!("{header}\n0: {ip}:0438 00000000:0000 0A 0:0 0:0 0 0 0 {inode}")
        };
        let inodes = BTreeSet::from([7001]);
        for (octets, expected) in [
            ([0, 0, 0, 0], "0.0.0.0:1080"),
            ([127, 0, 0, 1], "127.0.0.1:1080"),
        ] {
            let expected = expected.parse().unwrap();
            let tcp = row(&format!("{:08X}", u32::from_ne_bytes(octets)), 7001);
            assert!(
                tcp_listeners_match(&tcp, &row(&ipv6_loopback, 7002), &inodes, expected).unwrap()
            );
            for ambiguous in [&ipv6_mapped, &ipv6_wildcard] {
                assert!(
                    !tcp_listeners_match(&tcp, &row(ambiguous, 7002), &inodes, expected).unwrap()
                );
            }
            assert!(
                !tcp_listeners_match(&tcp, &row(&ipv6_loopback, 7001), &inodes, expected).unwrap()
            );
        }
    }

    #[test]
    fn socks5_restart_allows_default_dependencies_and_rejects_companion_units() {
        let defaults = |property: &str| match property {
            "Requires" => "sysinit.target system.slice -.mount",
            "Wants" => "network-online.target tmp.mount",
            "Conflicts" => "shutdown.target",
            _ => "",
        };
        check_restart_dependencies(|property| Ok(defaults(property).to_owned())).unwrap();
        for property in ["RequiredBy", "PropagatesStopTo", "OnFailure", "Wants"] {
            let error = check_restart_dependencies(|queried| {
                if queried == property {
                    Ok(format!("{} companion.service", defaults(queried)))
                } else {
                    Ok(defaults(queried).to_owned())
                }
            })
            .unwrap_err();
            assert!(error.to_string().contains(property));
        }
    }
}
