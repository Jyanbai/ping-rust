use std::{collections::BTreeSet, fs, path::Path, process::Command, thread, time::Duration};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;

use crate::{installer, performance, utils};

pub const SERVICE_NAME: &str = "shoes.service";
const RESET_FAILED_COMMAND: &[&str] = &["reset-failed", SERVICE_NAME];
const ENABLE_NOW_COMMAND: &[&str] = &["enable", "--now", SERVICE_NAME];
const START_COMMAND: &[&str] = &["start", SERVICE_NAME];
const RESTART_COMMAND: &[&str] = &["restart", SERVICE_NAME];

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

const HOT_RELOAD_TIMEOUT: Duration = Duration::from_secs(6);
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
    })
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

pub fn capture_hot_reload_snapshot(
    snapshot: &ServiceSnapshot,
) -> Result<Option<HotReloadSnapshot>> {
    if !snapshot.was_active || snapshot.unit_contents.as_deref() != Some(unit_contents().as_bytes())
    {
        hot_reload_trace("service inactive or unit differs from managed unit");
        return Ok(None);
    }
    let shoes = installer::load_provenance();
    if shoes.source != "verified-pin"
        || shoes.revision.as_deref() != Some(installer::verified_pin())
    {
        hot_reload_trace("shoes verified-pin provenance unavailable");
        return Ok(None);
    }
    let drop_ins = systemctl_show_value("DropInPaths")?;
    if !drop_ins.is_empty() && drop_ins != "-" {
        hot_reload_trace("systemd unit has drop-ins");
        return Ok(None);
    }
    let main_pid = snapshot
        .main_pid
        .context("shoes.service active but MainPID is unavailable")?;
    utils::prepare_hot_reload_anchor(main_pid)?;
    let snapshot = HotReloadSnapshot {
        main_pid,
        listening_ports: listening_ports(main_pid)?,
    };
    hot_reload_trace(&format!(
        "candidate PID={} ports={:?}",
        snapshot.main_pid, snapshot.listening_ports
    ));
    Ok(Some(snapshot))
}

pub(crate) fn hot_reload_trace(message: &str) {
    if std::env::var_os("PING_RUST_HOT_RELOAD_TRACE").is_some() {
        eprintln!("hot reload: {message}");
    }
}

pub fn hot_reload_and_verify(
    snapshot: HotReloadSnapshot,
    expected_ports: &BTreeSet<u16>,
    removed_ports: &BTreeSet<u16>,
) -> Result<()> {
    hot_reload_trace(&format!(
        "trigger PID={} expected={expected_ports:?} removed={removed_ports:?}",
        snapshot.main_pid
    ));
    utils::notify_hot_reload_anchor()?;
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
            hot_reload_trace("verified listener delta");
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            hot_reload_trace(&format!("timeout current={ports:?}"));
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

fn listening_ports(pid: u32) -> Result<BTreeSet<u16>> {
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
    let mut ports = BTreeSet::new();
    for (name, tcp) in [
        ("tcp", true),
        ("tcp6", true),
        ("udp", false),
        ("udp6", false),
    ] {
        let path = format!("/proc/net/{name}");
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
    fn proc_net_parser_filters_pid_sockets_and_tcp_state() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n  0: 0100007F:1F90 00000000:0000 0A 00000000:0000 00:00000000 00000000   0        0 7001 1 0000000000000000 100 0 0 10 0\n  1: 0100007F:1F91 00000000:0000 01 00000000:0000 00:00000000 00000000   0        0 7002 1 0000000000000000 100 0 0 10 0\n";
        let ports = parse_proc_net_ports(table, &BTreeSet::from([7001, 7002]), true);
        assert_eq!(ports, BTreeSet::from([8080]));
    }
}
