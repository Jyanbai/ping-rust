use std::{collections::BTreeSet, fs, path::Path, process::Command, thread, time::Duration};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;

use crate::{installer, performance, utils};

pub const SERVICE_NAME: &str = "shoes.service";
const RESET_FAILED_COMMAND: &[&str] = &["reset-failed", SERVICE_NAME];
const ENABLE_NOW_COMMAND: &[&str] = &["enable", "--now", SERVICE_NAME];
const START_COMMAND: &[&str] = &["start", SERVICE_NAME];
const RESTART_COMMAND: &[&str] = &["restart", SERVICE_NAME];
const SECURE_JOB_TIMEOUT: Duration = Duration::from_secs(120);
const SECURE_QUERY_TIMEOUT: Duration = Duration::from_secs(15);

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
    shoes.source == "verified-pin" && shoes.revision.as_deref() == Some(installer::verified_pin())
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
    Systemctl::Foreground.restart_and_verify()
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
    capture_snapshot_with(
        Path::new(utils::SERVICE_FILE),
        systemctl_is_active,
        systemctl_is_enabled,
        main_pid,
    )
}

fn capture_snapshot_with(
    path: &Path,
    is_active: impl FnOnce() -> Result<bool>,
    is_enabled: impl FnOnce() -> Result<bool>,
    main_pid: impl FnOnce() -> Result<Option<u32>>,
) -> Result<ServiceSnapshot> {
    let unit_contents = match fs::read(path) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("读取现有 systemd unit 失败"),
    };
    // systemd 可以从其他搜索路径加载同名 unit。
    let was_active = is_active()?;
    Ok(ServiceSnapshot {
        unit_contents,
        was_active,
        was_enabled: is_enabled()?,
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
    Systemctl::Foreground.main_pid()
}

fn systemctl_show_value(property: &str) -> Result<String> {
    Systemctl::Foreground.show_value(property)
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
    restore_snapshot_with(
        snapshot,
        Path::new(utils::SERVICE_FILE),
        systemctl,
        systemctl_is_active,
        systemctl_is_enabled,
        || thread::sleep(Duration::from_millis(750)),
    )
}

fn restore_snapshot_with(
    snapshot: ServiceSnapshot,
    path: &Path,
    mut run: impl FnMut(&[&str]) -> Result<()>,
    mut is_active: impl FnMut() -> Result<bool>,
    is_enabled: impl FnOnce() -> Result<bool>,
    pause: impl FnMut(),
) -> Result<()> {
    if path.exists() {
        let _ = run(&["disable", "--now", SERVICE_NAME]);
    }
    if let Some(contents) = snapshot.unit_contents {
        utils::atomic_write(path, &contents, 0o644)?;
    } else if path.exists() {
        fs::remove_file(path).context("删除回滚 systemd unit 失败")?;
    }
    run(&["daemon-reload"])?;

    let enablement = is_enabled().and_then(|enabled| {
        if enabled != snapshot.was_enabled {
            let action = if snapshot.was_enabled {
                "enable"
            } else {
                "disable"
            };
            run(&[action, SERVICE_NAME])?;
        }
        Ok(())
    });
    let active = is_active()?;
    if snapshot.was_active {
        let _ = run(RESET_FAILED_COMMAND);
        // 当前进程可能仍在使用加固后的配置，需重启以加载已恢复的文件。
        run(if active {
            RESTART_COMMAND
        } else {
            START_COMMAND
        })?;
        verify_active_stable(is_active, pause)?;
    } else if active {
        run(&["stop", SERVICE_NAME])?;
        if is_active()? {
            bail!("回滚后 shoes.service 仍处于 active 状态");
        }
    }
    enablement
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
    Systemctl::Foreground.after_reset(command)
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

// 只有 systemd 正在等待的 shoes 控制进程及其同步读者可以绕过写锁。
// systemd timer 的独立服务也有 INVOCATION_ID，清理环境的钩子则没有它。
pub(crate) async fn is_shoes_service_hook() -> bool {
    #[cfg(target_os = "linux")]
    {
        shoes_service_hook().await.unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    false
}

#[cfg(target_os = "linux")]
async fn shoes_service_hook() -> Option<bool> {
    let process = std::process::id();
    let cgroups = fs::read_to_string("/proc/self/cgroup").ok()?;
    let cgroup = systemd_cgroup(&cgroups)?;
    let unit = cgroup.rsplit('/').find(|part| part.ends_with(".service"))?;
    let systemctl = Systemctl::SecureTransaction;
    let control_pid = systemctl
        .timed_show("ControlPID")
        .await
        .ok()?
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid != 0)?;

    if unit == SERVICE_NAME {
        return Some(descends_from(process, control_pid));
    }

    // 同步 systemctl 可以是控制进程本身，也可以由 ExecStartPre 脚本派生。
    let systemctl_path = utils::command_path("systemctl")?;
    if !fs::read_dir("/proc")
        .ok()?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .any(|pid| waits_for_unit(pid, &systemctl_path, unit) && descends_from(pid, control_pid))
    {
        return Some(false);
    }
    // 用目标 unit 的进程核对读者归属。systemd 报告的 cgroup 路径可能相对于容器根。
    let target = systemctl
        .timed(
            &[
                "show",
                "--property=MainPID",
                "--property=ControlPID",
                "--",
                unit,
            ],
            SECURE_QUERY_TIMEOUT,
        )
        .await
        .ok()?;
    Some(target.lines().any(|line| {
        line.split_once('=')
            .filter(|(name, _)| matches!(*name, "MainPID" | "ControlPID"))
            .and_then(|(_, value)| value.parse::<u32>().ok())
            .is_some_and(|pid| pid > 1 && descends_from(process, pid))
    }))
}

#[cfg(target_os = "linux")]
fn waits_for_unit(pid: u32, executable: &Path, unit: &str) -> bool {
    let process = Path::new("/proc").join(pid.to_string());
    if !same_executable(&process.join("exe"), executable).unwrap_or(false) {
        return false;
    }
    fs::read(process.join("cmdline")).is_ok_and(|line| systemctl_starts_unit(&line, unit))
}

#[cfg(target_os = "linux")]
fn systemctl_starts_unit(command_line: &[u8], unit: &str) -> bool {
    let Some(command_line) = command_line.strip_suffix(b"\0") else {
        return false;
    };
    let mut args = command_line.split(|byte| *byte == 0).skip(1);
    let mut expected = [b"start".as_slice(), unit.as_bytes()].into_iter();
    let mut parse_options = true;
    while let Some(arg) = args.next() {
        if parse_options && arg.starts_with(b"-") {
            // 只允许本机系统管理器上仍会等待作业完成的选项。
            match arg {
                b"--" => parse_options = false,
                b"-q" | b"--quiet" | b"--no-ask-password" | b"--no-pager" | b"--system"
                | b"--wait" => {}
                b"--job-mode"
                    if args
                        .next()
                        .is_some_and(|mode| !mode.starts_with(b"-") && !mode.is_empty()) => {}
                mode if mode.starts_with(b"--job-mode=") && mode.len() > b"--job-mode=".len() => {}
                _ => return false,
            }
        } else if expected.next() != Some(arg) {
            return false;
        }
    }
    expected.next().is_none()
}

#[cfg(target_os = "linux")]
fn systemd_cgroup(cgroups: &str) -> Option<&str> {
    cgroups
        .lines()
        .find_map(|line| line.split_once(":name=systemd:").map(|(_, path)| path))
        .or_else(|| cgroups.lines().find_map(|line| line.strip_prefix("0::")))
}

#[cfg(target_os = "linux")]
fn descends_from(mut pid: u32, ancestor: u32) -> bool {
    while pid > 1 {
        if pid == ancestor {
            return true;
        }
        let parent = fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("PPid:")?.trim().parse::<u32>().ok())
            });
        let Some(parent) = parent else {
            return false;
        };
        pid = parent;
    }
    false
}

fn systemctl_is_active() -> Result<bool> {
    Systemctl::Foreground.is_active()
}

fn systemctl_is_failed() -> Result<bool> {
    Systemctl::Foreground.is_failed()
}

fn systemctl_is_enabled() -> Result<bool> {
    Systemctl::Foreground.query("is-enabled", "无法查询 systemd 服务启用状态")
}

fn systemctl(args: &[&str]) -> Result<()> {
    Systemctl::Foreground.run(args)
}

#[derive(Clone, Copy)]
pub(crate) enum Systemctl {
    Foreground,
    SecureTransaction,
}

impl Systemctl {
    fn command(self, program: &str) -> Command {
        match self {
            Self::Foreground => Command::new(program),
            Self::SecureTransaction => utils::isolated_command(program),
        }
    }

    fn run(self, args: &[&str]) -> Result<()> {
        let status = self
            .command("systemctl")
            .args(args)
            .status()
            .with_context(|| format!("无法执行 systemctl {}", args.join(" ")))?;
        if !status.success() {
            bail!("systemctl {} 失败（退出码：{status}）", args.join(" "));
        }
        Ok(())
    }

    fn query(self, action: &str, message: &str) -> Result<bool> {
        Ok(self
            .command("systemctl")
            .args([action, "--quiet", SERVICE_NAME])
            .status()
            .with_context(|| message.to_owned())?
            .success())
    }

    pub(crate) fn is_active(self) -> Result<bool> {
        self.query("is-active", "无法查询 systemd 服务状态")
    }

    fn is_failed(self) -> Result<bool> {
        self.query("is-failed", "无法查询 systemd 服务失败状态")
    }

    fn show_value(self, property: &str) -> Result<String> {
        let output = self
            .command("systemctl")
            .args([
                "show",
                &format!("--property={property}"),
                "--value",
                SERVICE_NAME,
            ])
            .stdout(std::process::Stdio::piped())
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

    pub(crate) fn main_pid(self) -> Result<Option<u32>> {
        parse_main_pid(&self.show_value("MainPID")?)
    }

    fn after_reset(self, command: &[&str]) -> Result<()> {
        if self.is_active()? || self.is_failed()? {
            self.run(RESET_FAILED_COMMAND)?;
        }
        self.run(command)
    }

    pub(crate) fn restart_and_verify(self) -> Result<()> {
        utils::require_linux_root()?;
        ensure_systemctl()?;
        self.after_reset(RESTART_COMMAND)?;
        verify_active_stable(
            || self.is_active(),
            || thread::sleep(Duration::from_millis(750)),
        )
    }

    pub(crate) async fn restart_secure_transaction(self, rollback: bool) -> Result<()> {
        utils::require_linux_root()?;
        ensure_systemctl()?;
        if rollback {
            // 取消 systemctl 客户端并不会撤销已提交给 systemd 的任务。先替换待完成的
            // restart，确保恢复的配置由新的进程加载。
            let stop = self.stop_secure_transaction().await;
            // 停止尚未完成或 unit 仍被引用时也可能保留启动计数。unit 已卸载时
            // reset-failed 可能报错，仍要尝试重启。
            let reset = self.timed(RESET_FAILED_COMMAND, SECURE_QUERY_TIMEOUT).await;
            let restart = if stop.is_err() {
                &["restart", "--job-mode=replace", SERVICE_NAME][..]
            } else {
                RESTART_COMMAND
            };
            self.timed(restart, SECURE_JOB_TIMEOUT)
                .await
                .with_context(|| {
                    let mut context = String::new();
                    if let Err(error) = stop {
                        context.push_str(&format!("等待回滚停止失败：{error:#}；"));
                    }
                    if let Err(error) = reset {
                        context.push_str(&format!("重置启动限流失败：{error:#}；"));
                    }
                    context.push_str("重启已恢复的 shoes.service 失败");
                    context
                })?;
        } else {
            if matches!(
                self.timed_show("ActiveState").await?.as_str(),
                "active" | "failed"
            ) {
                self.timed(RESET_FAILED_COMMAND, SECURE_QUERY_TIMEOUT)
                    .await?;
            }
            self.timed(RESTART_COMMAND, SECURE_JOB_TIMEOUT).await?;
        }
        if !self.secure_is_active().await? {
            bail!("systemd 命令已返回成功，但 shoes.service 未处于 active 状态");
        }
        tokio::time::sleep(Duration::from_millis(750)).await;
        if !self.secure_is_active().await? {
            bail!("shoes.service 启动后未保持 active，可能已立即退出或进入自动重启");
        }
        Ok(())
    }

    pub(crate) async fn stop_secure_transaction(self) -> Result<()> {
        self.timed(
            &["stop", "--job-mode=replace", SERVICE_NAME],
            SECURE_JOB_TIMEOUT,
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn secure_is_active(self) -> Result<bool> {
        Ok(self.timed_show("ActiveState").await? == "active")
    }

    pub(crate) async fn secure_main_pid(self) -> Result<Option<u32>> {
        parse_main_pid(&self.timed_show("MainPID").await?)
    }

    async fn timed_show(self, property: &str) -> Result<String> {
        self.timed(
            &[
                "show",
                &format!("--property={property}"),
                "--value",
                SERVICE_NAME,
            ],
            SECURE_QUERY_TIMEOUT,
        )
        .await
    }

    async fn timed(self, args: &[&str], timeout: Duration) -> Result<String> {
        wait_for_systemctl(self.command("systemctl"), args, timeout).await
    }
}

fn parse_main_pid(value: &str) -> Result<Option<u32>> {
    let pid = value
        .parse::<u32>()
        .with_context(|| format!("systemd 返回了无效 MainPID：{value}"))?;
    Ok((pid != 0).then_some(pid))
}

async fn wait_for_systemctl(command: Command, args: &[&str], timeout: Duration) -> Result<String> {
    let child = tokio::process::Command::from(command)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("无法执行 systemctl {}", args.join(" ")))?;
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .with_context(|| format!("systemctl {} 执行超时", args.join(" ")))?
        .with_context(|| format!("无法等待 systemctl {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "systemctl {} 失败（退出码：{}）",
            args.join(" "),
            output.status
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
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
    fn socks5_secure_recognizes_only_blocking_local_systemctl_start() {
        let waits = |command: &str| systemctl_starts_unit(command.as_bytes(), "helper.service");
        for command in [
            "systemctl\0start\0helper.service\0",
            "systemctl\0--quiet\0start\0helper.service\0",
            "systemctl\0start\0-q\0--no-ask-password\0--\0helper.service\0",
            "systemctl\0--job-mode=replace\0start\0helper.service\0",
            "systemctl\0start\0--job-mode\0replace\0helper.service\0",
        ] {
            assert!(waits(command), "{command:?}");
        }
        for command in [
            "systemctl\0--quiet\0--no-block\0start\0helper.service\0",
            "systemctl\0start\0helper.service\0--no-block\0",
            "systemctl\0--user\0start\0helper.service\0",
            "systemctl\0--host=example.com\0start\0helper.service\0",
            "systemctl\0--machine=container\0start\0helper.service\0",
            "systemctl\0show\0helper.service\0",
            "systemctl\0start\0other.service\0",
        ] {
            assert!(!waits(command), "{command:?}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn socks5_secure_systemctl_wait_is_bounded() {
        let mut command = utils::isolated_command("sh");
        command.args(["-c", "exec sleep 60"]);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_systemctl(command, RESTART_COMMAND, Duration::from_millis(100)),
        )
        .await
        .expect("systemctl 超时不能阻塞异步任务");
        assert!(format!("{:#}", result.unwrap_err()).contains("restart shoes.service 执行超时"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemctl_status_uses_foreground_group_and_rollback_detaches_stdio() {
        let script = concat!(
            "read -r stat < \"/proc/$$/stat\" || exit 1; ",
            "set -- \"${stat##*) }\" \"$1\"; mode=$2; set -- $1; ",
            "if [ \"$mode\" = foreground ]; then ",
            "  [ \"$3\" != \"$$\" ] || exit 2; ",
            "else ",
            "  [ \"$3\" = \"$$\" ] || exit 3; ",
            "  for fd in 0 1 2; do ",
            "    [ \"$(readlink /proc/$$/fd/$fd)\" = /dev/null ] || exit 4; ",
            "  done; ",
            "fi",
        );
        for (systemctl, mode) in [
            (Systemctl::Foreground, "foreground"),
            (Systemctl::SecureTransaction, "rollback"),
        ] {
            let status = systemctl
                .command("sh")
                .args(["-c", script, "sh", mode])
                .status();
            assert!(status.unwrap().success(), "{mode}");
        }
    }

    #[test]
    fn socks5_secure_restores_active_vendor_unit_with_or_without_temporary_override() {
        use std::cell::{Cell, RefCell};

        for override_created in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("shoes.service");
            let snapshot =
                capture_snapshot_with(&path, || Ok(true), || Ok(true), || Ok(Some(42))).unwrap();
            assert!(snapshot.unit_contents.is_none());
            assert!(snapshot.was_active());
            assert!(snapshot.was_enabled);
            assert_eq!(snapshot.main_pid, Some(42));
            if override_created {
                fs::write(&path, b"temporary override").unwrap();
            }

            let active = Cell::new(true);
            let enabled = Cell::new(true);
            let active_probes = Cell::new(0);
            let pauses = Cell::new(0);
            let commands = RefCell::new(Vec::new());
            restore_snapshot_with(
                snapshot,
                &path,
                |args| {
                    commands
                        .borrow_mut()
                        .push(args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>());
                    match args {
                        ["disable", "--now", SERVICE_NAME] => {
                            assert!(path.exists());
                            active.set(false);
                            enabled.set(false);
                        }
                        ["daemon-reload"] => assert!(!path.exists()),
                        ["enable", SERVICE_NAME] => enabled.set(true),
                        ["reset-failed", SERVICE_NAME] => {}
                        ["start" | "restart", SERVICE_NAME] => {
                            assert!(!path.exists());
                            active.set(true);
                        }
                        _ => panic!("意外 systemctl 操作 {args:?}"),
                    }
                    Ok(())
                },
                || {
                    active_probes.set(active_probes.get() + 1);
                    Ok(active.get())
                },
                || Ok(enabled.get()),
                || pauses.set(pauses.get() + 1),
            )
            .unwrap();

            let commands = commands.into_inner();
            if override_created {
                assert_eq!(commands[0], ["disable", "--now", SERVICE_NAME]);
                assert_eq!(commands[1], ["daemon-reload"]);
                assert_eq!(commands.last().unwrap().as_slice(), START_COMMAND);
            } else {
                assert_eq!(commands[0], ["daemon-reload"]);
                assert_eq!(commands.last().unwrap().as_slice(), RESTART_COMMAND);
            }
            assert!(active.get());
            assert!(enabled.get());
            assert_eq!(active_probes.get(), 3);
            assert_eq!(pauses.get(), 1);
            assert!(!path.exists());
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
        release.release_tag = Some("v0.3.6".into());
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
}
