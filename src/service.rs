use std::{fs, path::Path, process::Command};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;

use crate::utils;

pub const SERVICE_NAME: &str = "shoes.service";
const RESET_FAILED_COMMAND: &[&str] = &["reset-failed", SERVICE_NAME];
const ENABLE_NOW_COMMAND: &[&str] = &["enable", "--now", SERVICE_NAME];
const START_COMMAND: &[&str] = &["start", SERVICE_NAME];
const RESTART_COMMAND: &[&str] = &["restart", SERVICE_NAME];

pub struct ServiceSnapshot {
    unit_contents: Option<Vec<u8>>,
    was_active: bool,
    was_enabled: bool,
}

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
ReadOnlyPaths={}
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
    install_unit(true)?;
    if !systemctl_is_active()? {
        bail!("systemd 命令已返回成功，但 shoes.service 未处于 active 状态");
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
    Ok(ServiceSnapshot {
        unit_contents,
        was_active: unit_exists && systemctl_is_active()?,
        was_enabled: unit_exists && systemctl_is_enabled()?,
    })
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
        assert!(unit.contains("ExecStart=/usr/local/bin/shoes /etc/shoes/config.yaml"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("NoNewPrivileges=true"));
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
}
