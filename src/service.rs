use std::{fs, path::Path, process::Command};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;

use crate::utils;

pub const SERVICE_NAME: &str = "shoes.service";
const ENABLE_NOW_COMMAND: &[&str] = &["enable", "--now", SERVICE_NAME];
const RESTART_COMMAND: &[&str] = &["restart", SERVICE_NAME];

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
    let was_active =
        enable_now && Path::new(utils::SERVICE_FILE).exists() && systemctl_is_active()?;
    utils::atomic_write(
        Path::new(utils::SERVICE_FILE),
        unit_contents().as_bytes(),
        0o644,
    )?;
    systemctl(&["daemon-reload"])?;
    if enable_now {
        for command in activation_commands(was_active) {
            systemctl(command)?;
        }
    }
    Ok(())
}

fn activation_commands(was_active: bool) -> Vec<&'static [&'static str]> {
    let mut commands = vec![ENABLE_NOW_COMMAND];
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
        ServiceAction::Start => systemctl(&["start", SERVICE_NAME]),
        ServiceAction::Stop => systemctl(&["stop", SERVICE_NAME]),
        ServiceAction::Restart => systemctl(&["restart", SERVICE_NAME]),
        ServiceAction::Status => systemctl(&["status", "--no-pager", SERVICE_NAME]),
        ServiceAction::Enable => systemctl(&["enable", "--now", SERVICE_NAME]),
        ServiceAction::Disable => systemctl(&["disable", "--now", SERVICE_NAME]),
    }
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
    fn active_service_is_restarted_after_enabling_updated_unit() {
        assert_eq!(activation_commands(false), vec![ENABLE_NOW_COMMAND]);
        assert_eq!(
            activation_commands(true),
            vec![ENABLE_NOW_COMMAND, RESTART_COMMAND]
        );
    }
}
