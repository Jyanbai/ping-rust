use std::{
    fs::{self, File},
    io,
    net::{TcpListener, UdpSocket},
    path::{Component, Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use tar::Archive;

use crate::{config, service, utils};

pub struct PortStatus {
    pub tcp_available: Option<Result<(), String>>,
    pub udp_available: Option<Result<(), String>>,
}

pub fn check_port(port: u16, tcp: bool, udp: bool) -> PortStatus {
    PortStatus {
        tcp_available: tcp.then(|| {
            TcpListener::bind(("0.0.0.0", port))
                .map(drop)
                .map_err(|error| error.to_string())
        }),
        udp_available: udp.then(|| {
            UdpSocket::bind(("0.0.0.0", port))
                .map(drop)
                .map_err(|error| error.to_string())
        }),
    }
}

pub fn enable_bbr() -> Result<()> {
    utils::require_linux_root()?;
    if utils::command_exists("modprobe") {
        let _ = Command::new("modprobe").arg("tcp_bbr").status();
    }
    let settings = b"net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n";
    let sysctl_file = Path::new("/etc/sysctl.d/99-ping-rust-bbr.conf");
    utils::atomic_write(sysctl_file, settings, 0o644)?;
    let status = Command::new("sysctl")
        .arg("--system")
        .status()
        .context("无法执行 sysctl --system")?;
    if !status.success() {
        bail!(
            "sysctl --system 失败；设置文件保留在 {}",
            sysctl_file.display()
        );
    }
    let algorithms = fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")
        .context("无法读取内核拥塞控制算法列表")?;
    if !algorithms.split_whitespace().any(|name| name == "bbr") {
        bail!("当前内核未提供 BBR；请升级内核后重试");
    }
    let active = fs::read_to_string("/proc/sys/net/ipv4/tcp_congestion_control")
        .context("无法读取当前拥塞控制算法")?;
    if active.trim() != "bbr" {
        bail!("BBR 已写入 sysctl，但当前算法仍为 {}", active.trim());
    }
    Ok(())
}

pub fn backup(output: Option<PathBuf>) -> Result<PathBuf> {
    utils::require_linux_root()?;
    let _lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    let source = Path::new(utils::CONFIG_DIR);
    if !source.is_dir() {
        bail!("配置目录 {} 不存在", source.display());
    }
    let destination =
        output.unwrap_or_else(|| PathBuf::from(format!("shoes-backup-{}.tar.gz", timestamp())));
    if destination.exists() {
        bail!("备份文件 {} 已存在，拒绝覆盖", destination.display());
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).context("创建备份目录失败")?;
    let temp = tempfile::NamedTempFile::new_in(parent).context("创建备份临时文件失败")?;
    {
        let encoder = GzEncoder::new(temp.as_file(), Compression::default());
        let mut tar = tar::Builder::new(encoder);
        tar.append_dir_all("shoes", source)
            .context("将配置加入备份归档失败")?;
        let encoder = tar.into_inner().context("结束 tar 归档失败")?;
        encoder.finish().context("结束 gzip 压缩失败")?;
    }
    temp.persist(&destination)
        .map_err(|error| error.error)
        .context("保存备份文件失败")?;
    set_private_permissions(&destination)?;
    Ok(destination)
}

pub async fn restore(archive_path: &Path) -> Result<Option<PathBuf>> {
    utils::require_linux_root()?;
    let _lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    if !archive_path.is_file() {
        bail!("备份文件 {} 不存在", archive_path.display());
    }
    let stage = tempfile::tempdir().context("创建恢复临时目录失败")?;
    extract_backup(archive_path, stage.path())?;
    let restored = stage.path().join("shoes");
    if !restored.join("config.yaml").is_file() {
        bail!("归档缺少 shoes/config.yaml");
    }
    let yaml = fs::read_to_string(restored.join("config.yaml"))?;
    let _: Vec<serde_yaml::Value> =
        serde_yaml::from_str(&yaml).context("备份中的 config.yaml 不是有效 YAML 数组")?;
    if restored.join("ping-rust-state.json").exists() {
        config::prepare_managed_snapshot(&restored)?;
        config::validate_managed_snapshot(
            &restored.join("config.yaml"),
            &restored.join("ping-rust-state.json"),
        )?;
    }

    let destination = Path::new(utils::CONFIG_DIR);
    let rollback = destination.with_extension(format!("pre-restore-{}", timestamp()));
    let had_existing = destination.exists();
    let unit_exists = Path::new(utils::SERVICE_FILE).exists();
    let was_active = unit_exists && service::is_active()?;
    if had_existing {
        fs::rename(destination, &rollback).context("暂存现有配置失败")?;
    }
    if let Err(error) = copy_tree(&restored, destination) {
        rollback_restore(destination, &rollback, had_existing)?;
        return Err(error.context("复制恢复文件失败，原配置已回滚"));
    }
    if let Err(error) = harden_config_tree(destination) {
        rollback_restore(destination, &rollback, had_existing)?;
        return Err(error.context("收紧恢复配置权限失败，原配置已回滚"));
    }
    if let Err(error) = config::validate_with_shoes(Path::new(utils::CONFIG_FILE)).await {
        rollback_restore(destination, &rollback, had_existing)?;
        return Err(error.context("恢复配置未通过 shoes 校验，原配置已回滚"));
    }
    if was_active {
        if let Err(error) = service::execute(crate::service::ServiceAction::Restart) {
            rollback_restore(destination, &rollback, had_existing)?;
            if let Err(restart_error) = service::execute(crate::service::ServiceAction::Restart) {
                return Err(error.context(format!(
                    "恢复后的服务启动失败，文件已回滚，但原服务恢复也失败：{restart_error:#}"
                )));
            }
            return Err(error.context("恢复后的服务启动失败，原配置和服务已回滚"));
        }
    }
    Ok(had_existing.then_some(rollback))
}

fn extract_backup(archive_path: &Path, destination: &Path) -> Result<()> {
    let file = File::open(archive_path).context("打开备份归档失败")?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    for entry in archive.entries().context("读取备份归档失败")? {
        let mut entry = entry.context("读取备份条目失败")?;
        let path = entry.path().context("备份条目路径无效")?.into_owned();
        if !is_safe_relative_path(&path) {
            bail!("备份包含不安全路径 {}", path.display());
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            bail!("备份包含不允许的链接或特殊文件 {}", path.display());
        }
        if !entry.unpack_in(destination).context("解压备份条目失败")? {
            bail!("备份条目越过恢复目录 {}", path.display());
        }
    }
    Ok(())
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if entry.file_type()?.is_file() {
            fs::copy(entry.path(), target)?;
        } else {
            bail!("恢复源包含链接或特殊文件 {}", entry.path().display());
        }
    }
    Ok(())
}

fn harden_config_tree(path: &Path) -> Result<()> {
    utils::set_mode(path, 0o700)
        .with_context(|| format!("设置目录 {} 权限失败", path.display()))?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            harden_config_tree(&entry.path())?;
        } else if file_type.is_file() {
            utils::set_mode(&entry.path(), 0o600)
                .with_context(|| format!("设置文件 {} 权限失败", entry.path().display()))?;
        } else {
            bail!("配置目录包含链接或特殊文件 {}", entry.path().display());
        }
    }
    Ok(())
}

fn rollback_restore(destination: &Path, rollback: &Path, had_existing: bool) -> Result<()> {
    if destination != Path::new(utils::CONFIG_DIR) {
        bail!("内部安全检查失败：恢复目标不是预期配置目录");
    }
    if destination.exists() {
        fs::remove_dir_all(destination).context("清理失败的恢复目录失败")?;
    }
    if had_existing {
        fs::rename(rollback, destination).context("回滚原配置失败")?;
    }
    Ok(())
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn rejects_archive_traversal_paths() {
        assert!(!is_safe_relative_path(Path::new("../etc/passwd")));
        assert!(!is_safe_relative_path(Path::new("/etc/passwd")));
        assert!(is_safe_relative_path(Path::new("shoes/config.yaml")));
    }

    #[test]
    fn port_check_reports_requested_protocols() {
        let status = check_port(0, true, false);
        assert!(matches!(status.tcp_available, Some(Ok(()))));
        assert!(status.udp_available.is_none());
    }

    #[test]
    fn extracts_safe_backup_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("backup.tar.gz");
        {
            let file = File::create(&archive_path).unwrap();
            let encoder = GzEncoder::new(file, Compression::default());
            let mut builder = tar::Builder::new(encoder);
            let contents = b"- address: 0.0.0.0:443\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            builder
                .append_data(&mut header, "shoes/config.yaml", Cursor::new(contents))
                .unwrap();
            let profile = b"address: 0.0.0.0:443\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(profile.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "shoes/profiles/VLESS-REALITY-443.yaml",
                    Cursor::new(profile),
                )
                .unwrap();
            builder.finish().unwrap();
        }
        let output = dir.path().join("output");
        fs::create_dir(&output).unwrap();
        extract_backup(&archive_path, &output).unwrap();
        assert_eq!(
            fs::read(output.join("shoes/config.yaml")).unwrap(),
            b"- address: 0.0.0.0:443\n"
        );
        assert_eq!(
            fs::read(output.join("shoes/profiles").join("VLESS-REALITY-443.yaml")).unwrap(),
            b"address: 0.0.0.0:443\n"
        );
    }

    #[test]
    fn rejects_symlink_backup_entry() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("link.tar.gz");
        {
            let file = File::create(&archive_path).unwrap();
            let encoder = GzEncoder::new(file, Compression::default());
            let mut builder = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_link_name("/etc/passwd").unwrap();
            header.set_cksum();
            builder
                .append_data(&mut header, "shoes/key.pem", io::empty())
                .unwrap();
            builder.finish().unwrap();
        }
        let output = dir.path().join("output");
        fs::create_dir(&output).unwrap();
        let error = extract_backup(&archive_path, &output).unwrap_err();
        assert!(error.to_string().contains("链接或特殊文件"));
    }
}
