use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};

use crate::utils;

const PROGRAM: &str = "ping-rust";
const SHORT_COMMAND: &str = "prs";
const LEGACY_SHORT_COMMAND: &str = "sb";

#[derive(Debug)]
pub struct InstallReport {
    pub destination: PathBuf,
    pub command: &'static str,
}

struct BinarySnapshot {
    bytes: Option<Vec<u8>>,
    mode: u32,
}

impl BinarySnapshot {
    fn capture(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                bytes: None,
                mode: 0o755,
            });
        }
        let bytes =
            fs::read(path).with_context(|| format!("备份现有程序 {} 失败", path.display()))?;
        Ok(Self {
            bytes: Some(bytes),
            mode: executable_mode(path)?,
        })
    }

    fn restore(&self, path: &Path) -> Result<()> {
        match &self.bytes {
            Some(bytes) => utils::atomic_write(path, bytes, self.mode),
            None if path.exists() || path.is_symlink() => fs::remove_file(path)
                .with_context(|| format!("移除安装失败的程序 {} 失败", path.display())),
            None => Ok(()),
        }
    }
}

pub fn install(install_dir: &Path, quiet: bool) -> Result<InstallReport> {
    utils::require_linux()?;
    validate_install_dir(install_dir)?;
    fs::create_dir_all(install_dir)
        .with_context(|| format!("创建安装目录 {} 失败", install_dir.display()))?;
    if !install_dir.is_dir() {
        bail!("安装路径不是目录：{}", install_dir.display());
    }

    let source = std::env::current_exe().context("无法确定待安装的 ping-rust 路径")?;
    if !source.is_file() {
        bail!("待安装的 ping-rust 不是普通文件：{}", source.display());
    }
    let destination = install_dir.join(PROGRAM);
    let snapshot = BinarySnapshot::capture(&destination)?;
    if let Err(install_error) = install_and_verify(&source, &destination) {
        return match snapshot.restore(&destination) {
            Ok(()) => Err(install_error.context("安装失败，原程序已恢复")),
            Err(rollback) => {
                bail!("安装失败且原程序恢复失败：安装={install_error:#}；恢复={rollback:#}")
            }
        };
    }

    let short_alias_available = ensure_short_alias(install_dir)?;
    let removed_legacy_alias = remove_owned_legacy_alias(install_dir)?;
    if removed_legacy_alias && !quiet {
        println!("已移除旧快捷命令 {LEGACY_SHORT_COMMAND}。");
    }
    Ok(InstallReport {
        destination,
        command: if short_alias_available {
            SHORT_COMMAND
        } else {
            PROGRAM
        },
    })
}

pub fn run_bootstrap_as_root(binary: &Path) -> Result<()> {
    let sudo = utils::command_path("sudo")
        .context("自动部署 VLESS-REALITY 需要 root 权限，但系统没有 sudo；请以 root 运行。")?;
    let status = Command::new(sudo)
        .arg(binary)
        .arg("bootstrap")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("无法通过 sudo 启动默认 VLESS-REALITY 部署")?;
    if !status.success() {
        bail!("默认 VLESS-REALITY 部署失败（{status}）");
    }
    Ok(())
}

fn validate_install_dir(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("安装目录必须是绝对路径：{}", path.display());
    }
    if path == Path::new("/") {
        bail!("安装目录不能是根目录 /");
    }
    Ok(())
}

fn install_and_verify(source: &Path, destination: &Path) -> Result<()> {
    utils::atomic_copy(source, destination, 0o755).with_context(|| {
        format!(
            "写入 {} 失败；若它位于系统目录，请使用 sudo",
            destination.display()
        )
    })?;
    verify_installed_binary(destination)
}

fn verify_installed_binary(binary: &Path) -> Result<()> {
    let output = Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("无法执行 {} 版本检查", binary.display()))?;
    if !output.status.success() {
        bail!("安装后的版本检查失败（{}）", output.status);
    }
    let actual = String::from_utf8(output.stdout).context("安装后的版本输出不是有效 UTF-8")?;
    let actual = actual
        .strip_suffix("\r\n")
        .or_else(|| actual.strip_suffix('\n'))
        .unwrap_or(&actual);
    let expected = format!("{PROGRAM} {}", env!("CARGO_PKG_VERSION"));
    if actual.contains(['\r', '\n']) {
        bail!("安装后的版本输出必须只有一行");
    }
    if actual != expected {
        bail!("安装后的版本不匹配：期望 {expected:?}，实际 {:?}", actual);
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_short_alias(install_dir: &Path) -> Result<bool> {
    use std::os::unix::fs::symlink;

    let alias = install_dir.join(SHORT_COMMAND);
    if alias.is_symlink() {
        let target =
            fs::read_link(&alias).with_context(|| format!("读取 {} 失败", alias.display()))?;
        if owned_alias_target(&target, install_dir) {
            return Ok(true);
        }
        eprintln!(
            "警告：保留已有符号链接 {} -> {}；请使用 {}。",
            alias.display(),
            target.display(),
            PROGRAM
        );
        return Ok(false);
    }
    if alias.exists() {
        eprintln!(
            "警告：保留已有命令 {}；请使用 {}。",
            alias.display(),
            PROGRAM
        );
        return Ok(false);
    }
    symlink(PROGRAM, &alias).with_context(|| format!("创建快捷命令 {} 失败", alias.display()))?;
    Ok(true)
}

#[cfg(not(unix))]
fn ensure_short_alias(_install_dir: &Path) -> Result<bool> {
    Ok(false)
}

#[cfg(unix)]
fn remove_owned_legacy_alias(install_dir: &Path) -> Result<bool> {
    let alias = install_dir.join(LEGACY_SHORT_COMMAND);
    if !alias.is_symlink() {
        return Ok(false);
    }
    let target = fs::read_link(&alias).with_context(|| format!("读取 {} 失败", alias.display()))?;
    if !owned_alias_target(&target, install_dir) {
        return Ok(false);
    }
    fs::remove_file(&alias).with_context(|| format!("删除 {} 失败", alias.display()))?;
    Ok(true)
}

#[cfg(not(unix))]
fn remove_owned_legacy_alias(_install_dir: &Path) -> Result<bool> {
    Ok(false)
}

#[cfg(any(unix, test))]
fn owned_alias_target(target: &Path, install_dir: &Path) -> bool {
    target == Path::new(PROGRAM) || target == install_dir.join(PROGRAM)
}

#[cfg(unix)]
fn executable_mode(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;

    Ok(fs::metadata(path)
        .with_context(|| format!("读取 {} 权限失败", path.display()))?
        .permissions()
        .mode()
        & 0o777)
}

#[cfg(not(unix))]
fn executable_mode(_path: &Path) -> Result<u32> {
    Ok(0o755)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn validates_absolute_non_root_install_directory() {
        assert!(validate_install_dir(Path::new("/opt/ping-rust/bin")).is_ok());
        assert!(validate_install_dir(Path::new("relative")).is_err());
        assert!(validate_install_dir(Path::new("/")).is_err());
    }

    #[test]
    fn only_exact_same_directory_targets_are_owned() {
        let directory = Path::new("/usr/local/bin");
        assert!(owned_alias_target(Path::new("ping-rust"), directory));
        assert!(owned_alias_target(
            Path::new("/usr/local/bin/ping-rust"),
            directory
        ));
        assert!(!owned_alias_target(
            Path::new("/opt/other/ping-rust"),
            directory
        ));
        assert!(!owned_alias_target(Path::new("other"), directory));
    }

    #[cfg(unix)]
    #[test]
    fn preserves_conflicts_and_removes_only_owned_legacy_alias() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let prs = directory.path().join(SHORT_COMMAND);
        let sb = directory.path().join(LEGACY_SHORT_COMMAND);
        fs::write(&prs, b"owned by another program").unwrap();
        symlink(PROGRAM, &sb).unwrap();
        assert!(!ensure_short_alias(directory.path()).unwrap());
        assert!(remove_owned_legacy_alias(directory.path()).unwrap());
        assert_eq!(fs::read(&prs).unwrap(), b"owned by another program");
        assert!(!sb.exists());

        fs::remove_file(&prs).unwrap();
        symlink("other", &prs).unwrap();
        symlink("other", &sb).unwrap();
        assert!(!ensure_short_alias(directory.path()).unwrap());
        assert!(!remove_owned_legacy_alias(directory.path()).unwrap());
        assert_eq!(fs::read_link(&prs).unwrap(), Path::new("other"));
        assert_eq!(fs::read_link(&sb).unwrap(), Path::new("other"));
    }
}
