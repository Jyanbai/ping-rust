use std::{
    env, fs,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use fs2::FileExt;

pub const SHOES_BIN: &str = "/usr/local/bin/shoes";
pub const CONFIG_DIR: &str = "/etc/shoes";
pub const CONFIG_FILE: &str = "/etc/shoes/config.yaml";
pub const STATE_FILE: &str = "/etc/shoes/ping-rust-state.json";
pub const LOCK_FILE: &str = "/run/lock/ping-rust.lock";
pub const SERVICE_FILE: &str = "/etc/systemd/system/shoes.service";

pub fn remove_command_aliases() -> Result<usize> {
    let executable = env::current_exe().context("无法确定 ping-rust 当前路径")?;
    let Some(parent) = executable.parent() else {
        return Ok(0);
    };
    let mut removed = 0;
    for name in ["prs", "sb"] {
        removed += usize::from(remove_owned_alias(&parent.join(name), &executable)?);
    }
    Ok(removed)
}

#[cfg(unix)]
fn remove_owned_alias(alias: &Path, executable: &Path) -> Result<bool> {
    if !alias.is_symlink() {
        return Ok(false);
    }
    let target =
        fs::read_link(alias).with_context(|| format!("读取符号链接 {} 失败", alias.display()))?;
    let resolved = if target.is_absolute() {
        target
    } else {
        alias
            .parent()
            .context("快捷命令符号链接没有父目录")?
            .join(target)
    };
    let resolved = resolved
        .canonicalize()
        .with_context(|| format!("解析符号链接 {} 失败", alias.display()))?;
    let executable = executable
        .canonicalize()
        .with_context(|| format!("解析可执行文件 {} 失败", executable.display()))?;
    if resolved != executable {
        return Ok(false);
    }
    fs::remove_file(alias).with_context(|| format!("删除 {} 失败", alias.display()))?;
    Ok(true)
}

#[cfg(not(unix))]
fn remove_owned_alias(_alias: &Path, _executable: &Path) -> Result<bool> {
    Ok(false)
}

pub fn require_linux() -> Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        bail!("该操作仅支持 Linux；当前系统为 {}", std::env::consts::OS)
    }
}

pub fn require_linux_root() -> Result<()> {
    require_linux()?;
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("无法检查当前用户权限")?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "0" {
        bail!("该操作需要 root 权限，请使用 sudo ping-rust ...")
    }
    Ok(())
}

pub fn command_exists(name: &str) -> bool {
    command_path(name).is_some()
}

pub fn command_path(name: &str) -> Option<PathBuf> {
    let requested = Path::new(name);
    if requested.components().count() > 1 {
        return is_executable(requested).then(|| requested.to_path_buf());
    }

    env::var_os("PATH")
        .and_then(|path| {
            env::split_paths(&path).find_map(|directory| {
                command_candidates(&directory, name)
                    .into_iter()
                    .find(|candidate| is_executable(candidate))
            })
        })
        .or_else(|| {
            std::env::current_exe().ok().and_then(|executable| {
                executable.parent().and_then(|parent| {
                    command_candidates(parent, name)
                        .into_iter()
                        .find(|candidate| is_executable(candidate))
                })
            })
        })
}

fn command_candidates(directory: &Path, name: &str) -> Vec<PathBuf> {
    let base = directory.join(name);
    #[cfg(windows)]
    {
        if Path::new(name).extension().is_some() {
            return vec![base];
        }
        let extensions = env::var_os("PATHEXT")
            .map(|value| {
                value
                    .to_string_lossy()
                    .split(';')
                    .filter(|extension| !extension.is_empty())
                    .map(|extension| base.with_extension(extension.trim_start_matches('.')))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![base.with_extension("exe")]);
        extensions
    }
    #[cfg(not(windows))]
    vec![base]
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[derive(Debug)]
pub struct ExclusiveLock(File);

pub fn exclusive_lock(path: &Path) -> Result<ExclusiveLock> {
    let parent = path.parent().context("锁文件路径没有父目录")?;
    fs::create_dir_all(parent).with_context(|| format!("创建锁目录 {} 失败", parent.display()))?;
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("打开锁文件 {} 失败", path.display()))?;
    set_mode(path, 0o600)?;
    file.lock_exclusive()
        .with_context(|| format!("锁定 {} 失败", path.display()))?;
    Ok(ExclusiveLock(file))
}

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub fn atomic_write(destination: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = destination.parent().context("目标路径没有父目录")?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    fs::create_dir_all(parent).with_context(|| format!("创建目录 {} 失败", parent.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("无法在 {} 创建临时文件", parent.display()))?;
    temp.write_all(contents).context("写入临时文件失败")?;
    temp.as_file().sync_all().context("同步临时文件失败")?;
    set_mode(temp.path(), mode)?;
    persist_replace(temp, destination)
}

pub fn ensure_directory(path: &Path, mode: u32) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("创建目录 {} 失败", path.display()))?;
    set_mode(path, mode).with_context(|| format!("设置目录 {} 权限失败", path.display()))
}

pub fn atomic_copy(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    let bytes = fs::read(source).with_context(|| format!("读取 {} 失败", source.display()))?;
    atomic_write(destination, &bytes, mode)
}

fn persist_replace(temp: tempfile::NamedTempFile, destination: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    if destination.exists() {
        fs::remove_file(destination)
            .with_context(|| format!("替换 {} 失败", destination.display()))?;
    }
    temp.persist(destination)
        .map_err(|error| error.error)
        .with_context(|| format!("原子替换 {} 失败", destination.display()))?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
pub(crate) fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_content() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.yaml");
        atomic_write(&file, b"first", 0o600).unwrap();
        atomic_write(&file, b"second", 0o600).unwrap();
        assert_eq!(fs::read(file).unwrap(), b"second");
    }

    #[test]
    fn command_exists_does_not_require_which() {
        assert!(command_exists(
            std::env::current_exe().unwrap().to_str().unwrap()
        ));
        assert!(!command_exists("ping-rust-command-that-does-not-exist"));
    }

    #[test]
    fn exclusive_lock_can_be_reacquired_after_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        drop(exclusive_lock(&path).unwrap());
        drop(exclusive_lock(&path).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn removes_current_and_legacy_aliases_only_when_owned() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("ping-rust");
        let other = dir.path().join("other");
        fs::write(&executable, b"binary").unwrap();
        fs::write(&other, b"other").unwrap();

        for name in ["prs", "sb"] {
            let alias = dir.path().join(name);
            symlink("ping-rust", &alias).unwrap();
            assert!(remove_owned_alias(&alias, &executable).unwrap());
            assert!(!alias.exists());

            symlink("other", &alias).unwrap();
            assert!(!remove_owned_alias(&alias, &executable).unwrap());
            assert!(alias.is_symlink());
            fs::remove_file(alias).unwrap();
        }
    }
}
