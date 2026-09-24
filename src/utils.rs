use std::{
    env, fs,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use fs2::FileExt;

pub const SHOES_BIN: &str = "/usr/local/bin/shoes";
pub const CONFIG_DIR: &str = "/etc/shoes";
pub const CONFIG_FILE: &str = "/etc/shoes/config.yaml";
pub const PROFILES_DIR: &str = "/etc/shoes/profiles";
pub const STATE_FILE: &str = "/etc/shoes/ping-rust-state.json";
pub const SHOES_PROVENANCE_FILE: &str = "/var/lib/ping-rust/shoes-install.json";
pub const LOCK_FILE: &str = "/run/lock/ping-rust.lock";
pub const SERVICE_FILE: &str = "/etc/systemd/system/shoes.service";
pub const HOT_RELOAD_ANCHOR_FILE: &str = "/var/lib/ping-rust/.shoes-config-watch";
const HOT_RELOAD_ANCHOR_PID_FILE: &str = "/var/lib/ping-rust/.shoes-config-watch-pid";

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
    if !is_root()? {
        bail!("该操作需要 root 权限，请使用 sudo ping-rust ...")
    }
    Ok(())
}

pub fn is_root() -> Result<bool> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("无法检查当前用户权限")?;
    if !output.status.success() {
        bail!("检查当前用户权限失败：{}", output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "0")
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

/// Keep a hard link to the inode watched by shoes.  shoes watches the config
/// file itself, while ping-rust replaces it atomically; touching this anchor
/// lets the watcher observe later replacements without weakening atomicity.
pub fn prepare_hot_reload_anchor(pid: u32) -> Result<()> {
    let config = Path::new(CONFIG_FILE);
    let config_metadata = fs::symlink_metadata(config)?;
    if !config_metadata.is_file() || config_metadata.file_type().is_symlink() {
        bail!("shoes 聚合配置不是普通文件：{}", config.display());
    }
    let anchor = Path::new(HOT_RELOAD_ANCHOR_FILE);
    let pid_path = Path::new(HOT_RELOAD_ANCHOR_PID_FILE);
    let parent = anchor.parent().context("热重载锚点路径没有父目录")?;
    ensure_directory(parent, 0o700)?;
    if anchor.exists() {
        let metadata = fs::symlink_metadata(anchor)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("热重载锚点不是普通文件：{}", anchor.display());
        }
        if fs::read_to_string(pid_path)
            .ok()
            .is_some_and(|recorded| recorded.trim() == pid.to_string())
        {
            return Ok(());
        }
        fs::remove_file(anchor).context("更新 shoes 热重载锚点失败")?;
    }
    fs::hard_link(config, anchor).with_context(|| {
        format!(
            "创建 shoes 热重载锚点失败：{} -> {}",
            config.display(),
            anchor.display()
        )
    })?;
    atomic_write(pid_path, pid.to_string().as_bytes(), 0o600)
}

/// Generate a file modification event on the inode watched by shoes without
/// changing its contents. The aggregate config is already committed when this
/// is called, so shoes rereads the new path atomically.
pub fn notify_hot_reload_anchor() -> Result<()> {
    let anchor = Path::new(HOT_RELOAD_ANCHOR_FILE);
    let mut file = File::options()
        .read(true)
        .write(true)
        .open(anchor)
        .with_context(|| format!("打开 shoes 热重载锚点失败：{}", anchor.display()))?;
    let length = file.metadata()?.len();
    if length == 0 {
        file.set_len(0)?;
    } else {
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&byte)?;
    }
    file.sync_all().context("同步 shoes 热重载锚点失败")
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
    fn pinned_shoes_watches_repeated_atomic_config_replacements() {
        let Some(binary) = std::env::var_os("PING_RUST_SHOES_E2E_BIN") else {
            return;
        };
        let work = tempfile::tempdir().unwrap();
        let config = work.path().join("config.yaml");
        let ports = (0..3)
            .map(|_| {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                listener.local_addr().unwrap().port()
            })
            .collect::<Vec<_>>();
        let yaml = |port| {
            format!(
            "- address: 127.0.0.1:{port}\n  protocol:\n    type: socks\n    udp_enabled: false\n  rules:\n  - allow-all-direct\n"
        )
        };
        atomic_write(&config, yaml(ports[0]).as_bytes(), 0o600).unwrap();
        let anchor = work.path().join("config-watch-anchor");
        fs::hard_link(&config, &anchor).unwrap();
        let log_file = std::fs::File::create(work.path().join("shoes.log")).unwrap();
        let mut process = std::process::Command::new(binary)
            .arg(&config)
            .stdout(log_file.try_clone().unwrap())
            .stderr(log_file)
            .spawn()
            .unwrap();
        let probe = |port| std::net::TcpStream::connect(("127.0.0.1", port)).is_ok();
        let wait = |port, expected| {
            for _ in 0..100 {
                if probe(port) == expected {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            false
        };
        let initial = wait(ports[0], true);
        let mut replacements = Vec::new();
        if initial {
            for index in 1..3 {
                atomic_write(&config, yaml(ports[index]).as_bytes(), 0o600).unwrap();
                let first_byte = fs::read(&anchor).unwrap()[0];
                File::options()
                    .write(true)
                    .open(&anchor)
                    .unwrap()
                    .write_all(&[first_byte])
                    .unwrap();
                replacements.push((wait(ports[index], true), wait(ports[index - 1], false)));
            }
        }
        let _ = process.kill();
        let _ = process.wait();
        let log = std::fs::read_to_string(work.path().join("shoes.log")).unwrap();
        println!("shoes hot reload probe: initial={initial}, replacements={replacements:?}\n{log}");
        assert!(initial, "initial shoes listener did not start");
        assert_eq!(replacements, vec![(true, true), (true, true)]);
    }

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
