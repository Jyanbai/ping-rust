use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};

use super::{
    ChainProxyUpdateResult, DeletionResult, GenerationResult, ManagedProfile, ManagedState,
};
use crate::utils;

pub(super) struct ManagedRollback {
    pub(super) config: Option<Vec<u8>>,
    pub(super) state: Option<Vec<u8>>,
    pub(super) profiles: ProfileDirectorySnapshot,
    pub(super) generated_certificate: Option<PathBuf>,
    pub(super) generated_certificate_key: Option<PathBuf>,
}

#[derive(PartialEq, Eq)]
pub(super) struct ProfileDirectorySnapshot {
    directory: Option<FileAccess>,
    files: BTreeMap<String, ProfileDocumentSnapshot>,
}

#[derive(PartialEq, Eq)]
struct ProfileDocumentSnapshot {
    contents: Vec<u8>,
    access: FileAccess,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct FileAccess {
    permissions: fs::Permissions,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(target_os = "linux")]
    acl: Option<Vec<u8>>,
    #[cfg(target_os = "linux")]
    default_acl: Option<Vec<u8>>,
    #[cfg(target_os = "linux")]
    selinux_label: Option<Vec<u8>>,
}

impl FileAccess {
    pub(super) fn capture(file: &fs::File) -> io::Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata()?;
        Ok(Self {
            permissions: metadata.permissions(),
            #[cfg(unix)]
            uid: metadata.uid(),
            #[cfg(unix)]
            gid: metadata.gid(),
            #[cfg(target_os = "linux")]
            acl: read_file_xattr(file, ACCESS_ACL)?,
            #[cfg(target_os = "linux")]
            default_acl: if metadata.is_dir() {
                read_file_xattr(file, DEFAULT_ACL)?
            } else {
                None
            },
            #[cfg(target_os = "linux")]
            selinux_label: read_file_xattr(file, SELINUX_LABEL)?,
        })
    }

    pub(super) fn apply(&self, file: &fs::File) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{fchown, MetadataExt};

            let metadata = file.metadata()?;
            if (metadata.uid(), metadata.gid()) != (self.uid, self.gid) {
                fchown(file, Some(self.uid), Some(self.gid))?;
            }
        }
        #[cfg(target_os = "linux")]
        {
            // 在设置组权限前替换从父目录继承的 ACL。
            write_acl(file, ACCESS_ACL, self.acl.as_deref())?;
            if file.metadata()?.is_dir() {
                write_acl(file, DEFAULT_ACL, self.default_acl.as_deref())?;
            }
        }
        file.set_permissions(self.permissions.clone())?;
        #[cfg(target_os = "linux")]
        if let Some(label) = &self.selinux_label {
            use rustix::fs::{fsetxattr, XattrFlags};

            if read_file_xattr(file, SELINUX_LABEL)?.as_ref() != Some(label) {
                fsetxattr(file, SELINUX_LABEL, label, XattrFlags::empty())?;
            }
        }
        Ok(())
    }

    pub(super) fn apply_without_public_access(&self, file: &fs::File) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut access = self.clone();
            let mode = access.permissions.mode() & !0o007;
            access.permissions.set_mode(mode);
            #[cfg(target_os = "linux")]
            if let Some(acl) = &mut access.acl {
                // Linux POSIX ACL xattr v2：四字节头，后接八字节条目。
                for entry in acl[4..].chunks_exact_mut(8) {
                    if u16::from_le_bytes([entry[0], entry[1]]) == 0x20 {
                        entry[2..4].fill(0); // ACL_OTHER
                    }
                }
            }
            access.apply(file)
        }
        #[cfg(not(unix))]
        self.apply(file)
    }
}

#[cfg(target_os = "linux")]
const ACCESS_ACL: &str = "system.posix_acl_access";
#[cfg(target_os = "linux")]
const DEFAULT_ACL: &str = "system.posix_acl_default";
// 单元测试使用可写的 xattr，覆盖未启用 SELinux 的 runner。
#[cfg(target_os = "linux")]
const SELINUX_LABEL: &str = if cfg!(test) {
    "user.ping_rust_test_selinux"
} else {
    "security.selinux"
};

#[cfg(target_os = "linux")]
fn read_file_xattr(file: &fs::File, name: &str) -> io::Result<Option<Vec<u8>>> {
    use rustix::{
        fs::{fgetxattr, fgetxattr_query},
        io::Errno,
    };

    let size = match fgetxattr_query(file, name) {
        Ok(size) => size,
        Err(Errno::NODATA | Errno::OPNOTSUPP) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut value = vec![0; size];
    let len = fgetxattr(file, name, value.as_mut_slice())?;
    value.truncate(len);
    Ok(Some(value))
}

#[cfg(target_os = "linux")]
fn write_acl(file: &fs::File, name: &str, acl: Option<&[u8]>) -> io::Result<()> {
    use rustix::{
        fs::{fremovexattr, fsetxattr, XattrFlags},
        io::Errno,
    };

    if let Some(acl) = acl {
        fsetxattr(file, name, acl, XattrFlags::empty())?;
    } else {
        // 清除新路径可能从父目录继承的 ACL。
        match fremovexattr(file, name) {
            Ok(()) | Err(Errno::NODATA | Errno::OPNOTSUPP) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

impl GenerationResult {
    pub fn rollback_managed(&mut self) -> Result<()> {
        let rollback = self
            .rollback
            .take()
            .context("该生成结果不包含可回滚的系统配置事务")?;
        rollback.restore_to(
            Path::new(utils::CONFIG_FILE),
            Path::new(utils::STATE_FILE),
            Path::new(utils::PROFILES_DIR),
        )
    }

    pub fn finish_update(&mut self) {
        for path in [
            self.retired_certificate.take(),
            self.retired_certificate_key.take(),
        ] {
            if let Err(error) = remove_managed_credential(path.as_deref()) {
                eprintln!("警告：NaiveProxy 配置已更新，但旧自签名凭据清理失败：{error:#}");
            }
        }
    }
}

impl DeletionResult {
    pub fn rollback_managed(&mut self) -> Result<()> {
        let rollback = self
            .rollback
            .take()
            .context("该删除结果不包含可回滚的系统配置事务")?;
        rollback.restore_to(
            Path::new(utils::CONFIG_FILE),
            Path::new(utils::STATE_FILE),
            Path::new(utils::PROFILES_DIR),
        )
    }

    pub fn finish(self) -> ManagedProfile {
        self.finish_with(remove_managed_credential)
    }

    pub(super) fn finish_with(
        mut self,
        mut remove_credential: impl FnMut(Option<&Path>) -> Result<()>,
    ) -> ManagedProfile {
        self.rollback.take();
        if self.profile.self_signed_certificate {
            for path in [
                self.profile.certificate_path.as_deref(),
                self.profile.certificate_key_path.as_deref(),
            ] {
                if let Err(error) = remove_credential(path) {
                    eprintln!("警告：配置已删除，但清理凭据失败：{error:#}");
                }
            }
        }
        self.profile
    }
}

impl ChainProxyUpdateResult {
    pub fn rollback_managed(&mut self) -> Result<()> {
        let rollback = self
            .rollback
            .take()
            .context("该链式代理更新不包含可回滚的系统配置事务")?;
        rollback.restore_to(
            Path::new(utils::CONFIG_FILE),
            Path::new(utils::STATE_FILE),
            Path::new(utils::PROFILES_DIR),
        )
    }

    pub fn finish(mut self) -> ManagedState {
        self.rollback.take();
        self.state
    }
}

impl ManagedRollback {
    pub(super) fn restore_to(
        self,
        config_path: &Path,
        state_path: &Path,
        profiles_path: &Path,
    ) -> Result<()> {
        let state_result = restore_snapshot(state_path, self.state.as_deref(), 0o600);
        let config_result = restore_snapshot(config_path, self.config.as_deref(), 0o600);
        let profiles_result = self.profiles.restore(profiles_path);
        for path in [
            self.generated_certificate.as_deref(),
            self.generated_certificate_key.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if path.exists() {
                fs::remove_file(path)
                    .with_context(|| format!("删除回滚凭据 {} 失败", path.display()))?;
            }
        }
        let mut failures = Vec::new();
        if let Err(error) = state_result {
            failures.push(format!("状态={error:#}"));
        }
        if let Err(error) = config_result {
            failures.push(format!("聚合配置={error:#}"));
        }
        if let Err(error) = profiles_result {
            failures.push(format!("节点目录={error:#}"));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!("恢复受管配置失败：{}", failures.join("；"))
        }
    }
}

impl ProfileDirectorySnapshot {
    pub(super) fn existed(&self) -> bool {
        self.directory.is_some()
    }

    pub(super) fn matches_documents(&self, documents: &BTreeMap<String, Vec<u8>>) -> bool {
        self.files
            .iter()
            .map(|(name, snapshot)| (name, &snapshot.contents))
            .eq(documents)
    }

    pub(super) fn capture(path: &Path) -> Result<Self> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| format!("读取节点目录 {} 失败", path.display()))
            }
        };
        let Some(metadata) = metadata else {
            return Ok(Self {
                directory: None,
                files: BTreeMap::new(),
            });
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("节点目录不是普通目录：{}", path.display());
        }
        #[cfg(unix)]
        let directory = fs::File::open(path)
            .and_then(|file| FileAccess::capture(&file))
            .with_context(|| format!("备份节点目录 {} 的访问权限失败", path.display()))?;
        #[cfg(not(unix))]
        let directory = FileAccess {
            permissions: metadata.permissions(),
        };
        let mut files = BTreeMap::new();
        for entry in
            fs::read_dir(path).with_context(|| format!("读取节点目录 {} 失败", path.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                bail!(
                    "节点目录包含链接、目录或特殊文件：{}",
                    entry.path().display()
                );
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("节点文件名不是 UTF-8：{}", entry.path().display()))?;
            let mut file = fs::File::open(entry.path())
                .with_context(|| format!("打开节点文件 {} 失败", entry.path().display()))?;
            let mut contents = Vec::new();
            file.read_to_end(&mut contents)
                .with_context(|| format!("读取节点文件 {} 失败", entry.path().display()))?;
            let access = FileAccess::capture(&file).with_context(|| {
                format!("备份节点文件 {} 的访问权限失败", entry.path().display())
            })?;
            files.insert(name, ProfileDocumentSnapshot { contents, access });
        }
        Ok(Self {
            directory: Some(directory),
            files,
        })
    }

    pub(super) fn write_profile(
        &self,
        directory: &Path,
        name: &str,
        contents: &[u8],
        protect_credentials: bool,
    ) -> Result<()> {
        let path = directory.join(name);
        if let Some(snapshot) = self.files.get(name) {
            utils::atomic_write_with(&path, contents, |file| {
                if protect_credentials {
                    snapshot.access.apply_without_public_access(file)
                } else {
                    snapshot.access.apply(file)
                }
            })
        } else {
            utils::atomic_write(&path, contents, 0o600)
        }
    }

    pub(super) fn restore(self, path: &Path) -> Result<()> {
        if path.exists() {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                fs::remove_dir_all(path)
                    .with_context(|| format!("清理节点目录 {} 失败", path.display()))?;
            } else {
                fs::remove_file(path)
                    .with_context(|| format!("清理节点路径 {} 失败", path.display()))?;
            }
        }
        let Some(directory) = &self.directory else {
            return Ok(());
        };
        utils::ensure_directory(path, 0o700)?;
        for (name, snapshot) in &self.files {
            utils::atomic_write_with(&path.join(name), &snapshot.contents, |file| {
                snapshot.access.apply(file)
            })?;
        }
        #[cfg(unix)]
        let restored = fs::File::open(path).and_then(|file| directory.apply(&file));
        #[cfg(not(unix))]
        let restored = fs::set_permissions(path, directory.permissions.clone());
        restored.with_context(|| format!("恢复节点目录 {} 的访问权限失败", path.display()))
    }
}

pub(super) fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("读取 {} 失败", path.display())),
    }
}

pub(super) fn restore_snapshot(path: &Path, contents: Option<&[u8]>, mode: u32) -> Result<()> {
    if let Some(contents) = contents {
        utils::atomic_write(path, contents, mode)
    } else if path.exists() {
        fs::remove_file(path).with_context(|| format!("删除回滚目标 {} 失败", path.display()))
    } else {
        Ok(())
    }
}

pub(super) struct CredentialCleanup {
    paths: Vec<PathBuf>,
    armed: bool,
}

impl CredentialCleanup {
    pub(super) fn new(self_signed: bool, cert: Option<&Path>, key: Option<&Path>) -> Self {
        let paths = if self_signed {
            [cert, key]
                .into_iter()
                .flatten()
                .map(Path::to_path_buf)
                .collect()
        } else {
            Vec::new()
        };
        Self { paths, armed: true }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CredentialCleanup {
    fn drop(&mut self) {
        if self.armed {
            for path in &self.paths {
                let _ = fs::remove_file(path);
            }
        }
    }
}

fn remove_managed_credential(path: Option<&Path>) -> Result<()> {
    let Some(path) = path else { return Ok(()) };
    if !path.starts_with(Path::new(utils::CONFIG_DIR)) {
        bail!("拒绝删除配置目录之外的凭据文件 {}", path.display());
    }
    if path.is_file() {
        fs::remove_file(path).with_context(|| format!("删除凭据文件 {} 失败", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_cleanup_removes_only_armed_self_signed_files() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("certificate.pem");
        let key = directory.path().join("private-key.pem");
        fs::write(&certificate, b"certificate").unwrap();
        fs::write(&key, b"private-key").unwrap();

        {
            let _cleanup = CredentialCleanup::new(true, Some(&certificate), Some(&key));
        }
        assert!(!certificate.exists());
        assert!(!key.exists());

        fs::write(&certificate, b"external-certificate").unwrap();
        fs::write(&key, b"external-private-key").unwrap();
        {
            let _cleanup = CredentialCleanup::new(false, Some(&certificate), Some(&key));
        }
        assert_eq!(fs::read(&certificate).unwrap(), b"external-certificate");
        assert_eq!(fs::read(&key).unwrap(), b"external-private-key");
    }

    #[test]
    fn credential_cleanup_disarm_preserves_committed_files() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("certificate.pem");
        let key = directory.path().join("private-key.pem");
        fs::write(&certificate, b"certificate").unwrap();
        fs::write(&key, b"private-key").unwrap();

        {
            let mut cleanup = CredentialCleanup::new(true, Some(&certificate), Some(&key));
            cleanup.disarm();
        }

        assert_eq!(fs::read(&certificate).unwrap(), b"certificate");
        assert_eq!(fs::read(&key).unwrap(), b"private-key");
    }
}
