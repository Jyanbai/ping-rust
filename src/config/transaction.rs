use std::{
    collections::BTreeMap,
    fs,
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

pub(super) struct ProfileDirectorySnapshot {
    pub(super) existed: bool,
    pub(super) files: BTreeMap<String, Vec<u8>>,
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
                existed: false,
                files: BTreeMap::new(),
            });
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("节点目录不是普通目录：{}", path.display());
        }
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
            files.insert(
                name,
                fs::read(entry.path())
                    .with_context(|| format!("读取节点文件 {} 失败", entry.path().display()))?,
            );
        }
        Ok(Self {
            existed: true,
            files,
        })
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
        if !self.existed {
            return Ok(());
        }
        utils::ensure_directory(path, 0o700)?;
        for (name, contents) in self.files {
            utils::atomic_write(&path.join(name), &contents, 0o600)?;
        }
        Ok(())
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
