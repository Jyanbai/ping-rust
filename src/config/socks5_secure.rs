//! SOCKS5 加固的只读计划与现有受管文件事务。
use std::{io::Read, net::SocketAddr, time::Duration};

use fs2::FileExt;

use super::*;

const DRY_RUN_TIMEOUT: Duration = Duration::from_secs(15);
const PENDING_STATE: &str = ".ping-rust-socks5-secure.pending";
const UNFINISHED: &str = "上次 SOCKS5 加固未完成。请检查 shoes.service 和防火墙，从备份恢复一致的 config.yaml、profiles 和 ping-rust-state.json，验证服务后再移除 .ping-rust-socks5-secure.pending";
#[cfg(target_os = "linux")]
const ACCESS_ACL: &str = "system.posix_acl_access";
#[cfg(target_os = "linux")]
const RETRY_READ: &str =
    "请在 SOCKS5 加固结束后重试读取；若此提示持续出现，请由管理员检查加固事务状态";

fn pending_exists(state_path: &Path) -> Result<bool> {
    state_path
        .with_file_name(PENDING_STATE)
        .try_exists()
        .context("无法检查 SOCKS5 加固事务状态")
}

pub(super) fn require_finished(state_path: &Path) -> Result<()> {
    if pending_exists(state_path)? {
        bail!("{UNFINISHED}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn read_unlocked_snapshot<T>(
    state_path: &Path,
    read: impl FnOnce() -> Result<T>,
) -> Result<T> {
    use std::{io, os::unix::fs::MetadataExt};

    let identity = |path: &Path| match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some((
            meta.dev(),
            meta.ino(),
            meta.ctime(),
            meta.ctime_nsec(),
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("无法检查受管文件是否已变更"),
    };
    let config_path = state_path.with_file_name("config.yaml");
    let generation = || Ok::<_, anyhow::Error>((identity(state_path)?, identity(&config_path)?));
    let check_pending = || {
        if pending_exists(state_path)? {
            bail!("{RETRY_READ}");
        }
        Ok(())
    };

    // 兼容旧状态时也可能读取聚合配置。
    check_pending()?;
    let before = generation()?;
    let result = read();
    let after = generation()?;
    check_pending()?;
    if before != after {
        bail!("读取期间受管配置已变更，请重试");
    }
    result
}

#[cfg(target_os = "linux")]
pub(crate) fn lock_state_for_file_export(state_path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::MetadataExt;

    let file = fs::File::open(state_path).context("无法读取文件导出所需的管理状态")?;
    match FileExt::try_lock_shared(&file) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
            bail!("{RETRY_READ}");
        }
        Err(error) => return Err(error).context("无法锁定文件导出所需的管理状态"),
    }
    // 打开与加锁之间可能已发布新 inode。不能用旧 inode 的锁保护新快照。
    let locked = file.metadata().context("无法检查加锁的管理状态")?;
    let current = fs::metadata(state_path).context("无法检查当前管理状态")?;
    if (locked.dev(), locked.ino()) != (current.dev(), current.ino()) {
        bail!("读取期间受管配置已变更，请重试");
    }
    Ok(file)
}

pub(crate) fn load_for_plan(state_path: &Path) -> Result<ManagedState> {
    require_finished(state_path)?;
    load_state_file(state_path).map_err(|_| {
        anyhow::anyhow!("无法读取 SOCKS5 管理状态，请检查 ping-rust-state.json 和 config.yaml")
    })
}

fn open_live_pending(state_path: &Path) -> Result<Option<fs::File>> {
    let file = match fs::File::open(state_path.with_file_name(PENDING_STATE)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("无法读取 SOCKS5 加固事务状态"),
    };
    match FileExt::try_lock_shared(&file) {
        Ok(()) => bail!("{UNFINISHED}"),
        Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
            Ok(Some(file))
        }
        Err(error) => Err(error).context("无法检查 SOCKS5 加固事务锁"),
    }
}

pub(crate) fn read_info_state(
    state_path: &Path,
    service_hook: bool,
) -> Result<Option<ManagedState>> {
    if service_hook {
        if let Some(state) = read_pending_hook_state(state_path, true)? {
            return Ok(Some(state));
        }
    } else {
        require_finished(state_path)?;
    }
    state_path
        .try_exists()?
        .then(|| load_state_file(state_path))
        .transpose()
}

pub(crate) fn read_export_state(state_path: &Path, service_hook: bool) -> Result<ManagedState> {
    read_export_snapshot(state_path, service_hook, true)
}

pub(crate) fn read_file_export_state(
    state_path: &Path,
    service_hook: bool,
) -> Result<ManagedState> {
    read_export_snapshot(state_path, service_hook, false)
}

fn read_export_snapshot(
    state_path: &Path,
    service_hook: bool,
    allow_candidate: bool,
) -> Result<ManagedState> {
    if !service_hook {
        return load_state_from(state_path);
    }
    match read_pending_hook_state(state_path, allow_candidate)? {
        Some(state) => Ok(state),
        None => load_state_file(state_path),
    }
}

fn read_pending_hook_state(
    state_path: &Path,
    allow_candidate: bool,
) -> Result<Option<ManagedState>> {
    let Some(pending) = open_live_pending(state_path)? else {
        return Ok(None);
    };
    // 同步钩子应读取本次启动使用的配置。回滚启动时聚合配置已恢复，优先使用原状态。
    let servers = load_servers(&state_path.with_file_name("config.yaml"))
        .map_err(|_| anyhow::anyhow!("无法读取 SOCKS5 加固期间的聚合配置，请检查 config.yaml"))?;
    if let Ok(published) = load_state_file(state_path) {
        if ensure_servers_match_state(&servers, &published.profiles).is_ok() {
            return Ok(Some(published));
        }
    }
    if !allow_candidate {
        bail!("启动钩子无法将待验证的配置写入客户端文件，请在 SOCKS5 加固结束后重试文件导出");
    }
    let candidate: ManagedState =
        serde_json::from_reader(pending).context("无法解析待发布的 SOCKS5 加固状态")?;
    ensure_servers_match_state(&servers, &candidate.profiles).map_err(|_| {
        anyhow::anyhow!("SOCKS5 加固期间的配置与状态不一致，请在加固结束后重试读取")
    })?;
    Ok(Some(candidate))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SecureMode {
    Auth,
    Local,
}

pub(crate) struct SecurePlan {
    directory: PathBuf,
    servers: Vec<ServerConfig>,
    state: ManagedState,
    pub(crate) original: ManagedProfile,
    pub(crate) profile: ManagedProfile,
    before_yaml: String,
    before_profile: String,
    rollback: Option<SecureRollback>,
    pending: Option<fs::File>,
}

struct SecureRollback {
    config: FileSnapshot,
    state: FileSnapshot,
    profiles: ProfileDirectorySnapshot,
}

struct FileSnapshot {
    contents: Vec<u8>,
    metadata: fs::Metadata,
    #[cfg(target_os = "linux")]
    acl: Option<Vec<u8>>,
}

impl FileSnapshot {
    fn capture(mut file: &fs::File) -> Result<Self> {
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        Ok(Self {
            contents,
            metadata: file.metadata()?,
            #[cfg(target_os = "linux")]
            acl: access_acl(file).context("无法读取文件 ACL")?,
        })
    }

    fn write(&self, path: &Path, contents: &[u8]) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{fchown, MetadataExt};
            utils::atomic_write_with(path, contents, |file| {
                let owner = &self.metadata;
                let temporary = file.metadata()?;
                if (temporary.uid(), temporary.gid()) != (owner.uid(), owner.gid()) {
                    fchown(file, Some(owner.uid()), Some(owner.gid()))?;
                }
                file.set_permissions(owner.permissions())?;
                #[cfg(target_os = "linux")]
                match &self.acl {
                    Some(acl) => rustix::fs::fsetxattr(
                        file,
                        ACCESS_ACL,
                        acl,
                        rustix::fs::XattrFlags::empty(),
                    )?,
                    // 清除临时文件可能从父目录继承的 ACL。
                    None => match rustix::fs::fremovexattr(file, ACCESS_ACL) {
                        Ok(()) | Err(rustix::io::Errno::NODATA | rustix::io::Errno::OPNOTSUPP) => {}
                        Err(error) => return Err(error.into()),
                    },
                }
                Ok(())
            })
        }
        #[cfg(not(unix))]
        utils::atomic_write(path, contents, 0o600)
    }

    fn restored(&self, path: &Path) -> bool {
        let Ok(file) = fs::File::open(path) else {
            return false;
        };
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (metadata.uid(), metadata.gid(), metadata.mode())
                != (
                    self.metadata.uid(),
                    self.metadata.gid(),
                    self.metadata.mode(),
                )
            {
                return false;
            }
        }
        #[cfg(target_os = "linux")]
        if !access_acl(&file).is_ok_and(|acl| acl == self.acl) {
            return false;
        }
        let mut contents = Vec::new();
        metadata.permissions() == self.metadata.permissions()
            && (&file).read_to_end(&mut contents).is_ok()
            && contents == self.contents
    }

    fn save_state(&self, path: &Path, state: &ManagedState) -> Result<()> {
        let contents = serde_json::to_vec_pretty(state).context("序列化管理状态失败")?;
        self.write(path, &contents)
    }
}

#[cfg(target_os = "linux")]
fn access_acl(file: &fs::File) -> std::io::Result<Option<Vec<u8>>> {
    use rustix::{
        fs::{fgetxattr, fgetxattr_query},
        io::Errno,
    };

    let size = match fgetxattr_query(file, ACCESS_ACL) {
        Ok(size) => size,
        Err(Errno::NODATA | Errno::OPNOTSUPP) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut value = vec![0; size];
    let len = fgetxattr(file, ACCESS_ACL, value.as_mut_slice())?;
    value.truncate(len);
    Ok(Some(value))
}

impl SecurePlan {
    fn load_checked(
        directory: &Path,
        id: Uuid,
    ) -> Result<(ManagedState, Vec<ServerConfig>, usize)> {
        let state = load_for_plan(&directory.join("ping-rust-state.json"))?;
        let index = state
            .profiles
            .iter()
            .position(|p| p.id == id)
            .context("未找到 SOCKS5 节点")?;
        if state.profiles[index].protocol() != Protocol::Socks5 {
            bail!("只有 SOCKS5 节点支持 secure");
        }
        let servers = load_servers(&directory.join("config.yaml"))
            .map_err(|_| anyhow::anyhow!("无法读取 SOCKS5 的聚合配置，请检查 config.yaml"))?;
        ensure_servers_match_state(&servers, &state.profiles).map_err(|_| {
            anyhow::anyhow!("聚合配置与管理状态不一致，请检查 config.yaml 和 ping-rust-state.json")
        })?;
        Ok((state, servers, index))
    }

    pub(crate) fn already_secure(directory: &Path, id: Uuid) -> Result<bool> {
        Ok(Self::secure_profile(directory, id)?.is_some())
    }

    pub(crate) fn secure_profile(directory: &Path, id: Uuid) -> Result<Option<ManagedProfile>> {
        let (state, _, index) = Self::load_checked(directory, id)?;
        let profile = state.profiles.into_iter().nth(index).unwrap();
        Ok(profile.socks5_risk_warning().is_none().then_some(profile))
    }

    pub(crate) fn prepare(directory: &Path, id: Uuid, mode: SecureMode) -> Result<Option<Self>> {
        let (mut state, mut servers, index) = Self::load_checked(directory, id)?;
        let original = state.profiles[index].clone();
        if original.socks5_risk_warning().is_none() {
            return Ok(None);
        }
        ensure_chain_proxy_matches_state(&servers, &state)?;
        let before_yaml = redacted_aggregate(&servers, index)?;
        let before_profile = crate::yaml::to_string(&redacted_profile(&servers[index])?)?;
        match mode {
            SecureMode::Auth => apply_profile_change(
                &mut servers[index],
                &mut state.profiles[index],
                ProfileChange::Socks5Authentication(true),
            )?,
            SecureMode::Local => {
                let Credentials::Socks5 {
                    listen: Some(listen),
                    ..
                } = &mut state.profiles[index].credentials
                else {
                    unreachable!()
                };
                let loopback = if listen.address.contains(':') {
                    "::1"
                } else {
                    "127.0.0.1"
                };
                *listen = Socks5Listen::new(loopback);
                state.profiles[index].server_address = Some(loopback.to_owned());
                servers[index].address = state.profiles[index].listen_address()?;
                state.profiles[index].validate_socks5_listen()?;
            }
        }
        ensure_servers_match_state(&servers, &state.profiles)?;
        let profile = state.profiles[index].clone();
        Ok(Some(Self {
            directory: directory.to_path_buf(),
            servers,
            state,
            original,
            profile,
            before_yaml,
            before_profile,
            rollback: None,
            pending: None,
        }))
    }

    pub(crate) fn diff(&self) -> Result<String> {
        let index = self
            .state
            .profiles
            .iter()
            .position(|p| p.id == self.profile.id)
            .unwrap();
        let mut output = String::new();
        for (name, before, after) in [
            (
                format!("profiles/{} (profile)", self.profile.config_file_name()),
                &self.before_profile,
                crate::yaml::to_string(&redacted_profile(&self.servers[index])?)?,
            ),
            (
                "config.yaml".to_owned(),
                &self.before_yaml,
                redacted_aggregate(&self.servers, index)?,
            ),
        ] {
            output.push_str(&format!("--- {name}\n+++ {name}\n"));
            for line in before.lines() {
                output.push_str(&format!("-{line}\n"));
            }
            for line in after.lines() {
                output.push_str(&format!("+{line}\n"));
            }
        }
        Ok(output)
    }

    pub(crate) async fn validate(
        &self,
        interrupt: &crate::socks5_secure::InterruptGuard<'_>,
    ) -> Result<()> {
        if !utils::command_exists(utils::SHOES_BIN) {
            bail!("未找到可执行的 shoes，请先安装 shoes 后重试");
        }
        let yaml = crate::yaml::to_string(&self.servers)?;
        validate_yaml(&yaml)?;
        let deadline_or_signal = async {
            tokio::select! {
                biased;
                error = interrupt.cancelled() => error,
                _ = tokio::time::sleep(DRY_RUN_TIMEOUT) =>
                    anyhow::anyhow!("shoes 配置校验超时，请检查 shoes 后重试"),
            }
        };
        validate_candidate_with_shoes_until(&yaml, &self.directory, Some(deadline_or_signal)).await
    }

    pub(crate) fn commit_files(&mut self) -> Result<()> {
        let config = self.directory.join("config.yaml");
        let state = self.directory.join("ping-rust-state.json");
        let profiles = self.directory.join("profiles");
        let original_config = fs::File::open(&config).context("无法读取原聚合配置")?;
        let original_state_file = fs::File::open(&state).context("无法读取原管理状态")?;
        #[cfg(target_os = "linux")]
        match FileExt::try_lock_exclusive(&original_state_file) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
                bail!("有客户端文件导出正在读取管理状态，请在导出结束后重试加固");
            }
            Err(error) => return Err(error).context("无法锁定原管理状态"),
        }
        let rollback = SecureRollback {
            config: FileSnapshot::capture(&original_config).context("无法备份原聚合配置")?,
            state: FileSnapshot::capture(&original_state_file).context("无法备份原管理状态")?,
            profiles: ProfileDirectorySnapshot::capture(&profiles)?,
        };
        let original_state = if socks5::listen_migration_pending(&state)? {
            // 在替换聚合配置前保存旧监听，避免无锁读者把临时回环监听迁移进旧状态。
            let mut original_state = self.state.clone();
            let profile = original_state
                .profiles
                .iter_mut()
                .find(|profile| profile.id == self.original.id)
                .context("未找到 SOCKS5 节点")?;
            *profile = self.original.clone();
            Some(original_state)
        } else {
            None
        };
        // 先留下可检测的事务状态，SIGKILL 后导出和重试也能识别未完成的写入。
        let mut pending = tempfile::NamedTempFile::new_in(&self.directory)
            .context("无法创建 SOCKS5 加固事务状态")?;
        utils::set_mode(pending.path(), 0o600)?;
        FileExt::lock_exclusive(pending.as_file()).context("无法锁定 SOCKS5 加固事务状态")?;
        serde_json::to_writer(pending.as_file_mut(), &self.state)
            .context("无法写入 SOCKS5 加固事务状态")?;
        pending
            .as_file()
            .sync_all()
            .context("无法同步 SOCKS5 加固事务状态")?;
        self.pending = Some(
            pending
                .persist_noclobber(self.directory.join(PENDING_STATE))
                .map_err(|error| error.error)
                .context("无法保存 SOCKS5 加固事务状态")?,
        );
        // 先持有原 inode 的独占锁，再让 pending 标记保护后续替换出的状态文件。
        drop(original_state_file);
        let commit = commit::commit_managed_with_writers(
            &config,
            &state,
            &profiles,
            &self.servers,
            &self.state,
            |path, _| match original_state {
                Some(original_state) => rollback.state.save_state(path, &original_state),
                None => Ok(()),
            },
            |path, contents| {
                if path == state.as_path() {
                    rollback.state.write(path, contents)
                } else {
                    rollback.config.write(path, contents)
                }
            },
        );
        if let Err(error) = commit {
            // 提交函数已尝试回滚。确认原文件都在，再允许后续读写。
            let restored = rollback.config.restored(&config)
                && rollback.state.restored(&state)
                && ProfileDirectorySnapshot::capture(&profiles).is_ok_and(|snapshot| {
                    snapshot.existed == rollback.profiles.existed
                        && snapshot.files == rollback.profiles.files
                });
            if restored {
                if let Err(cleanup) = self.finish_pending() {
                    return Err(error.context(format!("清理 SOCKS5 加固事务状态失败：{cleanup:#}")));
                }
            }
            return Err(error);
        }
        self.rollback = Some(rollback);
        Ok(())
    }

    pub(crate) fn publish_state(&mut self) -> Result<()> {
        let rollback = self
            .rollback
            .as_ref()
            .context("没有已提交的 SOCKS5 加固事务")?;
        rollback
            .state
            .save_state(&self.directory.join("ping-rust-state.json"), &self.state)
            .context("保存已验证的 SOCKS5 状态失败")?;
        self.finish_pending()?;
        self.rollback = None;
        Ok(())
    }

    pub(crate) fn finish_pending(&mut self) -> Result<()> {
        if self.pending.is_some() {
            fs::remove_file(self.directory.join(PENDING_STATE))
                .context("无法清理 SOCKS5 加固事务状态")?;
            self.pending = None;
        }
        Ok(())
    }

    pub(crate) fn rollback_files(&mut self) -> Result<()> {
        let rollback = self
            .rollback
            .take()
            .context("没有已提交的 SOCKS5 加固事务")?;
        let mut failures = Vec::new();
        // 先还原聚合配置，再恢复可能缺少显式 listen 的旧状态。
        match rollback.config.write(
            &self.directory.join("config.yaml"),
            &rollback.config.contents,
        ) {
            Ok(()) => {
                if let Err(error) = rollback.state.write(
                    &self.directory.join("ping-rust-state.json"),
                    &rollback.state.contents,
                ) {
                    failures.push(format!("状态={error:#}"));
                }
            }
            Err(error) => failures.push(format!("聚合配置={error:#}")),
        }
        if let Err(error) = rollback.profiles.restore(&self.directory.join("profiles")) {
            failures.push(format!("节点目录={error:#}"));
        }
        if !failures.is_empty() {
            bail!("恢复受管配置失败：{}", failures.join("；"));
        }
        Ok(())
    }
}

fn redacted_profile(server: &ServerConfig) -> Result<serde_json::Value> {
    let ServerProtocol::Socks {
        username,
        password,
        udp_enabled,
    } = &server.protocol
    else {
        bail!("预览目标不是 SOCKS5 配置");
    };
    // 只展示此命令涉及的字段。规则与其他节点可在值或映射键中携带地址和凭据。
    let listen: SocketAddr = server.address.parse().context("SOCKS5 监听地址无效")?;
    let address = if listen.ip().is_unspecified() || listen.ip().is_loopback() {
        server.address.clone()
    } else {
        format!("[REDACTED]:{}", listen.port())
    };
    let mut profile = serde_json::json!({
        "address": address,
        "protocol": { "type": "socks", "udp_enabled": udp_enabled }
    });
    if username.is_some() {
        profile["protocol"]["username"] = "[REDACTED]".into();
    }
    if password.is_some() {
        profile["protocol"]["password"] = "[REDACTED]".into();
    }
    if !server.rules.is_empty() {
        profile["rules"] = "[REDACTED]".into();
    }
    Ok(profile)
}

fn redacted_aggregate(servers: &[ServerConfig], index: usize) -> Result<String> {
    let mut preview = vec![serde_json::Value::from("[REDACTED]"); servers.len()];
    preview[index] = redacted_profile(&servers[index])?;
    Ok(crate::yaml::to_string(&preview)?)
}
