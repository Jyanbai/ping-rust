//! SOCKS5 加固的只读计划与现有受管文件事务。
use std::{io::Read, net::SocketAddr, time::Duration};

use fs2::FileExt;

use super::transaction::FileAccess;
use super::*;
use crate::service::ShoesServiceHook;

const DRY_RUN_TIMEOUT: Duration = Duration::from_secs(15);
const PENDING_STATE: &str = ".ping-rust-socks5-secure.pending";
const PENDING_STOP: &str = ".ping-rust-socks5-secure.stop";
const UNFINISHED: &str = "上次 SOCKS5 加固未完成。请检查 shoes.service 和防火墙，从备份恢复一致的 config.yaml、profiles 和 ping-rust-state.json，验证服务后再移除 .ping-rust-socks5-secure.pending 和 .ping-rust-socks5-secure.stop（若存在）";
const DEFER_FILE_EXPORT: &str =
    "服务钩子无法将待验证的配置写入客户端文件，请在 SOCKS5 加固结束后重试文件导出";
const DEFER_DISPLAY: &str = "SOCKS5 加固期间的配置与已发布状态不一致，请在加固结束后重试读取";
#[cfg(target_os = "linux")]
const RETRY_READ: &str =
    "请在 SOCKS5 加固结束后重试读取；若此提示持续出现，请由管理员检查加固事务状态";

pub(crate) fn pending_exists(state_path: &Path) -> Result<bool> {
    state_path
        .with_file_name(PENDING_STATE)
        .try_exists()
        .context("无法检查 SOCKS5 加固事务状态")
}

pub(crate) fn require_finished(state_path: &Path) -> Result<()> {
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

enum PendingHook {
    Candidate(fs::File),
    PublishedOnly,
}

fn open_live_pending(state_path: &Path) -> Result<Option<PendingHook>> {
    let pending = match fs::File::open(state_path.with_file_name(PENDING_STATE)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            // 同步钩子可以通过已发布状态 inode 上的锁确认事务仍在运行。
            let published = fs::File::open(state_path).context("无法读取已发布的管理状态")?;
            require_live_lock(&published)?;
            return Ok(Some(PendingHook::PublishedOnly));
        }
        Err(error) => return Err(error).context("无法读取 SOCKS5 加固事务状态"),
    };
    require_live_lock(&pending)?;
    Ok(Some(PendingHook::Candidate(pending)))
}

fn require_live_lock(file: &fs::File) -> Result<()> {
    match FileExt::try_lock_shared(file) {
        Ok(()) => bail!("{UNFINISHED}"),
        Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => Ok(()),
        Err(error) => Err(error).context("无法检查 SOCKS5 加固事务锁"),
    }
}

enum HookRead<'a> {
    List,
    Profile(Option<&'a str>),
    ClientExport(Option<Uuid>),
}

#[derive(Serialize, Deserialize)]
struct PendingStop {
    profile: Uuid,
    view: StopView,
    #[serde(default)]
    config_restored: bool,
}

impl PendingStop {
    fn read(state_path: &Path) -> Result<Self> {
        let marker = fs::File::open(state_path.with_file_name(PENDING_STOP))
            .context("无法读取 SOCKS5 加固期间的钩子状态")?;
        serde_json::from_reader(marker).context("无法解析 SOCKS5 加固期间的钩子状态")
    }

    fn write(&self, state_path: &Path) -> Result<()> {
        // 仅保存节点、实例和恢复进度。委派钩子通过已发布状态的锁确认事务存活。
        utils::atomic_write(
            &state_path.with_file_name(PENDING_STOP),
            &serde_json::to_vec(self)?,
            0o644,
        )
        .context("无法保存 SOCKS5 加固期间的钩子状态")
    }
}

#[derive(Serialize, Deserialize)]
enum StopView {
    Activating { original: Uuid },
    RollingBack { candidate: Option<Uuid> },
    Unavailable,
}

pub(crate) fn read_info_state(
    state_path: &Path,
    service_hook: Option<ShoesServiceHook>,
    selector: Option<&str>,
) -> Result<Option<ManagedState>> {
    if let Some(hook) = service_hook {
        let read = selector.map_or(HookRead::List, |name| HookRead::Profile(Some(name)));
        if let Some(state) = read_pending_hook_state(state_path, hook, read)? {
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

pub(crate) fn read_export_state(
    state_path: &Path,
    service_hook: Option<ShoesServiceHook>,
    selector: Option<&str>,
) -> Result<ManagedState> {
    read_export_snapshot(state_path, service_hook, HookRead::Profile(selector))
}

pub(crate) fn read_client_export_state(
    state_path: &Path,
    service_hook: Option<ShoesServiceHook>,
    profile: Option<Uuid>,
) -> Result<ManagedState> {
    read_export_snapshot(state_path, service_hook, HookRead::ClientExport(profile))
}

fn read_export_snapshot(
    state_path: &Path,
    service_hook: Option<ShoesServiceHook>,
    read: HookRead<'_>,
) -> Result<ManagedState> {
    let Some(hook) = service_hook else {
        return load_state_from(state_path);
    };
    match read_pending_hook_state(state_path, hook, read)? {
        Some(state) => Ok(state),
        None => load_state_file(state_path),
    }
}

fn read_pending_hook_state(
    state_path: &Path,
    hook: ShoesServiceHook,
    read: HookRead<'_>,
) -> Result<Option<ManagedState>> {
    let Some(pending) = open_live_pending(state_path)? else {
        return Ok(None);
    };
    if let ShoesServiceHook::Stop(invocation) = hook {
        return read_stop_hook_state(state_path, invocation, read).map(Some);
    }
    let PendingHook::Candidate(pending) = pending else {
        // 仅有 state 读取权限时，通过事务标记确认启动的是候选还是已恢复配置。
        let stop = PendingStop::read(state_path)?;
        if stop.config_restored {
            return load_state_file(state_path).map(Some);
        }
        return read_unchanged_published(state_path, read, stop.profile).map(Some);
    };
    // 启动钩子读取本次启动使用的配置。回滚启动时聚合配置已恢复，优先使用原状态。
    let servers = load_servers(&state_path.with_file_name("config.yaml"))
        .map_err(|_| anyhow::anyhow!("无法读取 SOCKS5 加固期间的聚合配置，请检查 config.yaml"))?;
    let published = load_state_file(state_path).ok();
    if published
        .as_ref()
        .is_some_and(|state| ensure_servers_match_state(&servers, &state.profiles).is_ok())
    {
        return Ok(published);
    }
    let candidate = read_candidate(pending)?;
    ensure_servers_match_state(&servers, &candidate.profiles).map_err(|_| {
        anyhow::anyhow!("SOCKS5 加固期间的配置与状态不一致，请在加固结束后重试读取")
    })?;
    read_candidate_for_hook(candidate, published, read).map(Some)
}

fn read_stop_hook_state(
    state_path: &Path,
    invocation: Option<Uuid>,
    read: HookRead<'_>,
) -> Result<ManagedState> {
    let stop = PendingStop::read(state_path)?;
    let invocation = invocation.context("无法确认停止钩子对应的 shoes.service 实例")?;
    let uses_candidate = match stop.view {
        StopView::Activating { original } => invocation != original,
        StopView::RollingBack { candidate } => candidate == Some(invocation),
        StopView::Unavailable => bail!("无法确认停止钩子对应的 shoes.service 实例"),
    };
    if uses_candidate {
        // 停止钩子可能把链接、二维码或客户端配置保存到事务外。
        read_unchanged_published(state_path, read, stop.profile)
    } else {
        load_state_file(state_path)
    }
}

fn read_unchanged_published(
    state_path: &Path,
    read: HookRead<'_>,
    changed_profile: Uuid,
) -> Result<ManagedState> {
    let published = load_state_file(state_path)?;
    let (selected, defer) = match read {
        HookRead::List => bail!("{DEFER_DISPLAY}"),
        HookRead::Profile(selector) => (
            crate::client::select_profile(&published.profiles, selector)?,
            DEFER_DISPLAY,
        ),
        HookRead::ClientExport(selector) => (
            crate::client::select_export_profile(&published.profiles, selector)?,
            DEFER_FILE_EXPORT,
        ),
    };
    if selected.id == changed_profile {
        bail!("{defer}");
    }
    Ok(published)
}

fn read_candidate(pending: fs::File) -> Result<ManagedState> {
    serde_json::from_reader(pending).context("无法解析待发布的 SOCKS5 加固状态")
}

fn read_candidate_for_hook(
    candidate: ManagedState,
    published: Option<ManagedState>,
    read: HookRead<'_>,
) -> Result<ManagedState> {
    if let HookRead::ClientExport(selector) = read {
        if let Some(published) = published {
            let before = crate::client::select_export_profile(&published.profiles, selector)?;
            let after = crate::client::select_export_profile(&candidate.profiles, selector)?;
            if serde_json::to_value(before)? == serde_json::to_value(after)? {
                return Ok(published);
            }
        }
        bail!("{DEFER_FILE_EXPORT}");
    }
    Ok(candidate)
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
    pub(crate) original_invocation: Option<Uuid>,
    before_yaml: String,
    before_profile: String,
    rollback: Option<SecureRollback>,
    pending: Option<fs::File>,
    #[cfg(target_os = "linux")]
    state_lock: Option<fs::File>,
}

struct SecureRollback {
    config: FileSnapshot,
    state: FileSnapshot,
    profiles: ProfileDirectorySnapshot,
}

#[cfg(unix)]
struct FileLink {
    target: PathBuf,
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
impl FileLink {
    fn capture(path: &Path) -> Result<Option<Self>> {
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_symlink() {
            return Ok(None);
        }
        Ok(Some(Self {
            target: fs::read_link(path)?,
            uid: metadata.uid(),
            gid: metadata.gid(),
        }))
    }

    fn restore(&self, path: &Path) -> Result<()> {
        use std::os::unix::fs::{lchown, symlink, MetadataExt};

        let temporary = tempfile::tempdir_in(path.parent().context("受管文件没有父目录")?)?;
        let link = temporary.path().join("link");
        symlink(&self.target, &link)?;
        let metadata = fs::symlink_metadata(&link)?;
        if (metadata.uid(), metadata.gid()) != (self.uid, self.gid) {
            lchown(&link, Some(self.uid), Some(self.gid))?;
        }
        fs::rename(&link, path).with_context(|| format!("无法原子恢复软链接 {}", path.display()))
    }
}

struct FileSnapshot {
    contents: Vec<u8>,
    access: FileAccess,
    #[cfg(unix)]
    link: Option<FileLink>,
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn socks5_secure_preserves_aggregate_label_on_atomic_commit_and_rollback() {
    use rustix::fs::{getxattr, setxattr, XattrFlags};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    fs::write(&path, b"original").unwrap();
    // 模拟与父目录默认值不同的标签，使测试也能在未启用 SELinux 的 CI 上运行。
    let attribute = "user.ping_rust_test_selinux";
    let label = b"system_u:object_r:shoes_conf_t:s0\0";
    setxattr(&path, attribute, label, XattrFlags::empty()).unwrap();
    let original = FileSnapshot::capture(&path, &fs::File::open(&path).unwrap()).unwrap();

    let assert_file = |contents: &[u8]| {
        assert_eq!(fs::read(&path).unwrap(), contents);
        let mut value = [0; 64];
        let len = getxattr(&path, attribute, value.as_mut_slice()).unwrap();
        assert_eq!(&value[..len], label);
    };
    original.write(&path, b"candidate").unwrap();
    assert_file(b"candidate");
    original.restore(&path, &original.contents).unwrap();
    assert_file(b"original");
    assert!(original.restored(&path));
}

impl FileSnapshot {
    fn capture(path: &Path, mut file: &fs::File) -> Result<Self> {
        #[cfg(not(unix))]
        let _ = path;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        Ok(Self {
            contents,
            access: FileAccess::capture(file).context("无法读取文件访问权限")?,
            #[cfg(unix)]
            link: FileLink::capture(path).context("无法备份软链接")?,
        })
    }

    fn restore(&self, path: &Path, contents: &[u8]) -> Result<()> {
        if self.restored(path) {
            return Ok(());
        }
        #[cfg(unix)]
        if let Some(link) = &self.link {
            link.restore(path)?;
            if !self.restored(path) {
                bail!(
                    "软链接 {} 已恢复，但目标文件已变更，请检查目标文件",
                    path.display()
                );
            }
            return Ok(());
        }
        self.write(path, contents)
    }

    fn write(&self, path: &Path, contents: &[u8]) -> Result<()> {
        utils::atomic_write_with(path, contents, |file| self.access.apply(file))
    }

    fn restored(&self, path: &Path) -> bool {
        let Ok(file) = fs::File::open(path) else {
            return false;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let Ok(entry) = fs::symlink_metadata(path) else {
                return false;
            };
            let entry_restored = match &self.link {
                Some(link) => {
                    entry.is_symlink()
                        && (entry.uid(), entry.gid()) == (link.uid, link.gid)
                        && fs::read_link(path).is_ok_and(|target| target == link.target)
                }
                None => entry.is_file(),
            };
            if !entry_restored {
                return false;
            }
        }
        let mut contents = Vec::new();
        FileAccess::capture(&file).is_ok_and(|access| access == self.access)
            && (&file).read_to_end(&mut contents).is_ok()
            && contents == self.contents
    }

    fn save_state(&self, path: &Path, state: &ManagedState) -> Result<()> {
        let contents = serde_json::to_vec_pretty(state).context("序列化管理状态失败")?;
        self.write(path, &contents)
    }
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
            original_invocation: None,
            before_yaml,
            before_profile,
            rollback: None,
            pending: None,
            #[cfg(target_os = "linux")]
            state_lock: None,
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

    pub(crate) fn other_listeners(&self) -> impl Iterator<Item = (&str, bool)> {
        self.servers
            .iter()
            .zip(&self.state.profiles)
            .filter(|(_, profile)| profile.id != self.profile.id)
            .map(|(server, _)| {
                (
                    server.address.as_str(),
                    server.transport.as_deref() == Some("quic"),
                )
            })
    }

    pub(crate) fn other_socks5_profiles(&self) -> impl Iterator<Item = &ManagedProfile> {
        self.state.profiles.iter().filter(|profile| {
            profile.id != self.profile.id && profile.protocol() == Protocol::Socks5
        })
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
            config: FileSnapshot::capture(&config, &original_config)
                .context("无法备份原聚合配置")?,
            state: FileSnapshot::capture(&state, &original_state_file)
                .context("无法备份原管理状态")?,
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
        if let Some(original) = self.original_invocation {
            if let Err(error) = self.write_pending_stop(StopView::Activating { original }) {
                if let Err(cleanup) = self.finish_pending() {
                    return Err(error.context(format!("清理 SOCKS5 加固事务状态失败：{cleanup:#}")));
                }
                return Err(error);
            }
        }
        // 候选及回滚启动期间保留当前状态 inode 的独占锁，供委派钩子确认事务存活。
        #[cfg(target_os = "linux")]
        let mut state_lock = original_state_file;
        #[cfg(not(target_os = "linux"))]
        drop(original_state_file);
        let commit = commit::commit_managed_with_writers(
            &config,
            &state,
            &profiles,
            &self.servers,
            &self.state,
            |path, _| match original_state {
                Some(original_state) => {
                    rollback.state.save_state(path, &original_state)?;
                    #[cfg(target_os = "linux")]
                    {
                        let state = fs::File::open(path).context("无法打开已迁移的管理状态")?;
                        FileExt::try_lock_exclusive(&state).context("无法锁定已迁移的管理状态")?;
                        state_lock = state;
                    }
                    Ok(())
                }
                None => Ok(()),
            },
            |path, write| match write {
                commit::ManagedWrite::Profiles(documents) => {
                    commit::write_profile_documents_with_access(path, documents, &rollback.profiles)
                }
                commit::ManagedWrite::Config(contents) => rollback.config.write(path, contents),
                commit::ManagedWrite::RestoreConfig(contents) => {
                    rollback.config.restore(path, contents)
                }
                commit::ManagedWrite::RestoreState(contents) => {
                    rollback.state.restore(path, contents)
                }
            },
        );
        if let Err(error) = commit {
            // 提交函数已尝试回滚。确认原文件都在，再允许后续读写。
            let restored = rollback.config.restored(&config)
                && rollback.state.restored(&state)
                && ProfileDirectorySnapshot::capture(&profiles)
                    .is_ok_and(|snapshot| snapshot == rollback.profiles);
            if restored {
                if let Err(cleanup) = self.finish_pending() {
                    return Err(error.context(format!("清理 SOCKS5 加固事务状态失败：{cleanup:#}")));
                }
            }
            return Err(error);
        }
        #[cfg(target_os = "linux")]
        {
            self.state_lock = Some(state_lock);
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
            match fs::remove_file(self.directory.join(PENDING_STOP)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("无法清理 SOCKS5 加固停止钩子状态"),
            }
            fs::remove_file(self.directory.join(PENDING_STATE))
                .context("无法清理 SOCKS5 加固事务状态")?;
            self.pending = None;
            #[cfg(target_os = "linux")]
            {
                self.state_lock = None;
            }
        }
        Ok(())
    }

    pub(crate) fn capture_rollback_stop(&self, invocation: Result<Option<Uuid>>) -> Result<()> {
        let view = match invocation {
            Ok(current) => StopView::RollingBack {
                candidate: current.filter(|id| Some(*id) != self.original_invocation),
            },
            Err(_) => StopView::Unavailable,
        };
        self.write_pending_stop(view)
    }

    fn write_pending_stop(&self, view: StopView) -> Result<()> {
        PendingStop {
            profile: self.profile.id,
            view,
            config_restored: false,
        }
        .write(&self.directory.join("ping-rust-state.json"))
    }

    pub(crate) fn mark_config_restored(&self) -> Result<()> {
        if self.original_invocation.is_some() {
            let state_path = self.directory.join("ping-rust-state.json");
            let mut marker = PendingStop::read(&state_path)?;
            marker.config_restored = true;
            marker.write(&state_path)?;
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
        match rollback.config.restore(
            &self.directory.join("config.yaml"),
            &rollback.config.contents,
        ) {
            Ok(()) => {
                if let Err(error) = rollback.state.restore(
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
        #[cfg(target_os = "linux")]
        {
            self.state_lock = None;
            let state = fs::File::open(self.directory.join("ping-rust-state.json"))
                .context("无法打开已恢复的管理状态")?;
            FileExt::try_lock_exclusive(&state).context("无法锁定已恢复的管理状态")?;
            self.state_lock = Some(state);
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
