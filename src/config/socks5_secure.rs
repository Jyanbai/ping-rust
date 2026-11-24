//! SOCKS5 加固的只读计划与现有受管文件事务。
use std::{net::SocketAddr, time::Duration};

use fs2::FileExt;

use super::*;

const DRY_RUN_TIMEOUT: Duration = Duration::from_secs(15);
const PENDING_STATE: &str = ".ping-rust-socks5-secure.pending";
const UNFINISHED: &str = "上次 SOCKS5 加固未完成。请检查 shoes.service 和防火墙，从备份恢复一致的 config.yaml、profiles 和 ping-rust-state.json，验证服务后再移除 .ping-rust-socks5-secure.pending";

pub(super) fn require_finished(state_path: &Path) -> Result<()> {
    let path = state_path.with_file_name(PENDING_STATE);
    if path.try_exists().context("无法检查 SOCKS5 加固事务状态")? {
        bail!("{UNFINISHED}");
    }
    Ok(())
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
        if let Some(state) = read_pending_hook_state(state_path)? {
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
    if !service_hook {
        return load_state_from(state_path);
    }
    match read_pending_hook_state(state_path)? {
        Some(state) => Ok(state),
        None => load_state_file(state_path),
    }
}

fn read_pending_hook_state(state_path: &Path) -> Result<Option<ManagedState>> {
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
    rollback: Option<ManagedRollback>,
    pending: Option<fs::File>,
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
        let rollback = ManagedRollback {
            config: read_optional(&config)?,
            state: read_optional(&state)?,
            profiles: ProfileDirectorySnapshot::capture(&profiles)?,
            generated_certificate: None,
            generated_certificate_key: None,
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
        let commit = commit::commit_managed_with_state_writer(
            &config,
            &state,
            &profiles,
            &self.servers,
            &self.state,
            |path, _| match original_state {
                Some(original_state) => save_state_to(path, &original_state),
                None => Ok(()),
            },
        );
        if let Err(error) = commit {
            // 提交函数已尝试回滚。确认原文件都在，再允许后续读写。
            let restored = read_optional(&config).is_ok_and(|bytes| bytes == rollback.config)
                && read_optional(&state).is_ok_and(|bytes| bytes == rollback.state)
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
        save_state_to(&self.directory.join("ping-rust-state.json"), &self.state)
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
        match transaction::restore_snapshot(
            &self.directory.join("config.yaml"),
            rollback.config.as_deref(),
            0o600,
        ) {
            Ok(()) => {
                if let Err(error) = transaction::restore_snapshot(
                    &self.directory.join("ping-rust-state.json"),
                    rollback.state.as_deref(),
                    0o600,
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
