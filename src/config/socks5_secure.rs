//! SOCKS5 加固的只读计划与现有受管文件事务。
use super::*;

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
}

impl SecurePlan {
    fn load_checked(
        directory: &Path,
        id: Uuid,
    ) -> Result<(ManagedState, Vec<ServerConfig>, usize)> {
        let state = load_state_from(&directory.join("ping-rust-state.json")).map_err(|_| {
            anyhow::anyhow!("无法读取 SOCKS5 管理状态，请检查 ping-rust-state.json 和 config.yaml")
        })?;
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
        let (state, _, index) = Self::load_checked(directory, id)?;
        Ok(state.profiles[index].socks5_risk_warning().is_none())
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

    pub(crate) async fn validate(&self) -> Result<()> {
        if !utils::command_exists(utils::SHOES_BIN) {
            bail!("未找到可执行的 shoes，请先安装 shoes 后重试");
        }
        let yaml = crate::yaml::to_string(&self.servers)?;
        validate_yaml(&yaml)?;
        validate_candidate_with_shoes(&yaml, &self.directory).await
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
        commit::commit_managed_with_state_writer(
            &config,
            &state,
            &profiles,
            &self.servers,
            &self.state,
            save_state_to,
        )?;
        self.rollback = Some(rollback);
        Ok(())
    }

    pub(crate) fn rollback(&mut self) -> Result<()> {
        self.rollback
            .take()
            .context("没有已提交的 SOCKS5 加固事务")?
            .restore_to(
                &self.directory.join("config.yaml"),
                &self.directory.join("ping-rust-state.json"),
                &self.directory.join("profiles"),
            )
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
    let mut profile = serde_json::json!({
        "address": server.address,
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
    crate::yaml::to_string(&preview)
}
