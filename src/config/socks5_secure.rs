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
    pub(crate) fn prepare(directory: &Path, id: Uuid, mode: SecureMode) -> Result<Option<Self>> {
        let mut state = load_state_from(&directory.join("ping-rust-state.json"))?;
        let index = state
            .profiles
            .iter()
            .position(|p| p.id == id)
            .context("未找到 SOCKS5 节点")?;
        let original = state.profiles[index].clone();
        if original.protocol() != Protocol::Socks5 {
            bail!("只有 SOCKS5 节点支持 secure");
        }
        if original.socks5_risk_warning().is_none() {
            return Ok(None);
        }
        let mut servers = load_servers(&directory.join("config.yaml"))?;
        ensure_servers_match_state(&servers, &state.profiles)?;
        ensure_chain_proxy_matches_state(&servers, &state)?;
        let before_yaml = redacted_yaml(&servers)?;
        let before_profile = redacted_yaml(&servers[index])?;
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
                redacted_yaml(&self.servers[index])?,
            ),
            (
                "config.yaml".to_owned(),
                &self.before_yaml,
                redacted_yaml(&self.servers)?,
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

// 聚合配置可能含其他协议的密钥；仅保留监听地址和协议类型，其余字符串全部脱敏。
fn redacted_yaml(value: &impl Serialize) -> Result<String> {
    fn redact(value: &mut serde_json::Value, key: &str) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    redact(value, key);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    redact(value, key);
                }
            }
            serde_json::Value::String(text) if !matches!(key, "address" | "type") => {
                *text = "[REDACTED]".into()
            }
            _ => {}
        }
    }
    let mut value = serde_json::to_value(value)?;
    redact(&mut value, "");
    Ok(crate::yaml::to_string(&value)?)
}
