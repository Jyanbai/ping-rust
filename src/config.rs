use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use clap::ValueEnum;
use rand::RngCore;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::utils;

pub const DEFAULT_SNI: &str = "www.cloudflare.com";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Protocol {
    #[value(alias = "r", alias = "vless")]
    Reality,
    #[value(alias = "hy", alias = "hy2", alias = "hysteria")]
    Hysteria2,
    Tuic,
    #[value(alias = "ss")]
    Shadowsocks,
    #[value(name = "anytls")]
    AnyTls,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum ShadowsocksCipher {
    #[value(name = "aes-128-gcm")]
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[value(name = "aes-256-gcm")]
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[value(name = "chacha20-ietf-poly1305")]
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
    #[value(name = "2022-blake3-aes-128-gcm")]
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aes128Gcm2022,
    #[default]
    #[value(name = "2022-blake3-aes-256-gcm")]
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aes256Gcm2022,
    #[value(name = "2022-blake3-chacha20-ietf-poly1305")]
    #[serde(rename = "2022-blake3-chacha20-ietf-poly1305")]
    Chacha20IetfPoly13052022,
}

impl ShadowsocksCipher {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            Self::Aes128Gcm2022 => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm2022 => "2022-blake3-aes-256-gcm",
            Self::Chacha20IetfPoly13052022 => "2022-blake3-chacha20-ietf-poly1305",
        }
    }

    fn key_len(self) -> Option<usize> {
        match self {
            Self::Aes128Gcm2022 => Some(16),
            Self::Aes256Gcm2022 | Self::Chacha20IetfPoly13052022 => Some(32),
            _ => None,
        }
    }

    pub fn client_name(self) -> &'static str {
        match self {
            Self::Chacha20IetfPoly13052022 => "2022-blake3-chacha20-poly1305",
            _ => self.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum AnyTlsMode {
    #[default]
    Tls,
    Reality,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnyTlsUser {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub password: String,
}

impl FromStr for AnyTlsUser {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (name, password) = value
            .split_once(':')
            .map_or(("", value), |(name, password)| (name, password));
        if password.is_empty() {
            return Err("AnyTLS 用户格式应为 [名称:]密码，密码不能为空".to_owned());
        }
        Ok(Self {
            name: name.to_owned(),
            password: password.to_owned(),
        })
    }
}

pub fn generated_anytls_user(name: impl Into<String>) -> AnyTlsUser {
    AnyTlsUser {
        name: name.into(),
        password: random_secret(24),
    }
}

pub fn generated_password() -> String {
    random_secret(24)
}

#[derive(Clone, Debug)]
pub struct GenerationOptions {
    pub reality_short_id: Option<String>,
    pub reality_max_time_diff: u64,
    pub udp_enabled: bool,
    pub quic_endpoints: usize,
    pub tuic_zero_rtt: bool,
    pub shadowsocks_cipher: ShadowsocksCipher,
    pub shadowsocks_password: Option<String>,
    pub anytls_mode: AnyTlsMode,
    pub anytls_users: Vec<AnyTlsUser>,
    pub anytls_padding_scheme: Option<Vec<String>>,
    pub anytls_fallback: Option<String>,
}

impl Default for GenerationOptions {
    fn default() -> Self {
        Self {
            reality_short_id: None,
            reality_max_time_diff: 60_000,
            udp_enabled: true,
            quic_endpoints: 0,
            tuic_zero_rtt: false,
            shadowsocks_cipher: ShadowsocksCipher::default(),
            shadowsocks_password: None,
            anytls_mode: AnyTlsMode::default(),
            anytls_users: Vec::new(),
            anytls_padding_scheme: None,
            anytls_fallback: None,
        }
    }
}

pub struct GenerationRequest {
    pub name: Option<String>,
    pub protocol: Protocol,
    pub port: u16,
    pub output: PathBuf,
    pub server_address: Option<String>,
    pub server_name: String,
    pub reality_dest: Option<String>,
    pub certificate: Option<PathBuf>,
    pub certificate_key: Option<PathBuf>,
    pub options: GenerationOptions,
}

pub enum ProfileChange {
    Name(String),
    Port(u16),
    ServerAddress(Option<String>),
    RegenerateCredentials,
    Password(String),
    RealityServerName(String),
    ShadowsocksCipher(ShadowsocksCipher),
    AnyTlsUserPassword { index: usize, password: String },
}

pub struct GenerationResult {
    pub profile_id: Uuid,
    pub config_path: PathBuf,
    pub certificate_path: Option<PathBuf>,
    pub certificate_key_path: Option<PathBuf>,
    pub credentials: Credentials,
    pub profile: ManagedProfile,
    rollback: Option<ManagedRollback>,
    _lock: Option<utils::ExclusiveLock>,
}

struct ManagedRollback {
    config: Option<Vec<u8>>,
    state: Option<Vec<u8>>,
    generated_certificate: Option<PathBuf>,
    generated_certificate_key: Option<PathBuf>,
}

impl GenerationResult {
    pub fn rollback_managed(&mut self) -> Result<()> {
        let rollback = self
            .rollback
            .take()
            .context("该生成结果不包含可回滚的系统配置事务")?;
        rollback.restore_to(Path::new(utils::CONFIG_FILE), Path::new(utils::STATE_FILE))
    }
}

impl ManagedRollback {
    fn restore_to(self, config_path: &Path, state_path: &Path) -> Result<()> {
        let state_result = restore_snapshot(state_path, self.state.as_deref(), 0o600);
        let config_result = restore_snapshot(config_path, self.config.as_deref(), 0o600);
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
        match (state_result, config_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(state), Ok(())) => Err(state.context("恢复管理状态失败")),
            (Ok(()), Err(config)) => Err(config.context("恢复 shoes 配置失败")),
            (Err(state), Err(config)) => {
                bail!("恢复管理状态和 shoes 配置均失败：状态={state:#}；配置={config:#}")
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Credentials {
    Reality {
        user_id: Uuid,
        private_key: String,
        public_key: String,
        short_id: String,
        server_name: String,
    },
    Hysteria2 {
        password: String,
        server_name: String,
        #[serde(default = "default_h3_alpn")]
        alpn_protocols: Vec<String>,
    },
    Tuic {
        user_id: Uuid,
        password: String,
        server_name: String,
        #[serde(default = "default_h3_alpn")]
        alpn_protocols: Vec<String>,
        #[serde(default)]
        zero_rtt_handshake: bool,
    },
    Shadowsocks {
        cipher: ShadowsocksCipher,
        password: String,
        udp_enabled: bool,
    },
    AnyTls {
        users: Vec<AnyTlsUser>,
        server_name: String,
        alpn_protocols: Vec<String>,
        udp_enabled: bool,
        security: AnyTlsSecurity,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AnyTlsSecurity {
    Tls,
    Reality {
        private_key: String,
        public_key: String,
        short_id: String,
    },
}

fn default_h3_alpn() -> Vec<String> {
    vec!["h3".to_owned()]
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ManagedState {
    pub schema_version: u8,
    pub profiles: Vec<ManagedProfile>,
}

impl Default for ManagedState {
    fn default() -> Self {
        Self {
            schema_version: 1,
            profiles: Vec::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ManagedProfile {
    pub id: Uuid,
    pub name: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_address: Option<String>,
    pub credentials: Credentials,
    pub certificate_path: Option<PathBuf>,
    pub certificate_key_path: Option<PathBuf>,
    pub self_signed_certificate: bool,
}

impl ManagedProfile {
    pub fn display_name(&self) -> String {
        let protocol = match self.protocol() {
            Protocol::Reality => "VLESS-REALITY",
            Protocol::Hysteria2 => "HYSTERIA2",
            Protocol::Tuic => "TUIC",
            Protocol::Shadowsocks => "SHADOWSOCKS",
            Protocol::AnyTls => "ANYTLS",
        };
        format!("{protocol}-{}", self.port)
    }

    pub fn protocol(&self) -> Protocol {
        match &self.credentials {
            Credentials::Reality { .. } => Protocol::Reality,
            Credentials::Hysteria2 { .. } => Protocol::Hysteria2,
            Credentials::Tuic { .. } => Protocol::Tuic,
            Credentials::Shadowsocks { .. } => Protocol::Shadowsocks,
            Credentials::AnyTls { .. } => Protocol::AnyTls,
        }
    }

    pub fn protocol_name(&self) -> &'static str {
        match &self.credentials {
            Credentials::Reality { .. } => "VLESS-Reality-Vision",
            Credentials::Hysteria2 { .. } => "Hysteria2",
            Credentials::Tuic { .. } => "TUIC v5",
            Credentials::Shadowsocks { .. } => "Shadowsocks",
            Credentials::AnyTls { .. } => "AnyTLS",
        }
    }

    pub fn server_name(&self) -> &str {
        match &self.credentials {
            Credentials::Reality { server_name, .. }
            | Credentials::Hysteria2 { server_name, .. }
            | Credentials::Tuic { server_name, .. }
            | Credentials::AnyTls { server_name, .. } => server_name,
            Credentials::Shadowsocks { .. } => "-",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct ServerConfig {
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quic_settings: Option<QuicSettings>,
    protocol: ServerProtocol,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rules: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct QuicSettings {
    cert: String,
    key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    alpn_protocols: Vec<String>,
    #[serde(default)]
    num_endpoints: usize,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ServerProtocol {
    Tls {
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        tls_targets: BTreeMap<String, TlsTarget>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        reality_targets: BTreeMap<String, RealityTarget>,
    },
    Hysteria2 {
        password: String,
        udp_enabled: bool,
    },
    Tuic {
        uuid: Uuid,
        password: String,
        zero_rtt_handshake: bool,
    },
    Shadowsocks {
        cipher: String,
        password: String,
        udp_enabled: bool,
    },
}

#[derive(Clone, Serialize, Deserialize)]
struct TlsTarget {
    cert: String,
    key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    alpn_protocols: Vec<String>,
    protocol: InnerProtocol,
}

#[derive(Clone, Serialize, Deserialize)]
struct RealityTarget {
    private_key: String,
    short_ids: Vec<String>,
    dest: String,
    max_time_diff: u64,
    vision: bool,
    protocol: InnerProtocol,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum InnerProtocol {
    Vless {
        user_id: Uuid,
        udp_enabled: bool,
    },
    #[serde(rename = "anytls")]
    AnyTls {
        users: Vec<AnyTlsUser>,
        #[serde(skip_serializing_if = "Option::is_none")]
        padding_scheme: Option<Vec<String>>,
        udp_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        fallback: Option<String>,
    },
}

pub async fn generate(request: GenerationRequest) -> Result<GenerationResult> {
    generate_inner(request, true).await
}

async fn generate_inner(
    request: GenerationRequest,
    validate_with_shoes: bool,
) -> Result<GenerationResult> {
    generate_inner_with_lock(request, validate_with_shoes, None).await
}

pub(crate) async fn generate_locked(
    request: GenerationRequest,
    lock: utils::ExclusiveLock,
) -> Result<GenerationResult> {
    generate_inner_with_lock(request, true, Some(lock)).await
}

async fn generate_inner_with_lock(
    request: GenerationRequest,
    validate_with_shoes: bool,
    supplied_lock: Option<utils::ExclusiveLock>,
) -> Result<GenerationResult> {
    validate_request(&request)?;
    let parent = request.output.parent().context("配置输出路径没有父目录")?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let managed = request.output == Path::new(utils::CONFIG_FILE);
    if managed {
        utils::require_linux_root()?;
        utils::ensure_directory(Path::new(utils::CONFIG_DIR), 0o700)?;
    }
    let lock = if managed {
        Some(match supplied_lock {
            Some(lock) => lock,
            None => utils::exclusive_lock(Path::new(utils::LOCK_FILE))?,
        })
    } else {
        if supplied_lock.is_some() {
            bail!("自定义输出不应持有系统配置锁");
        }
        None
    };
    let mut state = if managed {
        load_state_for_update()?
    } else {
        ManagedState::default()
    };
    if state
        .profiles
        .iter()
        .any(|profile| profile.port == request.port)
    {
        bail!("端口 {} 已由现有配置使用", request.port);
    }
    let profile_id = Uuid::new_v4();
    let profile_name = request
        .name
        .clone()
        .unwrap_or_else(|| default_profile_name(request.protocol, profile_id));
    validate_profile_name(&profile_name, &state.profiles, None)?;
    let needs_certificate = matches!(request.protocol, Protocol::Hysteria2 | Protocol::Tuic)
        || (matches!(request.protocol, Protocol::AnyTls)
            && request.options.anytls_mode == AnyTlsMode::Tls);
    let self_signed = request.certificate.is_none() && needs_certificate;

    let (server, credentials, certificate_path, certificate_key_path) = match request.protocol {
        Protocol::Reality => generate_reality(&request),
        Protocol::Hysteria2 | Protocol::Tuic => {
            let (cert, key) = resolve_certificate(&request, parent, profile_id)?;
            let cert_string = cert.to_string_lossy().into_owned();
            let key_string = key.to_string_lossy().into_owned();
            let password = random_secret(24);
            if matches!(request.protocol, Protocol::Hysteria2) {
                (
                    quic_server(
                        request.port,
                        &cert_string,
                        &key_string,
                        ServerProtocol::Hysteria2 {
                            password: password.clone(),
                            udp_enabled: request.options.udp_enabled,
                        },
                        request.options.quic_endpoints,
                    ),
                    Credentials::Hysteria2 {
                        password,
                        server_name: request.server_name.clone(),
                        alpn_protocols: default_h3_alpn(),
                    },
                    Some(cert),
                    Some(key),
                )
            } else {
                let user_id = Uuid::new_v4();
                (
                    quic_server(
                        request.port,
                        &cert_string,
                        &key_string,
                        ServerProtocol::Tuic {
                            uuid: user_id,
                            password: password.clone(),
                            zero_rtt_handshake: request.options.tuic_zero_rtt,
                        },
                        request.options.quic_endpoints,
                    ),
                    Credentials::Tuic {
                        user_id,
                        password,
                        server_name: request.server_name.clone(),
                        alpn_protocols: default_h3_alpn(),
                        zero_rtt_handshake: request.options.tuic_zero_rtt,
                    },
                    Some(cert),
                    Some(key),
                )
            }
        }
        Protocol::Shadowsocks => generate_shadowsocks(&request),
        Protocol::AnyTls => generate_anytls(&request, parent, profile_id)?,
    };

    let profile = ManagedProfile {
        id: profile_id,
        name: profile_name,
        port: request.port,
        server_address: request.server_address.clone(),
        credentials: credentials.clone(),
        certificate_path: certificate_path.clone(),
        certificate_key_path: certificate_key_path.clone(),
        self_signed_certificate: self_signed,
    };
    let mut credential_cleanup = CredentialCleanup::new(
        self_signed,
        certificate_path.as_deref(),
        certificate_key_path.as_deref(),
    );

    let mut servers = if managed && !state.profiles.is_empty() {
        load_servers(Path::new(utils::CONFIG_FILE))?
    } else {
        Vec::new()
    };
    ensure_servers_match_state(&servers, &state.profiles)
        .context("配置文件与管理状态不一致；请先备份并修复，ping-rust 不会覆盖现有配置")?;
    servers.push(server);
    state.profiles.push(profile.clone());

    let yaml = serde_yaml::to_string(&servers).context("序列化 shoes YAML 失败")?;
    validate_yaml(&yaml)?;
    if validate_with_shoes {
        validate_candidate_with_shoes(&yaml, parent).await?;
    }
    let rollback = if managed {
        Some(ManagedRollback {
            config: read_optional(Path::new(utils::CONFIG_FILE))?,
            state: read_optional(Path::new(utils::STATE_FILE))?,
            generated_certificate: self_signed.then(|| certificate_path.clone()).flatten(),
            generated_certificate_key: self_signed.then(|| certificate_key_path.clone()).flatten(),
        })
    } else {
        None
    };
    if managed {
        commit_managed(&request.output, Path::new(utils::STATE_FILE), &yaml, &state)?;
    } else {
        utils::atomic_write(&request.output, yaml.as_bytes(), 0o600)?;
    }
    credential_cleanup.disarm();

    Ok(GenerationResult {
        profile_id,
        config_path: request.output,
        certificate_path,
        certificate_key_path,
        credentials,
        profile,
        rollback,
        _lock: lock,
    })
}

pub(crate) async fn update_profile_locked(
    id: Uuid,
    change: ProfileChange,
    lock: utils::ExclusiveLock,
) -> Result<GenerationResult> {
    utils::require_linux_root()?;
    utils::ensure_directory(Path::new(utils::CONFIG_DIR), 0o700)?;
    let config_path = Path::new(utils::CONFIG_FILE);
    let state_path = Path::new(utils::STATE_FILE);
    let mut state = load_state_for_update()?;
    let index = state
        .profiles
        .iter()
        .position(|profile| profile.id == id)
        .with_context(|| format!("未找到配置 {id}"))?;
    let mut servers = load_servers(config_path)?;
    ensure_servers_match_state(&servers, &state.profiles)
        .context("配置文件与管理状态不一致；请先备份并修复，ping-rust 不会覆盖现有配置")?;

    match &change {
        ProfileChange::Name(name) => validate_profile_name(name, &state.profiles, Some(id))?,
        ProfileChange::Port(port) => {
            if *port == 0 {
                bail!("端口必须在 1..=65535 范围内");
            }
            if state
                .profiles
                .iter()
                .any(|profile| profile.id != id && profile.port == *port)
            {
                bail!("端口 {port} 已由现有配置使用");
            }
        }
        ProfileChange::ServerAddress(Some(address)) => {
            if address.trim().is_empty()
                || address.len() > 255
                || address.chars().any(char::is_control)
            {
                bail!("客户端地址必须为 1..=255 个非控制字符");
            }
        }
        ProfileChange::RealityServerName(server_name) => validate_server_name(server_name)?,
        _ => {}
    }

    let rollback = ManagedRollback {
        config: read_optional(config_path)?,
        state: read_optional(state_path)?,
        generated_certificate: None,
        generated_certificate_key: None,
    };
    apply_profile_change(&mut servers[index], &mut state.profiles[index], change)?;
    let profile = state.profiles[index].clone();
    let yaml = serde_yaml::to_string(&servers).context("序列化更新后 shoes YAML 失败")?;
    validate_yaml(&yaml)?;
    validate_candidate_with_shoes(&yaml, Path::new(utils::CONFIG_DIR)).await?;
    commit_managed(config_path, state_path, &yaml, &state)?;

    Ok(GenerationResult {
        profile_id: profile.id,
        config_path: config_path.to_path_buf(),
        certificate_path: profile.certificate_path.clone(),
        certificate_key_path: profile.certificate_key_path.clone(),
        credentials: profile.credentials.clone(),
        profile,
        rollback: Some(rollback),
        _lock: Some(lock),
    })
}

fn apply_profile_change(
    server: &mut ServerConfig,
    profile: &mut ManagedProfile,
    change: ProfileChange,
) -> Result<()> {
    match change {
        ProfileChange::Name(name) => profile.name = name.trim().to_owned(),
        ProfileChange::Port(port) => {
            server.address = format!("0.0.0.0:{port}");
            profile.port = port;
        }
        ProfileChange::ServerAddress(address) => profile.server_address = address,
        ProfileChange::RegenerateCredentials => regenerate_profile_credentials(server, profile)?,
        ProfileChange::Password(password) => {
            if password.is_empty() || password.chars().any(char::is_control) {
                bail!("密码不能为空或包含控制字符");
            }
            match (&mut server.protocol, &mut profile.credentials) {
                (
                    ServerProtocol::Hysteria2 {
                        password: server_password,
                        ..
                    },
                    Credentials::Hysteria2 {
                        password: state_password,
                        ..
                    },
                )
                | (
                    ServerProtocol::Tuic {
                        password: server_password,
                        ..
                    },
                    Credentials::Tuic {
                        password: state_password,
                        ..
                    },
                ) => {
                    *server_password = password.clone();
                    *state_password = password;
                }
                (
                    ServerProtocol::Shadowsocks {
                        password: server_password,
                        ..
                    },
                    Credentials::Shadowsocks {
                        cipher,
                        password: state_password,
                        ..
                    },
                ) => {
                    validate_shadowsocks_password(*cipher, &password)?;
                    *server_password = password.clone();
                    *state_password = password;
                }
                _ => bail!("该协议不支持直接更改单一密码；请选择重新生成凭据"),
            }
        }
        ProfileChange::RealityServerName(new_name) => {
            let Credentials::Reality { server_name, .. } = &mut profile.credentials else {
                bail!("只有 VLESS-Reality 配置支持更改 SNI");
            };
            let ServerProtocol::Tls {
                reality_targets, ..
            } = &mut server.protocol
            else {
                bail!("Reality 配置与管理状态不一致");
            };
            if reality_targets.len() != 1 {
                bail!("Reality 配置必须恰好包含一个目标");
            }
            let mut target = reality_targets
                .remove(server_name)
                .or_else(|| reality_targets.pop_first().map(|(_, target)| target))
                .context("Reality 配置中缺少现有 SNI 目标")?;
            if target.dest == format!("{server_name}:443") {
                target.dest = format!("{new_name}:443");
            }
            reality_targets.insert(new_name.clone(), target);
            *server_name = new_name;
        }
        ProfileChange::ShadowsocksCipher(cipher) => {
            let password = generate_shadowsocks_password(cipher);
            match (&mut server.protocol, &mut profile.credentials) {
                (
                    ServerProtocol::Shadowsocks {
                        cipher: server_cipher,
                        password: server_password,
                        ..
                    },
                    Credentials::Shadowsocks {
                        cipher: state_cipher,
                        password: state_password,
                        ..
                    },
                ) => {
                    *server_cipher = cipher.as_str().to_owned();
                    *server_password = password.clone();
                    *state_cipher = cipher;
                    *state_password = password;
                }
                _ => bail!("只有 Shadowsocks 配置支持更改加密方式"),
            }
        }
        ProfileChange::AnyTlsUserPassword { index, password } => {
            if password.is_empty() || password.chars().any(char::is_control) {
                bail!("AnyTLS 用户密码不能为空或包含控制字符");
            }
            let Credentials::AnyTls { users, .. } = &mut profile.credentials else {
                bail!("只有 AnyTLS 配置支持更改用户密码");
            };
            let user = users.get_mut(index).context("AnyTLS 用户序号无效")?;
            user.password = password;
            *anytls_users_mut(server)? = users.clone();
        }
    }
    Ok(())
}

fn regenerate_profile_credentials(
    server: &mut ServerConfig,
    profile: &mut ManagedProfile,
) -> Result<()> {
    match &mut profile.credentials {
        Credentials::Reality {
            user_id,
            private_key,
            public_key,
            short_id,
            server_name,
        } => {
            let ServerProtocol::Tls {
                reality_targets, ..
            } = &mut server.protocol
            else {
                bail!("Reality 配置与管理状态不一致");
            };
            if reality_targets.len() != 1 {
                bail!("Reality 配置必须恰好包含一个目标");
            }
            let target = if reality_targets.contains_key(server_name) {
                reality_targets.get_mut(server_name)
            } else {
                reality_targets.values_mut().next()
            }
            .context("Reality 配置中缺少目标")?;
            let InnerProtocol::Vless {
                user_id: server_user_id,
                ..
            } = &mut target.protocol
            else {
                bail!("Reality 内层协议不是 VLESS");
            };
            let keypair = generate_reality_keypair();
            let new_user_id = Uuid::new_v4();
            let new_short_id = random_hex(8);
            target.private_key = keypair.private_key.clone();
            target.short_ids = vec![new_short_id.clone()];
            *server_user_id = new_user_id;
            *user_id = new_user_id;
            *private_key = keypair.private_key;
            *public_key = keypair.public_key;
            *short_id = new_short_id;
        }
        Credentials::Hysteria2 { password, .. } => {
            let ServerProtocol::Hysteria2 {
                password: server_password,
                ..
            } = &mut server.protocol
            else {
                bail!("Hysteria2 配置与管理状态不一致");
            };
            let generated = random_secret(24);
            *server_password = generated.clone();
            *password = generated;
        }
        Credentials::Tuic {
            user_id, password, ..
        } => {
            let ServerProtocol::Tuic {
                uuid,
                password: server_password,
                ..
            } = &mut server.protocol
            else {
                bail!("TUIC 配置与管理状态不一致");
            };
            let generated_id = Uuid::new_v4();
            let generated_password = random_secret(24);
            *uuid = generated_id;
            *server_password = generated_password.clone();
            *user_id = generated_id;
            *password = generated_password;
        }
        Credentials::Shadowsocks {
            cipher, password, ..
        } => {
            let ServerProtocol::Shadowsocks {
                cipher: server_cipher,
                password: server_password,
                ..
            } = &mut server.protocol
            else {
                bail!("Shadowsocks 配置与管理状态不一致");
            };
            let generated = generate_shadowsocks_password(*cipher);
            *server_cipher = cipher.as_str().to_owned();
            *server_password = generated.clone();
            *password = generated;
        }
        Credentials::AnyTls { users, .. } => {
            for user in users.iter_mut() {
                user.password = random_secret(24);
            }
            *anytls_users_mut(server)? = users.clone();
        }
    }
    Ok(())
}

fn anytls_users_mut(server: &mut ServerConfig) -> Result<&mut Vec<AnyTlsUser>> {
    let ServerProtocol::Tls {
        tls_targets,
        reality_targets,
    } = &mut server.protocol
    else {
        bail!("AnyTLS 配置与管理状态不一致");
    };
    let target_count = tls_targets.len() + reality_targets.len();
    if target_count != 1 {
        bail!("AnyTLS 配置必须恰好包含一个 TLS 或 Reality 目标");
    }
    let protocol = if let Some(target) = tls_targets.values_mut().next() {
        &mut target.protocol
    } else {
        &mut reality_targets
            .values_mut()
            .next()
            .context("AnyTLS 配置中缺少目标")?
            .protocol
    };
    let InnerProtocol::AnyTls { users, .. } = protocol else {
        bail!("TLS 目标内层协议不是 AnyTLS");
    };
    Ok(users)
}

fn validate_profile_name(
    name: &str,
    profiles: &[ManagedProfile],
    except_id: Option<Uuid>,
) -> Result<()> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
        bail!("配置名称必须为 1..=64 个非控制字符");
    }
    if profiles.iter().any(|profile| {
        Some(profile.id) != except_id && profile.name.trim().eq_ignore_ascii_case(name)
    }) {
        bail!("配置名称 {name} 已存在；名称必须唯一");
    }
    Ok(())
}

fn default_profile_name(protocol: Protocol, id: Uuid) -> String {
    let protocol = match protocol {
        Protocol::Reality => "reality",
        Protocol::Hysteria2 => "hysteria2",
        Protocol::Tuic => "tuic",
        Protocol::Shadowsocks => "shadowsocks",
        Protocol::AnyTls => "anytls",
    };
    format!("{protocol}-{}", &id.simple().to_string()[..8])
}

fn load_servers(path: &Path) -> Result<Vec<ServerConfig>> {
    let yaml =
        fs::read_to_string(path).with_context(|| format!("读取配置 {} 失败", path.display()))?;
    serde_yaml::from_str(&yaml).context("现有 shoes 配置不是 ping-rust 可管理的格式")
}

fn ensure_servers_match_state(servers: &[ServerConfig], profiles: &[ManagedProfile]) -> Result<()> {
    if servers.len() != profiles.len() {
        bail!(
            "配置条目数 {} 与管理状态条目数 {} 不一致",
            servers.len(),
            profiles.len()
        );
    }
    for (index, (server, profile)) in servers.iter().zip(profiles).enumerate() {
        let expected_address = format!("0.0.0.0:{}", profile.port);
        if server.address != expected_address {
            bail!(
                "第 {} 项监听地址 {} 与管理状态端口 {} 不一致",
                index + 1,
                server.address,
                profile.port
            );
        }
        let protocol_matches = match (&server.protocol, profile.protocol()) {
            (ServerProtocol::Hysteria2 { .. }, Protocol::Hysteria2)
            | (ServerProtocol::Tuic { .. }, Protocol::Tuic)
            | (ServerProtocol::Shadowsocks { .. }, Protocol::Shadowsocks) => true,
            (
                ServerProtocol::Tls {
                    reality_targets, ..
                },
                Protocol::Reality,
            ) => reality_targets
                .values()
                .any(|target| matches!(target.protocol, InnerProtocol::Vless { .. })),
            (
                ServerProtocol::Tls {
                    tls_targets,
                    reality_targets,
                },
                Protocol::AnyTls,
            ) => {
                tls_targets
                    .values()
                    .any(|target| matches!(target.protocol, InnerProtocol::AnyTls { .. }))
                    || reality_targets
                        .values()
                        .any(|target| matches!(target.protocol, InnerProtocol::AnyTls { .. }))
            }
            _ => false,
        };
        if !protocol_matches {
            bail!("第 {} 项协议与管理状态 {} 不一致", index + 1, profile.id);
        }
    }
    Ok(())
}

fn load_state_for_update() -> Result<ManagedState> {
    let config_exists = Path::new(utils::CONFIG_FILE).exists();
    let state_exists = Path::new(utils::STATE_FILE).exists();
    if config_exists && !state_exists {
        bail!(
            "检测到非 ping-rust 管理的 {}；为避免覆盖，请先备份或改用 --output",
            utils::CONFIG_FILE
        );
    }
    if state_exists {
        load_state()
    } else {
        Ok(ManagedState::default())
    }
}

pub fn load_state() -> Result<ManagedState> {
    load_state_from(Path::new(utils::STATE_FILE))
}

fn load_state_from(path: &Path) -> Result<ManagedState> {
    let json = fs::read_to_string(path)
        .with_context(|| format!("读取管理状态 {} 失败", path.display()))?;
    let state: ManagedState = serde_json::from_str(&json).context("管理状态 JSON 已损坏")?;
    if state.schema_version != 1 {
        bail!("不支持的管理状态版本 {}", state.schema_version);
    }
    Ok(state)
}

fn save_state_to(path: &Path, state: &ManagedState) -> Result<()> {
    let json = serde_json::to_vec_pretty(state).context("序列化管理状态失败")?;
    utils::atomic_write(path, &json, 0o600)
}

pub async fn delete_profile(id: Uuid) -> Result<ManagedProfile> {
    utils::require_linux_root()?;
    let _lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    let mut state = load_state()?;
    let index = state
        .profiles
        .iter()
        .position(|profile| profile.id == id)
        .with_context(|| format!("未找到配置 {id}"))?;
    let config_path = Path::new(utils::CONFIG_FILE);
    let mut servers = load_servers(config_path)?;
    ensure_servers_match_state(&servers, &state.profiles)
        .context("配置文件与管理状态不一致，已拒绝删除")?;
    servers.remove(index);
    let profile = state.profiles.remove(index);
    let yaml = serde_yaml::to_string(&servers).context("序列化更新后配置失败")?;
    if !servers.is_empty() {
        validate_yaml(&yaml)?;
        validate_candidate_with_shoes(&yaml, Path::new(utils::CONFIG_DIR)).await?;
    }
    commit_managed(config_path, Path::new(utils::STATE_FILE), &yaml, &state)?;

    if profile.self_signed_certificate {
        for path in [
            profile.certificate_path.as_deref(),
            profile.certificate_key_path.as_deref(),
        ] {
            if let Err(error) = remove_managed_credential(path) {
                eprintln!("警告：配置已删除，但清理凭据失败：{error:#}");
            }
        }
    }
    Ok(profile)
}

fn commit_managed(
    config_path: &Path,
    state_path: &Path,
    yaml: &str,
    state: &ManagedState,
) -> Result<()> {
    commit_managed_with_state_writer(config_path, state_path, yaml, state, save_state_to)
}

fn commit_managed_with_state_writer<F>(
    config_path: &Path,
    state_path: &Path,
    yaml: &str,
    state: &ManagedState,
    write_state: F,
) -> Result<()>
where
    F: FnOnce(&Path, &ManagedState) -> Result<()>,
{
    let old_config = read_optional(config_path)?;
    let old_state = read_optional(state_path)?;
    utils::atomic_write(config_path, yaml.as_bytes(), 0o600)?;
    if let Err(error) = write_state(state_path, state) {
        let state_rollback = restore_snapshot(state_path, old_state.as_deref(), 0o600);
        let config_rollback = restore_snapshot(config_path, old_config.as_deref(), 0o600);
        if let Err(rollback_error) = state_rollback.and(config_rollback) {
            return Err(error.context(format!(
                "写入管理状态失败，且回滚也失败：{rollback_error:#}"
            )));
        }
        return Err(error.context("写入管理状态失败，配置和状态已回滚"));
    }
    Ok(())
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("读取 {} 失败", path.display())),
    }
}

fn restore_snapshot(path: &Path, contents: Option<&[u8]>, mode: u32) -> Result<()> {
    if let Some(contents) = contents {
        utils::atomic_write(path, contents, mode)
    } else if path.exists() {
        fs::remove_file(path).with_context(|| format!("删除回滚目标 {} 失败", path.display()))
    } else {
        Ok(())
    }
}

struct CredentialCleanup {
    paths: Vec<PathBuf>,
    armed: bool,
}

impl CredentialCleanup {
    fn new(self_signed: bool, cert: Option<&Path>, key: Option<&Path>) -> Self {
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

    fn disarm(&mut self) {
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
        std::fs::remove_file(path)
            .with_context(|| format!("删除凭据文件 {} 失败", path.display()))?;
    }
    Ok(())
}

fn generate_reality(
    request: &GenerationRequest,
) -> (ServerConfig, Credentials, Option<PathBuf>, Option<PathBuf>) {
    let keypair = generate_reality_keypair();
    let short_id = request
        .options
        .reality_short_id
        .clone()
        .unwrap_or_else(|| random_hex(8));
    let user_id = Uuid::new_v4();
    let destination = request
        .reality_dest
        .clone()
        .unwrap_or_else(|| format!("{}:443", request.server_name));
    let target = RealityTarget {
        private_key: keypair.private_key.clone(),
        short_ids: vec![short_id.clone()],
        dest: destination,
        max_time_diff: request.options.reality_max_time_diff,
        vision: true,
        protocol: InnerProtocol::Vless {
            user_id,
            udp_enabled: request.options.udp_enabled,
        },
    };
    let mut targets = BTreeMap::new();
    targets.insert(request.server_name.clone(), target);

    (
        ServerConfig {
            address: format!("0.0.0.0:{}", request.port),
            transport: None,
            quic_settings: None,
            protocol: ServerProtocol::Tls {
                tls_targets: BTreeMap::new(),
                reality_targets: targets,
            },
            rules: Vec::new(),
        },
        Credentials::Reality {
            user_id,
            private_key: keypair.private_key,
            public_key: keypair.public_key,
            short_id,
            server_name: request.server_name.clone(),
        },
        None,
        None,
    )
}

fn generate_shadowsocks(
    request: &GenerationRequest,
) -> (ServerConfig, Credentials, Option<PathBuf>, Option<PathBuf>) {
    let cipher = request.options.shadowsocks_cipher;
    let password = request
        .options
        .shadowsocks_password
        .clone()
        .unwrap_or_else(|| generate_shadowsocks_password(cipher));
    (
        ServerConfig {
            address: format!("0.0.0.0:{}", request.port),
            transport: None,
            quic_settings: None,
            protocol: ServerProtocol::Shadowsocks {
                cipher: cipher.as_str().to_owned(),
                password: password.clone(),
                udp_enabled: request.options.udp_enabled,
            },
            rules: vec!["allow-all-direct".to_owned()],
        },
        Credentials::Shadowsocks {
            cipher,
            password,
            udp_enabled: request.options.udp_enabled,
        },
        None,
        None,
    )
}

fn generate_anytls(
    request: &GenerationRequest,
    parent: &Path,
    profile_id: Uuid,
) -> Result<(ServerConfig, Credentials, Option<PathBuf>, Option<PathBuf>)> {
    let inner = InnerProtocol::AnyTls {
        users: request.options.anytls_users.clone(),
        padding_scheme: request.options.anytls_padding_scheme.clone(),
        udp_enabled: request.options.udp_enabled,
        fallback: request.options.anytls_fallback.clone(),
    };
    let mut tls_targets = BTreeMap::new();
    let mut reality_targets = BTreeMap::new();

    let (security, cert, key) = match request.options.anytls_mode {
        AnyTlsMode::Tls => {
            let (cert, key) = resolve_certificate(request, parent, profile_id)?;
            tls_targets.insert(
                request.server_name.clone(),
                TlsTarget {
                    cert: cert.to_string_lossy().into_owned(),
                    key: key.to_string_lossy().into_owned(),
                    alpn_protocols: vec!["h2".to_owned(), "http/1.1".to_owned()],
                    protocol: inner,
                },
            );
            (AnyTlsSecurity::Tls, Some(cert), Some(key))
        }
        AnyTlsMode::Reality => {
            let keypair = generate_reality_keypair();
            let short_id = request
                .options
                .reality_short_id
                .clone()
                .unwrap_or_else(|| random_hex(8));
            reality_targets.insert(
                request.server_name.clone(),
                RealityTarget {
                    private_key: keypair.private_key.clone(),
                    short_ids: vec![short_id.clone()],
                    dest: request
                        .reality_dest
                        .clone()
                        .unwrap_or_else(|| format!("{}:443", request.server_name)),
                    max_time_diff: request.options.reality_max_time_diff,
                    vision: false,
                    protocol: inner,
                },
            );
            (
                AnyTlsSecurity::Reality {
                    private_key: keypair.private_key,
                    public_key: keypair.public_key,
                    short_id,
                },
                None,
                None,
            )
        }
    };

    Ok((
        ServerConfig {
            address: format!("0.0.0.0:{}", request.port),
            transport: None,
            quic_settings: None,
            protocol: ServerProtocol::Tls {
                tls_targets,
                reality_targets,
            },
            rules: Vec::new(),
        },
        Credentials::AnyTls {
            users: request.options.anytls_users.clone(),
            server_name: request.server_name.clone(),
            alpn_protocols: vec!["h2".to_owned(), "http/1.1".to_owned()],
            udp_enabled: request.options.udp_enabled,
            security,
        },
        cert,
        key,
    ))
}

fn quic_server(
    port: u16,
    cert: &str,
    key: &str,
    protocol: ServerProtocol,
    num_endpoints: usize,
) -> ServerConfig {
    ServerConfig {
        address: format!("0.0.0.0:{port}"),
        transport: Some("quic".to_owned()),
        quic_settings: Some(QuicSettings {
            cert: cert.to_owned(),
            key: key.to_owned(),
            alpn_protocols: vec!["h3".to_owned()],
            num_endpoints,
        }),
        protocol,
        rules: vec!["allow-all-direct".to_owned()],
    }
}

fn generate_shadowsocks_password(cipher: ShadowsocksCipher) -> String {
    let bytes = cipher.key_len().unwrap_or(24);
    let mut value = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut value);
    if cipher.key_len().is_some() {
        STANDARD.encode(value)
    } else {
        URL_SAFE_NO_PAD.encode(value)
    }
}

fn resolve_certificate(
    request: &GenerationRequest,
    parent: &Path,
    profile_id: Uuid,
) -> Result<(PathBuf, PathBuf)> {
    match (&request.certificate, &request.certificate_key) {
        (Some(cert), Some(key)) => {
            if !cert.is_file() || !key.is_file() {
                bail!("指定的证书或私钥文件不存在");
            }
            Ok((cert.clone(), key.clone()))
        }
        (None, None) => {
            let suffix = &profile_id.simple().to_string()[..8];
            let cert = parent.join(format!("cert-{suffix}.pem"));
            let key = parent.join(format!("key-{suffix}.pem"));
            write_self_signed_certificate(&request.server_name, &cert, &key)?;
            Ok((cert, key))
        }
        _ => bail!("--cert 和 --key 必须同时提供"),
    }
}

fn write_self_signed_certificate(server_name: &str, cert: &Path, key: &Path) -> Result<()> {
    let CertifiedKey {
        cert: generated,
        key_pair,
    } = generate_simple_self_signed(vec![server_name.to_owned()]).context("生成自签名证书失败")?;
    utils::atomic_write(cert, generated.pem().as_bytes(), 0o644)?;
    if let Err(error) = utils::atomic_write(key, key_pair.serialize_pem().as_bytes(), 0o600) {
        let _ = fs::remove_file(cert);
        return Err(error.context("写入证书私钥失败，已清理证书"));
    }
    Ok(())
}

pub struct RealityKeyPair {
    pub private_key: String,
    pub public_key: String,
}

pub fn generate_reality_keypair() -> RealityKeyPair {
    let private = StaticSecret::random();
    let public = PublicKey::from(&private);
    RealityKeyPair {
        private_key: URL_SAFE_NO_PAD.encode(private.to_bytes()),
        public_key: URL_SAFE_NO_PAD.encode(public.as_bytes()),
    }
}

fn random_hex(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut value);
    hex::encode(value)
}

fn random_secret(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn validate_request(request: &GenerationRequest) -> Result<()> {
    if request.port == 0 {
        bail!("端口必须在 1..=65535 范围内");
    }
    if let Some(name) = &request.name {
        if name.trim().is_empty() || name.chars().any(char::is_control) || name.len() > 64 {
            bail!("配置名称必须为 1..=64 个非控制字符");
        }
    }
    if !matches!(request.protocol, Protocol::Shadowsocks) {
        validate_server_name(&request.server_name)?;
    }
    if let Some(destination) = &request.reality_dest {
        validate_host_port(destination)?;
    }
    if let Some(short_id) = &request.options.reality_short_id {
        validate_reality_short_id(short_id)?;
    }
    if request.options.reality_max_time_diff == 0 {
        bail!("Reality max_time_diff 必须大于 0 毫秒");
    }
    if request.options.quic_endpoints > 256 {
        bail!("QUIC endpoint 数量不能超过 256");
    }
    if request.options.quic_endpoints > 0
        && !matches!(request.protocol, Protocol::Hysteria2 | Protocol::Tuic)
    {
        bail!("--quic-endpoints 仅适用于 Hysteria2/TUIC");
    }
    if request.options.tuic_zero_rtt && !matches!(request.protocol, Protocol::Tuic) {
        bail!("--zero-rtt 仅适用于 TUIC v5");
    }
    if request.options.anytls_mode != AnyTlsMode::Tls
        && !matches!(request.protocol, Protocol::AnyTls)
    {
        bail!("--anytls-mode 仅适用于 AnyTLS");
    }

    let reality_outer = matches!(request.protocol, Protocol::Reality)
        || (matches!(request.protocol, Protocol::AnyTls)
            && request.options.anytls_mode == AnyTlsMode::Reality);
    let certificate_protocol = matches!(request.protocol, Protocol::Hysteria2 | Protocol::Tuic)
        || (matches!(request.protocol, Protocol::AnyTls)
            && request.options.anytls_mode == AnyTlsMode::Tls);

    match (&request.certificate, &request.certificate_key) {
        (Some(_), None) | (None, Some(_)) => bail!("--cert 和 --key 必须同时提供"),
        (Some(_), Some(_)) if !certificate_protocol => {
            bail!("当前协议不使用 --cert/--key")
        }
        _ => {}
    }
    if request.reality_dest.is_some() && !reality_outer {
        bail!("--dest 仅适用于 Reality 或 Reality+AnyTLS");
    }
    if request.options.reality_short_id.is_some() && !reality_outer {
        bail!("--short-id 仅适用于 Reality 或 Reality+AnyTLS");
    }

    if matches!(request.protocol, Protocol::Shadowsocks) {
        if let Some(password) = &request.options.shadowsocks_password {
            validate_shadowsocks_password(request.options.shadowsocks_cipher, password)?;
        }
    } else if request.options.shadowsocks_password.is_some() {
        bail!("--password 仅适用于 Shadowsocks");
    }

    if matches!(request.protocol, Protocol::AnyTls) {
        validate_anytls_users(&request.options.anytls_users)?;
        if let Some(scheme) = &request.options.anytls_padding_scheme {
            validate_padding_scheme(scheme)?;
        }
        if let Some(fallback) = &request.options.anytls_fallback {
            validate_host_port(fallback)?;
        }
    } else if !request.options.anytls_users.is_empty()
        || request.options.anytls_padding_scheme.is_some()
        || request.options.anytls_fallback.is_some()
    {
        bail!("--user/--padding/--fallback 仅适用于 AnyTLS");
    }
    Ok(())
}

fn validate_server_name(value: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > 253
        || value.contains(char::is_whitespace)
        || value.contains('/')
        || value.contains([':', '\\'])
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
    {
        bail!("SNI/服务器名称无效");
    }
    Ok(())
}

fn validate_reality_short_id(value: &str) -> Result<()> {
    if value.len() > 16
        || !value.len().is_multiple_of(2)
        || !value.chars().all(|c| c.is_ascii_hexdigit())
    {
        bail!("Reality short ID 必须是 0..=16 个偶数长度十六进制字符");
    }
    Ok(())
}

fn validate_shadowsocks_password(cipher: ShadowsocksCipher, password: &str) -> Result<()> {
    if password.is_empty() || password.contains(char::is_control) {
        bail!("Shadowsocks 密码不能为空或包含控制字符");
    }
    if let Some(expected) = cipher.key_len() {
        let decoded = STANDARD
            .decode(password)
            .context("Shadowsocks 2022 密码必须使用标准 Base64 编码")?;
        if decoded.len() != expected {
            bail!(
                "{} 密码解码后必须为 {} 字节，当前为 {} 字节",
                cipher.as_str(),
                expected,
                decoded.len()
            );
        }
    }
    Ok(())
}

fn validate_anytls_users(users: &[AnyTlsUser]) -> Result<()> {
    if users.is_empty() {
        bail!("AnyTLS 至少需要一个用户");
    }
    for user in users {
        if user.name.len() > 64 || user.name.chars().any(char::is_control) {
            bail!("AnyTLS 用户名不能超过 64 字符或包含控制字符");
        }
        if user.password.is_empty() || user.password.chars().any(char::is_control) {
            bail!("AnyTLS 用户密码不能为空或包含控制字符");
        }
    }
    Ok(())
}

fn validate_padding_scheme(scheme: &[String]) -> Result<()> {
    if scheme.is_empty() {
        bail!("AnyTLS padding_scheme 不能为空");
    }
    let mut stop_count = 0;
    for entry in scheme {
        let (key, value) = entry
            .split_once('=')
            .context("AnyTLS padding 条目必须采用 key=value 格式")?;
        if key == "stop" {
            stop_count += 1;
            let stop = value
                .parse::<u32>()
                .context("AnyTLS padding 的 stop 必须是正整数")?;
            if stop == 0 {
                bail!("AnyTLS padding 的 stop 必须大于 0");
            }
            continue;
        }
        key.parse::<u32>()
            .context("AnyTLS padding 的包序号必须是非负整数")?;
        if value.is_empty() {
            bail!("AnyTLS padding 范围不能为空");
        }
        for range in value.split(',') {
            let (min, max) = match range.split_once('-') {
                Some((min, max)) => (
                    min.parse::<u32>().context("AnyTLS padding 下限无效")?,
                    max.parse::<u32>().context("AnyTLS padding 上限无效")?,
                ),
                None => {
                    let size = range.parse::<u32>().context("AnyTLS padding 长度无效")?;
                    (size, size)
                }
            };
            if min > max || max > 65_535 {
                bail!("AnyTLS padding 范围必须满足 0 <= min <= max <= 65535");
            }
        }
    }
    if stop_count != 1 {
        bail!("AnyTLS padding_scheme 必须且只能包含一个 stop=N 条目");
    }
    Ok(())
}

fn validate_host_port(value: &str) -> Result<()> {
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        let (host, port) = bracketed
            .split_once("]:")
            .context("IPv6 Reality fallback 必须采用 [address]:port 格式")?;
        (host, port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .context("Reality fallback 必须采用 host:port 格式")?;
        if host.contains(':') {
            bail!("IPv6 Reality fallback 必须使用方括号，例如 [2001:db8::1]:443");
        }
        (host, port)
    };
    if host.is_empty() || host.contains(char::is_whitespace) || host.contains(['/', '\\', '[', ']'])
    {
        bail!("Reality fallback 主机名或地址无效");
    }
    let port = port
        .parse::<u16>()
        .context("Reality fallback 端口必须是 1..=65535 的整数")?;
    if port == 0 {
        bail!("Reality fallback 端口必须在 1..=65535 范围内");
    }
    Ok(())
}

fn validate_yaml(yaml: &str) -> Result<()> {
    let configs =
        serde_yaml::from_str::<Vec<ServerConfig>>(yaml).context("生成的 YAML 无法反序列化")?;
    if configs.is_empty() {
        bail!("生成的配置至少应包含一个服务器");
    }
    Ok(())
}

async fn validate_candidate_with_shoes(yaml: &str, directory: &Path) -> Result<()> {
    validate_candidate_with_binary(yaml, directory, Path::new(utils::SHOES_BIN)).await
}

async fn validate_candidate_with_binary(yaml: &str, directory: &Path, binary: &Path) -> Result<()> {
    fs::create_dir_all(directory)
        .with_context(|| format!("创建候选配置目录 {} 失败", directory.display()))?;
    let mut candidate = tempfile::Builder::new()
        .prefix(".ping-rust-candidate-")
        .suffix(".yaml")
        .tempfile_in(directory)
        .context("创建候选配置失败")?;
    candidate
        .write_all(yaml.as_bytes())
        .context("写入候选配置失败")?;
    candidate.as_file().sync_all().context("同步候选配置失败")?;
    validate_with_binary(binary, candidate.path()).await
}

pub(crate) fn validate_managed_snapshot(config_path: &Path, state_path: &Path) -> Result<()> {
    let servers = load_servers(config_path)?;
    let state = load_state_from(state_path)?;
    ensure_servers_match_state(&servers, &state.profiles).context("备份内容不一致")
}

pub async fn validate_with_shoes(config_path: &Path) -> Result<()> {
    validate_with_binary(Path::new(utils::SHOES_BIN), config_path).await
}

pub(crate) async fn validate_with_binary(binary: &Path, config_path: &Path) -> Result<()> {
    if !binary.is_file() {
        bail!("shoes 尚未安装，无法执行 --dry-run 验证");
    }
    let output = Command::new(binary)
        .arg("--dry-run")
        .arg(config_path)
        .output()
        .await
        .context("无法启动 shoes 配置校验")?;
    if !output.status.success() {
        bail!(
            "shoes 拒绝生成的配置：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(protocol: Protocol, output: PathBuf) -> GenerationRequest {
        GenerationRequest {
            name: None,
            protocol,
            port: 443,
            output,
            server_address: None,
            server_name: "www.cloudflare.com".to_owned(),
            reality_dest: None,
            certificate: None,
            certificate_key: None,
            options: GenerationOptions::default(),
        }
    }

    #[test]
    fn reality_keys_are_x25519_base64url() {
        let pair = generate_reality_keypair();
        let private = URL_SAFE_NO_PAD.decode(&pair.private_key).unwrap();
        let public = URL_SAFE_NO_PAD.decode(&pair.public_key).unwrap();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
        let private: [u8; 32] = private.try_into().unwrap();
        let derived = PublicKey::from(&StaticSecret::from(private));
        assert_eq!(derived.as_bytes(), public.as_slice());
    }

    #[tokio::test]
    async fn reality_yaml_matches_shoes_shape() {
        let dir = tempfile::tempdir().unwrap();
        let result = generate_inner(
            request(Protocol::Reality, dir.path().join("reality.yaml")),
            false,
        )
        .await
        .unwrap();
        let yaml = std::fs::read_to_string(result.config_path).unwrap();
        assert!(yaml.contains("type: tls"));
        assert!(yaml.contains("reality_targets:"));
        assert!(yaml.contains("type: vless"));
        assert!(yaml.contains("vision: true"));
    }

    #[tokio::test]
    async fn hysteria2_generates_certificate_and_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let result = generate_inner(
            request(Protocol::Hysteria2, dir.path().join("hy2.yaml")),
            false,
        )
        .await
        .unwrap();
        let yaml = std::fs::read_to_string(result.config_path).unwrap();
        assert!(yaml.contains("type: hysteria2"));
        assert!(yaml.contains("transport: quic"));
        assert!(result.certificate_path.unwrap().is_file());
        assert!(result.certificate_key_path.unwrap().is_file());
    }

    #[tokio::test]
    async fn tuic_yaml_has_required_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let result = generate_inner(request(Protocol::Tuic, dir.path().join("tuic.yaml")), false)
            .await
            .unwrap();
        let yaml = std::fs::read_to_string(result.config_path).unwrap();
        assert!(yaml.contains("type: tuic"));
        assert!(yaml.contains("uuid:"));
        assert!(yaml.contains("zero_rtt_handshake: false"));
    }

    #[tokio::test]
    async fn shadowsocks_2022_generates_exact_key_length() {
        let dir = tempfile::tempdir().unwrap();
        let mut request = request(Protocol::Shadowsocks, dir.path().join("shadowsocks.yaml"));
        request.options.shadowsocks_cipher = ShadowsocksCipher::Aes256Gcm2022;
        let result = generate_inner(request, false).await.unwrap();
        let yaml = fs::read_to_string(result.config_path).unwrap();
        assert!(yaml.contains("type: shadowsocks"));
        assert!(yaml.contains("cipher: 2022-blake3-aes-256-gcm"));
        let Credentials::Shadowsocks { password, .. } = result.credentials else {
            panic!("expected Shadowsocks credentials");
        };
        assert_eq!(STANDARD.decode(password).unwrap().len(), 32);
    }

    #[tokio::test]
    async fn anytls_tls_and_reality_match_shoes_shape() {
        let dir = tempfile::tempdir().unwrap();
        let mut tls_request = request(Protocol::AnyTls, dir.path().join("anytls-tls.yaml"));
        tls_request.options.anytls_users = vec![generated_anytls_user("alice")];
        tls_request.options.anytls_padding_scheme = Some(vec![
            "stop=8".to_owned(),
            "0=30-30".to_owned(),
            "1=50-100".to_owned(),
        ]);
        let tls = generate_inner(tls_request, false).await.unwrap();
        let tls_yaml = fs::read_to_string(tls.config_path).unwrap();
        assert!(tls_yaml.contains("tls_targets:"));
        assert!(tls_yaml.contains("type: anytls"));
        assert!(tls_yaml.contains("padding_scheme:"));
        assert!(tls.certificate_path.unwrap().is_file());

        let mut reality_request = request(Protocol::AnyTls, dir.path().join("anytls-reality.yaml"));
        reality_request.options.anytls_mode = AnyTlsMode::Reality;
        reality_request.options.anytls_users = vec![generated_anytls_user("bob")];
        let reality = generate_inner(reality_request, false).await.unwrap();
        let reality_yaml = fs::read_to_string(reality.config_path).unwrap();
        assert!(reality_yaml.contains("reality_targets:"));
        assert!(reality_yaml.contains("type: anytls"));
        assert!(reality_yaml.contains("vision: false"));
        assert!(reality.certificate_path.is_none());
    }

    #[test]
    fn rejects_invalid_shadowsocks_2022_password_and_anytls_inputs() {
        let mut ss = request(Protocol::Shadowsocks, PathBuf::from("unused.yaml"));
        ss.options.shadowsocks_cipher = ShadowsocksCipher::Aes128Gcm2022;
        ss.options.shadowsocks_password = Some(STANDARD.encode([0u8; 15]));
        assert!(validate_request(&ss)
            .unwrap_err()
            .to_string()
            .contains("16 字节"));

        let mut anytls = request(Protocol::AnyTls, PathBuf::from("unused.yaml"));
        assert!(validate_request(&anytls)
            .unwrap_err()
            .to_string()
            .contains("至少需要一个用户"));
        anytls.options.anytls_users = vec![generated_anytls_user("alice")];
        anytls.options.anytls_padding_scheme = Some(vec!["0=100-10".to_owned()]);
        assert!(validate_request(&anytls).is_err());
    }

    #[test]
    fn validates_reality_short_ids() {
        validate_reality_short_id("").unwrap();
        validate_reality_short_id("0123456789abcdef").unwrap();
        assert!(validate_reality_short_id("xyz").is_err());
        assert!(validate_reality_short_id("123").is_err());
        assert!(validate_reality_short_id("0123456789abcdef00").is_err());
    }

    #[test]
    fn validates_multiple_server_entries() {
        let request = request(Protocol::Reality, PathBuf::from("unused.yaml"));
        let (first, _, _, _) = generate_reality(&request);
        let mut second_request = request;
        second_request.port = 8443;
        let (second, _, _, _) = generate_reality(&second_request);
        let yaml = serde_yaml::to_string(&vec![first, second]).unwrap();
        validate_yaml(&yaml).unwrap();
    }

    #[test]
    fn managed_snapshot_rejects_count_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        let state = dir.path().join("state.json");
        let request = request(Protocol::Reality, config.clone());
        let (server, _, _, _) = generate_reality(&request);
        fs::write(&config, serde_yaml::to_string(&vec![server]).unwrap()).unwrap();
        fs::write(
            &state,
            serde_json::to_vec(&ManagedState::default()).unwrap(),
        )
        .unwrap();
        assert!(validate_managed_snapshot(&config, &state).is_err());
    }

    #[test]
    fn managed_state_rejects_reordered_or_wrong_protocol_servers() {
        let first_request = request(Protocol::Reality, PathBuf::from("unused.yaml"));
        let (first_server, first_credentials, _, _) = generate_reality(&first_request);
        let mut second_request = request(Protocol::Reality, PathBuf::from("unused.yaml"));
        second_request.port = 8443;
        let (second_server, second_credentials, _, _) = generate_reality(&second_request);
        let profiles = vec![
            ManagedProfile {
                id: Uuid::new_v4(),
                name: "first".to_owned(),
                port: first_request.port,
                server_address: None,
                credentials: first_credentials,
                certificate_path: None,
                certificate_key_path: None,
                self_signed_certificate: false,
            },
            ManagedProfile {
                id: Uuid::new_v4(),
                name: "second".to_owned(),
                port: second_request.port,
                server_address: None,
                credentials: second_credentials,
                certificate_path: None,
                certificate_key_path: None,
                self_signed_certificate: false,
            },
        ];
        ensure_servers_match_state(&[first_server.clone(), second_server.clone()], &profiles)
            .unwrap();
        assert!(ensure_servers_match_state(&[second_server, first_server], &profiles).is_err());

        let (wrong_protocol, _, _, _) = generate_shadowsocks(&request(
            Protocol::Shadowsocks,
            PathBuf::from("unused.yaml"),
        ));
        assert!(ensure_servers_match_state(
            &[wrong_protocol, generate_reality(&second_request).0],
            &profiles,
        )
        .is_err());
    }

    #[test]
    fn validates_reality_destination_host_and_port() {
        validate_host_port("www.cloudflare.com:443").unwrap();
        validate_host_port("[2001:db8::1]:443").unwrap();
        assert!(validate_host_port("2001:db8::1:443").is_err());
        assert!(validate_host_port("example.com:not-a-port").is_err());
        assert!(validate_host_port("example.com:0").is_err());
    }

    #[test]
    fn managed_commit_restores_exact_config_when_state_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        let state = dir.path().join("state.json");
        fs::write(&config, b"old-config").unwrap();

        let error = commit_managed_with_state_writer(
            &config,
            &state,
            "new-config",
            &ManagedState::default(),
            |_, _| Err(anyhow::anyhow!("injected state write failure")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("已回滚"));
        assert_eq!(fs::read(&config).unwrap(), b"old-config");
        assert!(!state.exists());
    }

    #[test]
    fn managed_activation_rollback_restores_exact_files_and_removes_new_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        let state = dir.path().join("state.json");
        let certificate = dir.path().join("new.pem");
        let certificate_key = dir.path().join("new-key.pem");
        fs::write(&config, b"new-config").unwrap();
        fs::write(&state, b"new-state").unwrap();
        fs::write(&certificate, b"certificate").unwrap();
        fs::write(&certificate_key, b"private-key").unwrap();

        ManagedRollback {
            config: Some(b"old-config\n".to_vec()),
            state: None,
            generated_certificate: Some(certificate.clone()),
            generated_certificate_key: Some(certificate_key.clone()),
        }
        .restore_to(&config, &state)
        .unwrap();

        assert_eq!(fs::read(config).unwrap(), b"old-config\n");
        assert!(!state.exists());
        assert!(!certificate.exists());
        assert!(!certificate_key.exists());
    }

    #[test]
    fn old_managed_profiles_without_server_address_still_deserialize() {
        let profile = ManagedProfile {
            id: Uuid::nil(),
            name: "legacy".to_owned(),
            port: 443,
            server_address: None,
            credentials: Credentials::Reality {
                user_id: Uuid::nil(),
                private_key: "private".to_owned(),
                public_key: "public".to_owned(),
                short_id: "0123456789abcdef".to_owned(),
                server_name: "www.cloudflare.com".to_owned(),
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };
        let mut value = serde_json::to_value(profile).unwrap();
        value.as_object_mut().unwrap().remove("server_address");
        let restored: ManagedProfile = serde_json::from_value(value).unwrap();
        assert!(restored.server_address.is_none());
    }

    #[test]
    fn profile_name_validation_rejects_case_insensitive_duplicates() {
        let existing = ManagedProfile {
            id: Uuid::new_v4(),
            name: "Main".to_owned(),
            port: 443,
            server_address: None,
            credentials: Credentials::Reality {
                user_id: Uuid::new_v4(),
                private_key: "private".to_owned(),
                public_key: "public".to_owned(),
                short_id: "0123456789abcdef".to_owned(),
                server_name: DEFAULT_SNI.to_owned(),
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };
        assert!(validate_profile_name("main", std::slice::from_ref(&existing), None).is_err());
        validate_profile_name("main", std::slice::from_ref(&existing), Some(existing.id)).unwrap();
    }

    #[test]
    fn reality_profile_changes_keep_yaml_and_client_credentials_aligned() {
        let request = request(Protocol::Reality, PathBuf::from("unused.yaml"));
        let (mut server, credentials, _, _) = generate_reality(&request);
        let mut profile = ManagedProfile {
            id: Uuid::new_v4(),
            name: "reality-main".to_owned(),
            port: request.port,
            server_address: Some("203.0.113.10".to_owned()),
            credentials,
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };
        let old_public_key = match &profile.credentials {
            Credentials::Reality { public_key, .. } => public_key.clone(),
            _ => unreachable!(),
        };

        apply_profile_change(&mut server, &mut profile, ProfileChange::Port(24443)).unwrap();
        apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::RealityServerName("www.example.com".to_owned()),
        )
        .unwrap();
        apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::RegenerateCredentials,
        )
        .unwrap();

        assert_eq!(profile.port, 24443);
        assert_eq!(server.address, "0.0.0.0:24443");
        let Credentials::Reality {
            public_key,
            server_name,
            ..
        } = &profile.credentials
        else {
            unreachable!()
        };
        assert_ne!(public_key, &old_public_key);
        assert_eq!(server_name, "www.example.com");
        let ServerProtocol::Tls {
            reality_targets, ..
        } = &server.protocol
        else {
            unreachable!()
        };
        let target = reality_targets.get("www.example.com").unwrap();
        assert_eq!(target.dest, "www.example.com:443");
        validate_yaml(&serde_yaml::to_string(&vec![server]).unwrap()).unwrap();
    }

    #[test]
    fn shadowsocks_cipher_change_generates_matching_key_length() {
        let request = request(Protocol::Shadowsocks, PathBuf::from("unused.yaml"));
        let (mut server, credentials, _, _) = generate_shadowsocks(&request);
        let mut profile = ManagedProfile {
            id: Uuid::new_v4(),
            name: "ss-main".to_owned(),
            port: request.port,
            server_address: None,
            credentials,
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };

        apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::ShadowsocksCipher(ShadowsocksCipher::Aes128Gcm2022),
        )
        .unwrap();
        let Credentials::Shadowsocks {
            cipher, password, ..
        } = &profile.credentials
        else {
            unreachable!()
        };
        assert_eq!(*cipher, ShadowsocksCipher::Aes128Gcm2022);
        assert_eq!(STANDARD.decode(password).unwrap().len(), 16);
        let ServerProtocol::Shadowsocks {
            cipher: server_cipher,
            password: server_password,
            ..
        } = &server.protocol
        else {
            unreachable!()
        };
        assert_eq!(server_cipher, cipher.as_str());
        assert_eq!(server_password, password);
    }

    #[test]
    fn anytls_user_password_change_updates_server_and_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut request = request(Protocol::AnyTls, dir.path().join("unused.yaml"));
        request
            .options
            .anytls_users
            .push(generated_anytls_user("alice"));
        let (mut server, credentials, certificate, certificate_key) =
            generate_anytls(&request, dir.path(), Uuid::new_v4()).unwrap();
        let mut profile = ManagedProfile {
            id: Uuid::new_v4(),
            name: "anytls-main".to_owned(),
            port: request.port,
            server_address: None,
            credentials,
            certificate_path: certificate,
            certificate_key_path: certificate_key,
            self_signed_certificate: true,
        };

        apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::AnyTlsUserPassword {
                index: 0,
                password: "new-anytls-password".to_owned(),
            },
        )
        .unwrap();
        let Credentials::AnyTls { users, .. } = &profile.credentials else {
            unreachable!()
        };
        assert_eq!(users[0].password, "new-anytls-password");
        assert_eq!(anytls_users_mut(&mut server).unwrap(), users);
    }

    #[tokio::test]
    async fn rejected_candidate_is_removed_without_touching_live_file() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("config.yaml");
        fs::write(&live, b"known-good").unwrap();
        let current_test_binary = std::env::current_exe().unwrap();

        let result =
            validate_candidate_with_binary("candidate: invalid", dir.path(), &current_test_binary)
                .await;
        assert!(result.is_err());
        assert_eq!(fs::read(&live).unwrap(), b"known-good");
        let leftovers = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".ping-rust-candidate-")
            })
            .count();
        assert_eq!(leftovers, 0);
    }
}
