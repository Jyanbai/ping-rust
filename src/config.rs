#[cfg(test)]
use std::collections::BTreeMap;
use std::{
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
use rand::{Rng, RngCore};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    chain_proxy::{ChainProxyChange, ChainProxyState, ShoesClientConfig},
    performance, utils,
};

mod commit;
mod presets;
mod schema;
mod transaction;
mod validation;

#[cfg(test)]
use commit::{
    aggregate_profile_documents, commit_managed_with_state_writer, is_managed_profile_file_name,
};
use commit::{
    commit_managed, profile_documents, profile_documents_are_current, write_profile_documents,
};
use schema::{
    default_h3_alpn, ChainRule, InnerProtocol, QuicSettings, RealityTarget, ServerConfig,
    ServerProtocol, ServerRule, ShadowTlsHandshake, ShadowTlsTarget,
};
use transaction::{read_optional, CredentialCleanup, ManagedRollback, ProfileDirectorySnapshot};
pub(crate) use validation::validate_shadowsocks_password;
use validation::{
    validate_anytls_users, validate_host_port, validate_padding_scheme, validate_reality_short_id,
    validate_server_name, validate_websocket_path,
};

pub const DEFAULT_SNI: &str = "www.cloudflare.com";
pub const REALITY_FINGERPRINT: &str = "chrome";
pub const REALITY_SERVER_NAMES: &[&str] = &[
    "www.amazon.com",
    "www.ebay.com",
    "www.paypal.com",
    "www.cloudflare.com",
    "dash.cloudflare.com",
    "aws.amazon.com",
];

fn random_reality_server_name() -> &'static str {
    let index = rand::rng().random_range(0..REALITY_SERVER_NAMES.len());
    REALITY_SERVER_NAMES[index]
}

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
    #[value(name = "vless-tls", alias = "vless-tls-vision")]
    VlessTlsVision,
    #[value(name = "vless-ws-tls", alias = "vless-wss")]
    VlessWsTls,
    #[value(name = "trojan-tls")]
    TrojanTls,
    #[value(name = "trojan-reality")]
    TrojanReality,
    #[value(name = "vmess-ws-tls", alias = "vmess-wss")]
    VmessWsTls,
    #[value(name = "socks5", alias = "socks", alias = "s5")]
    Socks5,
    Snell,
}

impl Protocol {
    pub(crate) fn all() -> impl ExactSizeIterator<Item = Self> {
        presets::all().iter().map(|preset| preset.protocol)
    }

    pub(crate) fn from_menu_number(number: usize) -> Option<Self> {
        presets::from_menu_number(number)
    }

    pub(crate) fn menu_number(self) -> usize {
        presets::descriptor(self).menu_number
    }

    pub(crate) fn menu_label(self) -> &'static str {
        presets::descriptor(self).menu_label
    }

    pub(crate) fn advanced_label(self) -> &'static str {
        presets::descriptor(self).advanced_label
    }

    pub(crate) fn slug(self) -> &'static str {
        presets::descriptor(self).slug
    }

    pub(crate) fn display_prefix(self) -> &'static str {
        presets::descriptor(self).display_prefix
    }

    pub(crate) fn required_sockets(self) -> (bool, bool) {
        let preset = presets::descriptor(self);
        (preset.tcp_required, preset.udp_required)
    }

    pub fn uses_reality(self, anytls_mode: AnyTlsMode) -> bool {
        matches!(self, Self::Reality | Self::TrojanReality)
            || (matches!(self, Self::AnyTls) && anytls_mode == AnyTlsMode::Reality)
    }

    pub fn requires_certificate(self, anytls_mode: AnyTlsMode) -> bool {
        matches!(
            self,
            Self::Hysteria2
                | Self::Tuic
                | Self::VlessTlsVision
                | Self::VlessWsTls
                | Self::TrojanTls
                | Self::VmessWsTls
        ) || (matches!(self, Self::AnyTls) && anytls_mode == AnyTlsMode::Tls)
    }

    pub fn uses_websocket(self) -> bool {
        matches!(self, Self::VlessWsTls | Self::VmessWsTls)
    }
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

    pub fn is_2022(self) -> bool {
        self.key_len().is_some()
    }

    pub fn client_name(self) -> &'static str {
        match self {
            Self::Chacha20IetfPoly13052022 => "2022-blake3-chacha20-poly1305",
            _ => self.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShadowsocksMode {
    #[default]
    Plain,
    ShadowTlsV3,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowTlsCredentials {
    pub password: String,
    pub server_name: String,
    pub handshake_address: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum SnellCipher {
    #[value(name = "aes-128-gcm")]
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[value(name = "aes-256-gcm")]
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[default]
    #[value(name = "chacha20-ietf-poly1305")]
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
}

impl SnellCipher {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
        }
    }

    pub(crate) fn from_shadowsocks(cipher: ShadowsocksCipher) -> Result<Self> {
        match cipher {
            ShadowsocksCipher::Aes128Gcm => Ok(Self::Aes128Gcm),
            ShadowsocksCipher::Aes256Gcm => Ok(Self::Aes256Gcm),
            ShadowsocksCipher::Chacha20IetfPoly1305 => Ok(Self::Chacha20IetfPoly1305),
            _ => bail!(
                "Snell v3 不支持加密方式 {}；只允许 aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305",
                cipher.as_str()
            ),
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

pub fn resolve_server_name(
    explicit: Option<String>,
    protocol: Protocol,
    anytls_mode: AnyTlsMode,
) -> String {
    explicit.unwrap_or_else(|| {
        if protocol.uses_reality(anytls_mode) {
            random_reality_server_name().to_owned()
        } else {
            DEFAULT_SNI.to_owned()
        }
    })
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

pub(crate) fn generated_socks5_username() -> String {
    random_secret(9)
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
    pub shadowsocks_mode: ShadowsocksMode,
    pub shadowtls_password: Option<String>,
    pub shadowtls_handshake: Option<String>,
    pub snell_cipher: SnellCipher,
    pub snell_password: Option<String>,
    pub socks5_username: Option<String>,
    pub socks5_password: Option<String>,
    pub socks5_no_auth: bool,
    pub anytls_mode: AnyTlsMode,
    pub anytls_users: Vec<AnyTlsUser>,
    pub anytls_padding_scheme: Option<Vec<String>>,
    pub anytls_fallback: Option<String>,
    pub websocket_path: Option<String>,
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
            shadowsocks_mode: ShadowsocksMode::Plain,
            shadowtls_password: None,
            shadowtls_handshake: None,
            snell_cipher: SnellCipher::default(),
            snell_password: None,
            socks5_username: None,
            socks5_password: None,
            socks5_no_auth: false,
            anytls_mode: AnyTlsMode::default(),
            anytls_users: Vec::new(),
            anytls_padding_scheme: None,
            anytls_fallback: None,
            websocket_path: None,
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
    ShadowTlsPassword(String),
    ShadowTlsServerName(String),
    ShadowTlsHandshake(String),
    SnellCipher(SnellCipher),
    Socks5Username(String),
    Socks5Authentication(bool),
    UdpEnabled(bool),
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

pub(crate) struct DeletionResult {
    pub profile: ManagedProfile,
    pub remaining_profiles: usize,
    rollback: Option<ManagedRollback>,
    _lock: Option<utils::ExclusiveLock>,
}

pub(crate) struct ChainProxyUpdateResult {
    pub state: ManagedState,
    pub configuration_changed: bool,
    pub profiles_count: usize,
    rollback: Option<ManagedRollback>,
    _lock: Option<utils::ExclusiveLock>,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shadowtls: Option<ShadowTlsCredentials>,
    },
    Snell {
        cipher: SnellCipher,
        password: String,
        udp_enabled: bool,
    },
    Socks5 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        udp_enabled: bool,
    },
    AnyTls {
        users: Vec<AnyTlsUser>,
        server_name: String,
        alpn_protocols: Vec<String>,
        udp_enabled: bool,
        security: AnyTlsSecurity,
    },
    VlessTls {
        user_id: Uuid,
        server_name: String,
        alpn_protocols: Vec<String>,
        vision: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        websocket_path: Option<String>,
    },
    Trojan {
        password: String,
        server_name: String,
        alpn_protocols: Vec<String>,
        security: TlsSecurity,
    },
    VmessTls {
        user_id: Uuid,
        server_name: String,
        alpn_protocols: Vec<String>,
        websocket_path: String,
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

#[derive(Clone, Serialize, Deserialize)]
pub enum TlsSecurity {
    Tls,
    Reality {
        private_key: String,
        public_key: String,
        short_id: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ManagedState {
    pub schema_version: u8,
    pub profiles: Vec<ManagedProfile>,
    #[serde(default)]
    pub chain_proxy: ChainProxyState,
}

impl Default for ManagedState {
    fn default() -> Self {
        Self {
            schema_version: 2,
            profiles: Vec::new(),
            chain_proxy: ChainProxyState::default(),
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
        format!("{}-{}", self.protocol().display_prefix(), self.port)
    }

    pub fn config_file_name(&self) -> String {
        format!("{}.yaml", self.display_name())
    }

    pub fn protocol(&self) -> Protocol {
        match &self.credentials {
            Credentials::Reality { .. } => Protocol::Reality,
            Credentials::Hysteria2 { .. } => Protocol::Hysteria2,
            Credentials::Tuic { .. } => Protocol::Tuic,
            Credentials::Shadowsocks { .. } => Protocol::Shadowsocks,
            Credentials::AnyTls { .. } => Protocol::AnyTls,
            Credentials::VlessTls {
                websocket_path: None,
                ..
            } => Protocol::VlessTlsVision,
            Credentials::VlessTls {
                websocket_path: Some(_),
                ..
            } => Protocol::VlessWsTls,
            Credentials::Trojan {
                security: TlsSecurity::Tls,
                ..
            } => Protocol::TrojanTls,
            Credentials::Trojan {
                security: TlsSecurity::Reality { .. },
                ..
            } => Protocol::TrojanReality,
            Credentials::VmessTls { .. } => Protocol::VmessWsTls,
            Credentials::Snell { .. } => Protocol::Snell,
            Credentials::Socks5 { .. } => Protocol::Socks5,
        }
    }

    pub fn protocol_name(&self) -> &'static str {
        match &self.credentials {
            Credentials::Reality { .. } => "VLESS-Reality-Vision",
            Credentials::Hysteria2 { .. } => "Hysteria2",
            Credentials::Tuic { .. } => "TUIC v5",
            Credentials::Shadowsocks {
                shadowtls: Some(_), ..
            } => "Shadowsocks 2022 + ShadowTLS v3",
            Credentials::Shadowsocks { .. } => "Shadowsocks",
            Credentials::AnyTls { .. } => "AnyTLS",
            Credentials::VlessTls {
                websocket_path: Some(_),
                ..
            } => "VLESS-WS-TLS",
            Credentials::VlessTls { vision: true, .. } => "VLESS-TLS-Vision",
            Credentials::VlessTls { .. } => "VLESS-TLS",
            Credentials::Trojan {
                security: TlsSecurity::Tls,
                ..
            } => "Trojan-TLS",
            Credentials::Trojan {
                security: TlsSecurity::Reality { .. },
                ..
            } => "Trojan-Reality",
            Credentials::VmessTls { .. } => "VMess-WS-TLS",
            Credentials::Snell { .. } => "Snell v3",
            Credentials::Socks5 { .. } => "SOCKS5",
        }
    }

    pub fn server_name(&self) -> &str {
        match &self.credentials {
            Credentials::Reality { server_name, .. }
            | Credentials::Hysteria2 { server_name, .. }
            | Credentials::Tuic { server_name, .. }
            | Credentials::AnyTls { server_name, .. } => server_name,
            Credentials::VlessTls { server_name, .. }
            | Credentials::Trojan { server_name, .. }
            | Credentials::VmessTls { server_name, .. } => server_name,
            Credentials::Shadowsocks {
                shadowtls: Some(shadowtls),
                ..
            } => &shadowtls.server_name,
            Credentials::Shadowsocks { .. }
            | Credentials::Snell { .. }
            | Credentials::Socks5 { .. } => "-",
        }
    }
}

fn direct_rules() -> Vec<ServerRule> {
    vec![ServerRule::Group("allow-all-direct".to_owned())]
}

fn chain_rules(client: &ShoesClientConfig) -> Vec<ServerRule> {
    vec![ServerRule::Inline(ChainRule {
        masks: "0.0.0.0/0".to_owned(),
        action: "allow".to_owned(),
        client_chains: client.clone(),
    })]
}

fn apply_chain_proxy_rules(servers: &mut [ServerConfig], state: &ManagedState) {
    let rules = state
        .chain_proxy
        .effective()
        .map(|node| chain_rules(&node.client))
        .unwrap_or_else(direct_rules);
    for server in servers {
        server.rules.clone_from(&rules);
    }
}

fn ensure_chain_proxy_matches_state(servers: &[ServerConfig], state: &ManagedState) -> Result<()> {
    state.chain_proxy.validate().context("链式代理状态无效")?;
    if let Some(node) = state.chain_proxy.effective() {
        let expected = chain_rules(&node.client);
        if servers.iter().any(|server| server.rules != expected) {
            bail!("链式代理状态与 shoes 配置不一致");
        }
    } else if servers.iter().any(|server| {
        server
            .rules
            .iter()
            .any(|rule| matches!(rule, ServerRule::Inline(_)))
    }) {
        bail!("链式代理状态为关闭，但 shoes 配置仍包含链式出口");
    }
    Ok(())
}

fn ensure_chain_proxy_has_no_direct_udp_path(state: &ManagedState) -> Result<()> {
    if state.chain_proxy.effective().is_none() {
        return Ok(());
    }
    let unsafe_profiles = state
        .profiles
        .iter()
        .filter(|profile| matches!(profile.protocol(), Protocol::Hysteria2 | Protocol::Tuic))
        .map(ManagedProfile::config_file_name)
        .collect::<Vec<_>>();
    if !unsafe_profiles.is_empty() {
        bail!(
            "无法启用全局链式代理：当前 shoes 的 Hysteria2/TUIC UDP 路径会绕过 client chain 并直连。请先删除这些配置：{}",
            unsafe_profiles.join("、")
        );
    }
    Ok(())
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
    let needs_certificate = request
        .protocol
        .requires_certificate(request.options.anytls_mode);
    let self_signed = request.certificate.is_none() && needs_certificate;

    let generation_timer = performance::stage("config_generate");
    let generated = presets::generate(&request, parent, profile_id)?;
    drop(generation_timer);
    let presets::GeneratedPreset {
        server,
        credentials,
        certificate_path,
        certificate_key_path,
    } = generated;

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
    ensure_chain_proxy_matches_state(&servers, &state)?;
    servers.push(server);
    state.profiles.push(profile.clone());
    ensure_chain_proxy_has_no_direct_udp_path(&state)?;
    if state.chain_proxy.effective().is_some() {
        apply_chain_proxy_rules(&mut servers, &state);
    }

    let yaml = serde_yaml::to_string(&servers).context("序列化 shoes YAML 失败")?;
    validate_yaml(&yaml)?;
    if validate_with_shoes {
        validate_candidate_with_shoes(&yaml, parent).await?;
    }
    let rollback = if managed {
        Some(ManagedRollback {
            config: read_optional(Path::new(utils::CONFIG_FILE))?,
            state: read_optional(Path::new(utils::STATE_FILE))?,
            profiles: ProfileDirectorySnapshot::capture(Path::new(utils::PROFILES_DIR))?,
            generated_certificate: self_signed.then(|| certificate_path.clone()).flatten(),
            generated_certificate_key: self_signed.then(|| certificate_key_path.clone()).flatten(),
        })
    } else {
        None
    };
    if managed {
        commit_managed(
            &request.output,
            Path::new(utils::STATE_FILE),
            &servers,
            &state,
        )?;
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
    ensure_chain_proxy_matches_state(&servers, &state)?;

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
        ProfileChange::ShadowTlsServerName(server_name) => validate_server_name(server_name)?,
        ProfileChange::ShadowTlsHandshake(handshake) => validate_host_port(handshake)?,
        ProfileChange::ShadowTlsPassword(password)
            if password.is_empty() || password.chars().any(char::is_control) =>
        {
            bail!("ShadowTLS 密码不能为空或包含控制字符");
        }
        _ => {}
    }

    let rollback = ManagedRollback {
        config: read_optional(config_path)?,
        state: read_optional(state_path)?,
        profiles: ProfileDirectorySnapshot::capture(Path::new(utils::PROFILES_DIR))?,
        generated_certificate: None,
        generated_certificate_key: None,
    };
    apply_profile_change(&mut servers[index], &mut state.profiles[index], change)?;
    let profile = state.profiles[index].clone();
    let yaml = serde_yaml::to_string(&servers).context("序列化更新后 shoes YAML 失败")?;
    validate_yaml(&yaml)?;
    validate_candidate_with_shoes(&yaml, Path::new(utils::CONFIG_DIR)).await?;
    commit_managed(config_path, state_path, &servers, &state)?;

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
                (
                    ServerProtocol::Tls {
                        shadowtls_targets, ..
                    },
                    Credentials::Shadowsocks {
                        cipher,
                        password: state_password,
                        shadowtls: Some(shadowtls),
                        ..
                    },
                ) => {
                    validate_shadowsocks_password(*cipher, &password)?;
                    let target = shadowtls_targets
                        .get_mut(&shadowtls.server_name)
                        .context("ShadowTLS 配置中缺少现有 SNI 目标")?;
                    let InnerProtocol::Shadowsocks {
                        password: server_password,
                        ..
                    } = &mut target.protocol
                    else {
                        bail!("ShadowTLS 内层协议不是 Shadowsocks");
                    };
                    *server_password = password.clone();
                    *state_password = password;
                }
                (
                    ServerProtocol::Snell {
                        password: server_password,
                        ..
                    },
                    Credentials::Snell {
                        password: state_password,
                        ..
                    },
                ) => {
                    *server_password = password.clone();
                    *state_password = password;
                }
                (
                    ServerProtocol::Socks {
                        password: server_password,
                        ..
                    },
                    Credentials::Socks5 {
                        password: state_password,
                        ..
                    },
                ) if server_password.is_some() && state_password.is_some() => {
                    validate_socks5_component("密码", &password)?;
                    *server_password = Some(password.clone());
                    *state_password = Some(password);
                }
                (ServerProtocol::Socks { .. }, Credentials::Socks5 { .. }) => {
                    bail!("无认证 SOCKS5 请先切换为用户名密码认证")
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
            if matches!(
                profile.credentials,
                Credentials::Shadowsocks {
                    shadowtls: Some(_),
                    ..
                }
            ) && !cipher.is_2022()
            {
                bail!("ShadowTLS v3 模式只允许 Shadowsocks 2022 cipher");
            }
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
                (
                    ServerProtocol::Tls {
                        shadowtls_targets, ..
                    },
                    Credentials::Shadowsocks {
                        cipher: state_cipher,
                        password: state_password,
                        shadowtls: Some(shadowtls),
                        ..
                    },
                ) => {
                    let target = shadowtls_targets
                        .get_mut(&shadowtls.server_name)
                        .context("ShadowTLS 配置中缺少现有 SNI 目标")?;
                    let InnerProtocol::Shadowsocks {
                        cipher: server_cipher,
                        password: server_password,
                        ..
                    } = &mut target.protocol
                    else {
                        bail!("ShadowTLS 内层协议不是 Shadowsocks");
                    };
                    *server_cipher = cipher.as_str().to_owned();
                    *server_password = password.clone();
                    *state_cipher = cipher;
                    *state_password = password;
                }
                _ => bail!("只有 Shadowsocks 配置支持更改加密方式"),
            }
        }
        ProfileChange::ShadowTlsPassword(password) => {
            let (
                ServerProtocol::Tls {
                    shadowtls_targets, ..
                },
                Credentials::Shadowsocks {
                    shadowtls: Some(shadowtls),
                    ..
                },
            ) = (&mut server.protocol, &mut profile.credentials)
            else {
                bail!("只有 ShadowTLS Shadowsocks 配置支持更改 ShadowTLS 密码");
            };
            shadowtls_targets
                .get_mut(&shadowtls.server_name)
                .context("ShadowTLS 配置中缺少现有 SNI 目标")?
                .password = password.clone();
            shadowtls.password = password;
        }
        ProfileChange::ShadowTlsServerName(new_name) => {
            let (
                ServerProtocol::Tls {
                    shadowtls_targets, ..
                },
                Credentials::Shadowsocks {
                    shadowtls: Some(shadowtls),
                    ..
                },
            ) = (&mut server.protocol, &mut profile.credentials)
            else {
                bail!("只有 ShadowTLS Shadowsocks 配置支持更改 SNI");
            };
            if shadowtls_targets.len() != 1 {
                bail!("ShadowTLS 配置必须恰好包含一个目标");
            }
            let mut target = shadowtls_targets
                .remove(&shadowtls.server_name)
                .or_else(|| shadowtls_targets.pop_first().map(|(_, target)| target))
                .context("ShadowTLS 配置中缺少现有 SNI 目标")?;
            if target.handshake.address == format!("{}:443", shadowtls.server_name) {
                target.handshake.address = format!("{new_name}:443");
                shadowtls.handshake_address = target.handshake.address.clone();
            }
            shadowtls_targets.insert(new_name.clone(), target);
            shadowtls.server_name = new_name;
        }
        ProfileChange::ShadowTlsHandshake(handshake_address) => {
            let (
                ServerProtocol::Tls {
                    shadowtls_targets, ..
                },
                Credentials::Shadowsocks {
                    shadowtls: Some(shadowtls),
                    ..
                },
            ) = (&mut server.protocol, &mut profile.credentials)
            else {
                bail!("只有 ShadowTLS Shadowsocks 配置支持更改握手目标");
            };
            shadowtls_targets
                .get_mut(&shadowtls.server_name)
                .context("ShadowTLS 配置中缺少现有 SNI 目标")?
                .handshake
                .address = handshake_address.clone();
            shadowtls.handshake_address = handshake_address;
        }
        ProfileChange::SnellCipher(cipher) => {
            match (&mut server.protocol, &mut profile.credentials) {
                (
                    ServerProtocol::Snell {
                        cipher: server_cipher,
                        ..
                    },
                    Credentials::Snell {
                        cipher: state_cipher,
                        ..
                    },
                ) => {
                    *server_cipher = cipher.as_str().to_owned();
                    *state_cipher = cipher;
                }
                _ => bail!("只有 Snell v3 配置支持更改加密方式"),
            }
        }
        ProfileChange::Socks5Username(username) => {
            validate_socks5_component("用户名", &username)?;
            match (&mut server.protocol, &mut profile.credentials) {
                (
                    ServerProtocol::Socks {
                        username: server_username,
                        password: server_password,
                        ..
                    },
                    Credentials::Socks5 {
                        username: state_username,
                        password: state_password,
                        ..
                    },
                ) if server_password.is_some() && state_password.is_some() => {
                    *server_username = Some(username.clone());
                    *state_username = Some(username);
                }
                (ServerProtocol::Socks { .. }, Credentials::Socks5 { .. }) => {
                    bail!("无认证 SOCKS5 请先切换为用户名密码认证")
                }
                _ => bail!("只有 SOCKS5 配置支持更改用户名"),
            }
        }
        ProfileChange::Socks5Authentication(enabled) => {
            match (&mut server.protocol, &mut profile.credentials) {
                (
                    ServerProtocol::Socks {
                        username: server_username,
                        password: server_password,
                        ..
                    },
                    Credentials::Socks5 {
                        username: state_username,
                        password: state_password,
                        ..
                    },
                ) => {
                    if enabled {
                        let username = state_username
                            .clone()
                            .unwrap_or_else(generated_socks5_username);
                        let password = state_password.clone().unwrap_or_else(generated_password);
                        *server_username = Some(username.clone());
                        *server_password = Some(password.clone());
                        *state_username = Some(username);
                        *state_password = Some(password);
                    } else {
                        *server_username = None;
                        *server_password = None;
                        *state_username = None;
                        *state_password = None;
                    }
                }
                _ => bail!("只有 SOCKS5 配置支持更改认证模式"),
            }
        }
        ProfileChange::UdpEnabled(enabled) => {
            match (&mut server.protocol, &mut profile.credentials) {
                (
                    ServerProtocol::Socks {
                        udp_enabled: server_udp,
                        ..
                    },
                    Credentials::Socks5 {
                        udp_enabled: state_udp,
                        ..
                    },
                ) => {
                    *server_udp = enabled;
                    *state_udp = enabled;
                }
                (
                    ServerProtocol::Snell {
                        udp_enabled: server_udp,
                        ..
                    },
                    Credentials::Snell {
                        udp_enabled: state_udp,
                        ..
                    },
                ) => {
                    *server_udp = enabled;
                    *state_udp = enabled;
                }
                _ => bail!("只有 SOCKS5 或 Snell v3 配置支持更改 UDP"),
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
            cipher,
            password,
            shadowtls,
            ..
        } => {
            let generated = generate_shadowsocks_password(*cipher);
            if let Some(shadowtls) = shadowtls {
                let ServerProtocol::Tls {
                    shadowtls_targets, ..
                } = &mut server.protocol
                else {
                    bail!("ShadowTLS Shadowsocks 配置与管理状态不一致");
                };
                let target = shadowtls_targets
                    .get_mut(&shadowtls.server_name)
                    .context("ShadowTLS 配置中缺少现有 SNI 目标")?;
                let InnerProtocol::Shadowsocks {
                    cipher: server_cipher,
                    password: server_password,
                    ..
                } = &mut target.protocol
                else {
                    bail!("ShadowTLS 内层协议不是 Shadowsocks");
                };
                *server_cipher = cipher.as_str().to_owned();
                *server_password = generated.clone();
                let shadowtls_password = generated_password();
                target.password = shadowtls_password.clone();
                shadowtls.password = shadowtls_password;
            } else {
                let ServerProtocol::Shadowsocks {
                    cipher: server_cipher,
                    password: server_password,
                    ..
                } = &mut server.protocol
                else {
                    bail!("Shadowsocks 配置与管理状态不一致");
                };
                *server_cipher = cipher.as_str().to_owned();
                *server_password = generated.clone();
            }
            *password = generated;
        }
        Credentials::Snell {
            cipher, password, ..
        } => {
            let ServerProtocol::Snell {
                cipher: server_cipher,
                password: server_password,
                ..
            } = &mut server.protocol
            else {
                bail!("Snell v3 配置与管理状态不一致");
            };
            let generated = generated_password();
            *server_cipher = cipher.as_str().to_owned();
            *server_password = generated.clone();
            *password = generated;
        }
        Credentials::Socks5 {
            username, password, ..
        } => {
            let ServerProtocol::Socks {
                username: server_username,
                password: server_password,
                ..
            } = &mut server.protocol
            else {
                bail!("SOCKS5 配置与管理状态不一致");
            };
            let generated_username = generated_socks5_username();
            let generated_password = generated_password();
            *server_username = Some(generated_username.clone());
            *server_password = Some(generated_password.clone());
            *username = Some(generated_username);
            *password = Some(generated_password);
        }
        Credentials::AnyTls { users, .. } => {
            for user in users.iter_mut() {
                user.password = random_secret(24);
            }
            *anytls_users_mut(server)? = users.clone();
        }
        Credentials::VlessTls { user_id, .. } => {
            let generated = Uuid::new_v4();
            *vless_user_id_mut(only_tls_inner_mut(server)?)? = generated;
            *user_id = generated;
        }
        Credentials::Trojan {
            password, security, ..
        } => {
            let generated = generated_password();
            match security {
                TlsSecurity::Tls => {
                    *trojan_password_mut(only_tls_inner_mut(server)?)? = generated.clone();
                }
                TlsSecurity::Reality {
                    private_key,
                    public_key,
                    short_id,
                } => {
                    let target = only_reality_target_mut(server)?;
                    *trojan_password_mut(&mut target.protocol)? = generated.clone();
                    let keypair = generate_reality_keypair();
                    let generated_short_id = random_hex(8);
                    target.private_key = keypair.private_key.clone();
                    target.short_ids = vec![generated_short_id.clone()];
                    *private_key = keypair.private_key;
                    *public_key = keypair.public_key;
                    *short_id = generated_short_id;
                }
            }
            *password = generated;
        }
        Credentials::VmessTls { user_id, .. } => {
            let generated = Uuid::new_v4();
            *vmess_user_id_mut(only_tls_inner_mut(server)?)? = generated;
            *user_id = generated;
        }
    }
    Ok(())
}

fn only_tls_inner_mut(server: &mut ServerConfig) -> Result<&mut InnerProtocol> {
    let ServerProtocol::Tls { tls_targets, .. } = &mut server.protocol else {
        bail!("TLS 配置与管理状态不一致");
    };
    if tls_targets.len() != 1 {
        bail!("TLS 配置必须恰好包含一个目标");
    }
    Ok(&mut tls_targets
        .values_mut()
        .next()
        .context("TLS 配置中缺少目标")?
        .protocol)
}

fn only_reality_target_mut(server: &mut ServerConfig) -> Result<&mut RealityTarget> {
    let ServerProtocol::Tls {
        reality_targets, ..
    } = &mut server.protocol
    else {
        bail!("Reality 配置与管理状态不一致");
    };
    if reality_targets.len() != 1 {
        bail!("Reality 配置必须恰好包含一个目标");
    }
    reality_targets
        .values_mut()
        .next()
        .context("Reality 配置中缺少目标")
}

fn vless_user_id_mut(protocol: &mut InnerProtocol) -> Result<&mut Uuid> {
    match protocol {
        InnerProtocol::Vless { user_id, .. } => Ok(user_id),
        InnerProtocol::Websocket { targets } if targets.len() == 1 => {
            vless_user_id_mut(&mut targets[0].protocol)
        }
        _ => bail!("TLS 目标内层协议不是 VLESS"),
    }
}

fn trojan_password_mut(protocol: &mut InnerProtocol) -> Result<&mut String> {
    match protocol {
        InnerProtocol::Trojan { password } => Ok(password),
        InnerProtocol::Websocket { targets } if targets.len() == 1 => {
            trojan_password_mut(&mut targets[0].protocol)
        }
        _ => bail!("TLS/Reality 目标内层协议不是 Trojan"),
    }
}

fn vmess_user_id_mut(protocol: &mut InnerProtocol) -> Result<&mut Uuid> {
    match protocol {
        InnerProtocol::Vmess { user_id, .. } => Ok(user_id),
        InnerProtocol::Websocket { targets } if targets.len() == 1 => {
            vmess_user_id_mut(&mut targets[0].protocol)
        }
        _ => bail!("TLS 目标内层协议不是 VMess"),
    }
}

fn anytls_users_mut(server: &mut ServerConfig) -> Result<&mut Vec<AnyTlsUser>> {
    let ServerProtocol::Tls {
        tls_targets,
        shadowtls_targets: _,
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
    format!("{}-{}", protocol.slug(), &id.simple().to_string()[..8])
}

fn load_servers(path: &Path) -> Result<Vec<ServerConfig>> {
    let yaml =
        fs::read_to_string(path).with_context(|| format!("读取配置 {} 失败", path.display()))?;
    serde_yaml::from_str(&yaml).context("现有 shoes 配置不是 ping-rust 可管理的格式")
}

pub async fn ensure_profile_files() -> Result<bool> {
    utils::require_linux_root()?;
    let lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    let config_path = Path::new(utils::CONFIG_FILE);
    let state_path = Path::new(utils::STATE_FILE);
    if !config_path.exists() && !state_path.exists() {
        return Ok(false);
    }
    let state = load_state_for_update()?;
    let servers = load_servers(config_path)?;
    ensure_servers_match_state(&servers, &state.profiles)
        .context("旧版聚合配置与管理状态不一致，无法安全迁移节点文件")?;
    ensure_chain_proxy_matches_state(&servers, &state)?;
    let documents = profile_documents(&servers, &state.profiles)?;
    if profile_documents_are_current(Path::new(utils::PROFILES_DIR), &documents)? {
        return Ok(false);
    }
    let yaml = serde_yaml::to_string(&servers).context("序列化迁移聚合配置失败")?;
    if !servers.is_empty() {
        validate_candidate_with_shoes(&yaml, Path::new(utils::CONFIG_DIR)).await?;
    }
    commit_managed(config_path, state_path, &servers, &state)?;
    drop(lock);
    Ok(true)
}

pub(crate) fn prepare_managed_snapshot(directory: &Path) -> Result<bool> {
    let config_path = directory.join("config.yaml");
    let state_path = directory.join("ping-rust-state.json");
    if !state_path.exists() {
        return Ok(false);
    }
    let state = load_state_from(&state_path)?;
    let servers = load_servers(&config_path)?;
    ensure_servers_match_state(&servers, &state.profiles).context("备份内容不一致")?;
    ensure_chain_proxy_matches_state(&servers, &state).context("备份内容不一致")?;
    ensure_chain_proxy_has_no_direct_udp_path(&state).context("备份内容不安全")?;
    let documents = profile_documents(&servers, &state.profiles)?;
    let profiles_path = directory.join("profiles");
    if profile_documents_are_current(&profiles_path, &documents)? {
        return Ok(false);
    }
    write_profile_documents(&profiles_path, &documents)?;
    Ok(true)
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
            | (ServerProtocol::Shadowsocks { .. }, Protocol::Shadowsocks)
            | (ServerProtocol::Snell { .. }, Protocol::Snell)
            | (ServerProtocol::Socks { .. }, Protocol::Socks5) => true,
            (
                ServerProtocol::Tls {
                    shadowtls_targets, ..
                },
                Protocol::Shadowsocks,
            ) => shadowtls_targets
                .values()
                .any(|target| matches!(target.protocol, InnerProtocol::Shadowsocks { .. })),
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
                    ..
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
            (ServerProtocol::Tls { tls_targets, .. }, Protocol::VlessTlsVision) => {
                tls_targets.values().any(|target| {
                    target.vision && matches!(target.protocol, InnerProtocol::Vless { .. })
                })
            }
            (ServerProtocol::Tls { tls_targets, .. }, Protocol::VlessWsTls) => tls_targets
                .values()
                .any(|target| !target.vision && inner_is_websocket_vless(&target.protocol)),
            (ServerProtocol::Tls { tls_targets, .. }, Protocol::TrojanTls) => tls_targets
                .values()
                .any(|target| matches!(target.protocol, InnerProtocol::Trojan { .. })),
            (
                ServerProtocol::Tls {
                    reality_targets, ..
                },
                Protocol::TrojanReality,
            ) => reality_targets.values().any(|target| {
                !target.vision && matches!(target.protocol, InnerProtocol::Trojan { .. })
            }),
            (ServerProtocol::Tls { tls_targets, .. }, Protocol::VmessWsTls) => tls_targets
                .values()
                .any(|target| inner_is_websocket_vmess(&target.protocol)),
            _ => false,
        };
        if !protocol_matches {
            bail!("第 {} 项协议与管理状态 {} 不一致", index + 1, profile.id);
        }
    }
    Ok(())
}

fn inner_is_websocket_vless(protocol: &InnerProtocol) -> bool {
    matches!(
        protocol,
        InnerProtocol::Websocket { targets }
            if targets.len() == 1
                && matches!(targets[0].protocol, InnerProtocol::Vless { .. })
    )
}

fn inner_is_websocket_vmess(protocol: &InnerProtocol) -> bool {
    matches!(
        protocol,
        InnerProtocol::Websocket { targets }
            if targets.len() == 1
                && matches!(targets[0].protocol, InnerProtocol::Vmess { .. })
    )
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
    let mut state: ManagedState = serde_json::from_str(&json).context("管理状态 JSON 已损坏")?;
    if !matches!(state.schema_version, 1 | 2) {
        bail!("不支持的管理状态版本 {}", state.schema_version);
    }
    state.schema_version = 2;
    state.chain_proxy.validate().context("链式代理状态无效")?;
    Ok(state)
}

fn save_state_to(path: &Path, state: &ManagedState) -> Result<()> {
    let json = serde_json::to_vec_pretty(state).context("序列化管理状态失败")?;
    utils::atomic_write(path, &json, 0o600)
}

pub(crate) async fn update_chain_proxy_locked(
    change: ChainProxyChange,
    lock: utils::ExclusiveLock,
) -> Result<ChainProxyUpdateResult> {
    utils::require_linux_root()?;
    utils::ensure_directory(Path::new(utils::CONFIG_DIR), 0o700)?;
    let config_path = Path::new(utils::CONFIG_FILE);
    let state_path = Path::new(utils::STATE_FILE);
    let mut state = load_state_for_update()?;
    let mut servers = if config_path.exists() {
        load_servers(config_path)?
    } else {
        Vec::new()
    };
    ensure_servers_match_state(&servers, &state.profiles)
        .context("配置文件与管理状态不一致，已拒绝修改链式代理")?;
    ensure_chain_proxy_matches_state(&servers, &state)?;
    let rollback = ManagedRollback {
        config: read_optional(config_path)?,
        state: read_optional(state_path)?,
        profiles: ProfileDirectorySnapshot::capture(Path::new(utils::PROFILES_DIR))?,
        generated_certificate: None,
        generated_certificate_key: None,
    };
    let old_effective = state.chain_proxy.effective().map(|node| node.id);
    state.chain_proxy.apply(change)?;
    ensure_chain_proxy_has_no_direct_udp_path(&state)?;
    let new_effective = state.chain_proxy.effective().map(|node| node.id);
    let configuration_changed = old_effective != new_effective;
    if configuration_changed {
        apply_chain_proxy_rules(&mut servers, &state);
    }
    let yaml = serde_yaml::to_string(&servers).context("序列化链式代理配置失败")?;
    if !servers.is_empty() {
        validate_yaml(&yaml)?;
        validate_candidate_with_shoes(&yaml, Path::new(utils::CONFIG_DIR)).await?;
    }
    commit_managed(config_path, state_path, &servers, &state)?;
    let profiles_count = state.profiles.len();
    Ok(ChainProxyUpdateResult {
        state,
        configuration_changed,
        profiles_count,
        rollback: Some(rollback),
        _lock: Some(lock),
    })
}

pub(crate) async fn delete_profile_locked(
    id: Uuid,
    lock: utils::ExclusiveLock,
) -> Result<DeletionResult> {
    utils::require_linux_root()?;
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
    ensure_chain_proxy_matches_state(&servers, &state)?;
    let rollback = ManagedRollback {
        config: read_optional(config_path)?,
        state: read_optional(Path::new(utils::STATE_FILE))?,
        profiles: ProfileDirectorySnapshot::capture(Path::new(utils::PROFILES_DIR))?,
        generated_certificate: None,
        generated_certificate_key: None,
    };
    servers.remove(index);
    let profile = state.profiles.remove(index);
    let yaml = serde_yaml::to_string(&servers).context("序列化更新后配置失败")?;
    if !servers.is_empty() {
        validate_yaml(&yaml)?;
        validate_candidate_with_shoes(&yaml, Path::new(utils::CONFIG_DIR)).await?;
    }
    commit_managed(config_path, Path::new(utils::STATE_FILE), &servers, &state)?;

    Ok(DeletionResult {
        profile,
        remaining_profiles: state.profiles.len(),
        rollback: Some(rollback),
        _lock: Some(lock),
    })
}

pub fn generated_websocket_path() -> String {
    format!("/{}", random_hex(8))
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
        rules: direct_rules(),
    }
}

pub(crate) fn generate_shadowsocks_password(cipher: ShadowsocksCipher) -> String {
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
    if !matches!(
        request.protocol,
        Protocol::Shadowsocks | Protocol::Snell | Protocol::Socks5
    ) || (matches!(request.protocol, Protocol::Shadowsocks)
        && request.options.shadowsocks_mode == ShadowsocksMode::ShadowTlsV3)
    {
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

    let reality_outer = request.protocol.uses_reality(request.options.anytls_mode);
    let certificate_protocol = request
        .protocol
        .requires_certificate(request.options.anytls_mode);

    match (&request.certificate, &request.certificate_key) {
        (Some(_), None) | (None, Some(_)) => bail!("--cert 和 --key 必须同时提供"),
        (Some(_), Some(_)) if !certificate_protocol => {
            bail!("当前协议不使用 --cert/--key")
        }
        _ => {}
    }
    if request.reality_dest.is_some() && !reality_outer {
        bail!("--dest 仅适用于使用 Reality 的协议预设");
    }
    if request.options.reality_short_id.is_some() && !reality_outer {
        bail!("--short-id 仅适用于使用 Reality 的协议预设");
    }
    if let Some(path) = &request.options.websocket_path {
        if !request.protocol.uses_websocket() {
            bail!("--websocket-path 仅适用于 VLESS-WS-TLS/VMess-WS-TLS");
        }
        validate_websocket_path(path)?;
    }

    if matches!(request.protocol, Protocol::Shadowsocks) {
        if let Some(password) = &request.options.shadowsocks_password {
            validate_shadowsocks_password(request.options.shadowsocks_cipher, password)?;
        }
        if request.options.shadowsocks_mode == ShadowsocksMode::ShadowTlsV3 {
            if !request.options.shadowsocks_cipher.is_2022() {
                bail!("ShadowTLS v3 模式只允许 Shadowsocks 2022 cipher");
            }
            if let Some(password) = &request.options.shadowtls_password {
                if password.is_empty() || password.chars().any(char::is_control) {
                    bail!("ShadowTLS 密码不能为空或包含控制字符");
                }
            }
            validate_host_port(
                request
                    .options
                    .shadowtls_handshake
                    .as_deref()
                    .unwrap_or(&format!("{}:443", request.server_name)),
            )?;
        } else if request.options.shadowtls_password.is_some()
            || request.options.shadowtls_handshake.is_some()
        {
            bail!("ShadowTLS 参数需要显式启用 ShadowTLS v3 模式");
        }
    } else if request.options.shadowsocks_password.is_some() {
        bail!("--password 仅适用于 Shadowsocks");
    } else if request.options.shadowsocks_mode != ShadowsocksMode::Plain
        || request.options.shadowtls_password.is_some()
        || request.options.shadowtls_handshake.is_some()
    {
        bail!("ShadowTLS v3 仅适用于 Shadowsocks");
    }

    if matches!(request.protocol, Protocol::Snell) {
        if let Some(password) = &request.options.snell_password {
            if password.is_empty() || password.chars().any(char::is_control) {
                bail!("Snell v3 密码不能为空或包含控制字符");
            }
        }
    } else if request.options.snell_password.is_some() {
        bail!("Snell 密码仅适用于 Snell v3");
    }

    if matches!(request.protocol, Protocol::Socks5) {
        if request.options.socks5_no_auth {
            if request.options.socks5_username.is_some()
                || request.options.socks5_password.is_some()
            {
                bail!("--no-auth 不能与 SOCKS5 用户名或密码同时使用");
            }
        } else {
            if let Some(username) = request.options.socks5_username.as_deref() {
                validate_socks5_component("用户名", username)?;
            }
            if let Some(password) = request.options.socks5_password.as_deref() {
                validate_socks5_component("密码", password)?;
            }
        }
    } else if request.options.socks5_username.is_some()
        || request.options.socks5_password.is_some()
        || request.options.socks5_no_auth
    {
        bail!("--username/--no-auth 仅适用于 SOCKS5");
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

fn validate_socks5_component(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
        bail!("SOCKS5 {label}必须为 1..=255 字节且不能包含控制字符");
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
    ensure_servers_match_state(&servers, &state.profiles).context("备份内容不一致")?;
    ensure_chain_proxy_matches_state(&servers, &state).context("备份内容不一致")?;
    ensure_chain_proxy_has_no_direct_udp_path(&state).context("备份内容不安全")?;
    let profiles_path = config_path
        .parent()
        .context("备份配置没有父目录")?
        .join("profiles");
    if profiles_path.exists() {
        let documents = profile_documents(&servers, &state.profiles)?;
        if !profile_documents_are_current(&profiles_path, &documents)? {
            bail!("备份中的节点文件与聚合配置不一致");
        }
    }
    Ok(())
}

pub async fn validate_with_shoes(config_path: &Path) -> Result<()> {
    validate_with_binary(Path::new(utils::SHOES_BIN), config_path).await
}

pub(crate) async fn validate_with_binary(binary: &Path, config_path: &Path) -> Result<()> {
    let _timer = performance::stage("shoes_dry_run");
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

    fn is_generated_socks5_username(value: &str) -> bool {
        value.len() == 12
            && value != "default"
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    }

    #[test]
    fn generated_socks5_username_is_url_safe_and_fixed_length() {
        for _ in 0..64 {
            assert!(is_generated_socks5_username(&generated_socks5_username()));
        }
    }

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

    fn generate_parts(
        request: &GenerationRequest,
        parent: &Path,
        profile_id: Uuid,
    ) -> Result<(ServerConfig, Credentials, Option<PathBuf>, Option<PathBuf>)> {
        let generated = presets::generate(request, parent, profile_id)?;
        Ok((
            generated.server,
            generated.credentials,
            generated.certificate_path,
            generated.certificate_key_path,
        ))
    }

    fn generate_reality(
        request: &GenerationRequest,
    ) -> (ServerConfig, Credentials, Option<PathBuf>, Option<PathBuf>) {
        generate_parts(request, Path::new("."), Uuid::nil()).unwrap()
    }

    fn generate_shadowsocks(
        request: &GenerationRequest,
    ) -> (ServerConfig, Credentials, Option<PathBuf>, Option<PathBuf>) {
        generate_parts(request, Path::new("."), Uuid::nil()).unwrap()
    }

    fn generate_anytls(
        request: &GenerationRequest,
        parent: &Path,
        profile_id: Uuid,
    ) -> Result<(ServerConfig, Credentials, Option<PathBuf>, Option<PathBuf>)> {
        generate_parts(request, parent, profile_id)
    }

    #[test]
    fn reality_defaults_match_the_local_233boy_source() {
        assert_eq!(
            REALITY_SERVER_NAMES,
            [
                "www.amazon.com",
                "www.ebay.com",
                "www.paypal.com",
                "www.cloudflare.com",
                "dash.cloudflare.com",
                "aws.amazon.com",
            ]
        );
        assert!(REALITY_SERVER_NAMES
            .iter()
            .all(|name| !name.to_ascii_lowercase().contains("apple")));
        assert_eq!(REALITY_FINGERPRINT, "chrome");

        for _ in 0..64 {
            let selected = resolve_server_name(None, Protocol::Reality, AnyTlsMode::Tls);
            assert!(REALITY_SERVER_NAMES.contains(&selected.as_str()));
        }
        let anytls_reality = resolve_server_name(None, Protocol::AnyTls, AnyTlsMode::Reality);
        assert!(REALITY_SERVER_NAMES.contains(&anytls_reality.as_str()));
        let trojan_reality = resolve_server_name(None, Protocol::TrojanReality, AnyTlsMode::Tls);
        assert!(REALITY_SERVER_NAMES.contains(&trojan_reality.as_str()));
    }

    #[test]
    fn explicit_and_tls_server_names_keep_existing_behavior() {
        assert_eq!(
            resolve_server_name(
                Some("custom.example.com".to_owned()),
                Protocol::Reality,
                AnyTlsMode::Tls,
            ),
            "custom.example.com"
        );
        assert_eq!(
            resolve_server_name(None, Protocol::Hysteria2, AnyTlsMode::Tls),
            DEFAULT_SNI
        );
        assert_eq!(
            resolve_server_name(None, Protocol::AnyTls, AnyTlsMode::Tls),
            DEFAULT_SNI
        );
    }

    fn reality_server_and_profile(port: u16) -> (ServerConfig, ManagedProfile) {
        let mut request = request(Protocol::Reality, PathBuf::from("unused.yaml"));
        request.port = port;
        let (server, credentials, _, _) = generate_reality(&request);
        let profile = ManagedProfile {
            id: Uuid::new_v4(),
            name: format!("reality-{port}"),
            port,
            server_address: None,
            credentials,
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };
        (server, profile)
    }

    #[test]
    fn legacy_state_without_chain_proxy_migrates_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, br#"{"schema_version":1,"profiles":[]}"#).unwrap();
        let state = load_state_from(&path).unwrap();
        assert_eq!(state.schema_version, 2);
        assert!(!state.chain_proxy.enabled);
        assert!(state.chain_proxy.nodes.is_empty());
    }

    #[test]
    fn chain_proxy_compiles_to_shoes_client_chain_for_every_server() {
        let (first, first_profile) = reality_server_and_profile(53453);
        let (second, second_profile) = reality_server_and_profile(53454);
        let node = crate::chain_proxy::parse_share_uri(
            "socks5://alice:secret@proxy.example.com:1080#exit",
        )
        .unwrap();
        let id = node.id;
        let mut state = ManagedState {
            schema_version: 2,
            profiles: vec![first_profile, second_profile],
            chain_proxy: ChainProxyState::default(),
        };
        state
            .chain_proxy
            .apply(ChainProxyChange::Add(node))
            .unwrap();
        state
            .chain_proxy
            .apply(ChainProxyChange::Select(id))
            .unwrap();
        state
            .chain_proxy
            .apply(ChainProxyChange::SetEnabled(true))
            .unwrap();
        let mut servers = vec![first, second];
        apply_chain_proxy_rules(&mut servers, &state);
        ensure_chain_proxy_matches_state(&servers, &state).unwrap();
        let yaml = serde_yaml::to_string(&servers).unwrap();
        validate_yaml(&yaml).unwrap();
        assert_eq!(yaml.matches("client_chains:").count(), 2);
        assert_eq!(yaml.matches("masks: 0.0.0.0/0").count(), 2);
        assert!(yaml.contains("type: socks"));
        assert!(yaml.contains("username: alice"));
        assert!(yaml.contains("password: secret"));

        state
            .chain_proxy
            .apply(ChainProxyChange::SetEnabled(false))
            .unwrap();
        assert!(ensure_chain_proxy_matches_state(&servers, &state).is_err());
        apply_chain_proxy_rules(&mut servers, &state);
        ensure_chain_proxy_matches_state(&servers, &state).unwrap();
        let direct_yaml = serde_yaml::to_string(&servers).unwrap();
        assert!(!direct_yaml.contains("client_chains:"));
        assert_eq!(direct_yaml.matches("allow-all-direct").count(), 2);
    }

    #[test]
    fn chain_proxy_reads_legacy_singular_field_and_writes_current_plural_field() {
        let (mut server, profile) = reality_server_and_profile(53453);
        let node = crate::chain_proxy::parse_share_uri(
            "socks5://alice:secret@proxy.example.com:1080#exit",
        )
        .unwrap();
        let mut state = ManagedState {
            schema_version: 2,
            profiles: vec![profile],
            chain_proxy: ChainProxyState::default(),
        };
        let id = node.id;
        state
            .chain_proxy
            .apply(ChainProxyChange::Add(node))
            .unwrap();
        state
            .chain_proxy
            .apply(ChainProxyChange::Select(id))
            .unwrap();
        state
            .chain_proxy
            .apply(ChainProxyChange::SetEnabled(true))
            .unwrap();
        apply_chain_proxy_rules(std::slice::from_mut(&mut server), &state);
        let current = serde_yaml::to_string(std::slice::from_ref(&server)).unwrap();
        assert!(current.contains("client_chains:"));
        let legacy = current.replace("client_chains:", "client_chain:");
        let parsed: Vec<ServerConfig> = serde_yaml::from_str(&legacy).unwrap();
        assert!(parsed[0].rules == server.rules);
    }

    #[test]
    fn enabled_chain_rejects_quic_inbounds_that_can_bypass_the_chain() {
        let (_, safe_profile) = reality_server_and_profile(53453);
        let node = crate::chain_proxy::parse_share_uri(
            "socks5://alice:secret@proxy.example.com:1080#exit",
        )
        .unwrap();
        let id = node.id;
        let mut state = ManagedState {
            schema_version: 2,
            profiles: vec![safe_profile.clone()],
            chain_proxy: ChainProxyState::default(),
        };
        state
            .chain_proxy
            .apply(ChainProxyChange::Add(node))
            .unwrap();
        state
            .chain_proxy
            .apply(ChainProxyChange::Select(id))
            .unwrap();
        state
            .chain_proxy
            .apply(ChainProxyChange::SetEnabled(true))
            .unwrap();
        ensure_chain_proxy_has_no_direct_udp_path(&state).unwrap();

        for credentials in [
            Credentials::Hysteria2 {
                password: "test-password".to_owned(),
                server_name: "hy2.example.com".to_owned(),
                alpn_protocols: vec!["h3".to_owned()],
            },
            Credentials::Tuic {
                user_id: Uuid::new_v4(),
                password: "test-password".to_owned(),
                server_name: "tuic.example.com".to_owned(),
                alpn_protocols: vec!["h3".to_owned()],
                zero_rtt_handshake: false,
            },
        ] {
            let mut unsafe_profile = safe_profile.clone();
            unsafe_profile.port += 1;
            unsafe_profile.credentials = credentials;
            let expected_name = unsafe_profile.config_file_name();
            state.profiles.push(unsafe_profile);
            let error = ensure_chain_proxy_has_no_direct_udp_path(&state)
                .unwrap_err()
                .to_string();
            assert!(error.contains("会绕过 client chain 并直连"));
            assert!(error.contains(&expected_name));
            state.profiles.pop();
        }

        state
            .chain_proxy
            .apply(ChainProxyChange::SetEnabled(false))
            .unwrap();
        let mut unsafe_profile = safe_profile;
        unsafe_profile.credentials = Credentials::Hysteria2 {
            password: "test-password".to_owned(),
            server_name: "hy2.example.com".to_owned(),
            alpn_protocols: vec!["h3".to_owned()],
        };
        state.profiles.push(unsafe_profile);
        ensure_chain_proxy_has_no_direct_udp_path(&state).unwrap();
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
    async fn shadowtls_v3_generates_nested_tcp_only_shadowsocks() {
        let dir = tempfile::tempdir().unwrap();
        let mut req = request(Protocol::Shadowsocks, dir.path().join("shadowtls.yaml"));
        req.server_name = "www.cloudflare.com".to_owned();
        req.options.shadowsocks_mode = ShadowsocksMode::ShadowTlsV3;
        req.options.shadowtls_handshake = Some("www.example.com:443".to_owned());
        let result = generate_inner(req, false).await.unwrap();
        let yaml = fs::read_to_string(result.config_path).unwrap();
        assert!(yaml.contains("shadowtls_targets:"));
        assert!(yaml.contains("type: shadowsocks"));
        assert!(yaml.contains("cipher: 2022-blake3-aes-256-gcm"));
        assert!(yaml.contains("address: www.example.com:443"));
        assert!(yaml.contains("udp_enabled: false"));
        let Credentials::Shadowsocks {
            cipher,
            password,
            udp_enabled,
            shadowtls: Some(shadowtls),
        } = result.credentials
        else {
            panic!("expected ShadowTLS Shadowsocks credentials");
        };
        assert!(cipher.is_2022());
        assert!(!password.is_empty());
        assert!(!udp_enabled);
        assert_eq!(shadowtls.server_name, "www.cloudflare.com");
        assert_eq!(shadowtls.handshake_address, "www.example.com:443");
        assert!(!shadowtls.password.is_empty());
    }

    #[test]
    fn shadowtls_rejects_legacy_cipher_and_invalid_handshake() {
        let mut req = request(Protocol::Shadowsocks, PathBuf::from("unused.yaml"));
        req.options.shadowsocks_mode = ShadowsocksMode::ShadowTlsV3;
        req.options.shadowsocks_cipher = ShadowsocksCipher::Aes256Gcm;
        assert!(validate_request(&req).is_err());
        req.options.shadowsocks_cipher = ShadowsocksCipher::Aes256Gcm2022;
        req.options.shadowtls_handshake = Some("not-a-host-port".to_owned());
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn legacy_shadowsocks_state_defaults_shadowtls_to_none() {
        let json = r#"{"schema_version":2,"profiles":[{"id":"00000000-0000-0000-0000-000000000000","name":"ss","port":8388,"credentials":{"Shadowsocks":{"cipher":"2022-blake3-aes-256-gcm","password":"key","udp_enabled":true}},"certificate_path":null,"certificate_key_path":null,"self_signed_certificate":false}]}"#;
        let state: ManagedState = serde_json::from_str(json).unwrap();
        let Credentials::Shadowsocks { shadowtls, .. } = &state.profiles[0].credentials else {
            panic!("expected Shadowsocks");
        };
        assert!(shadowtls.is_none());
    }

    #[tokio::test]
    async fn snell_v3_yaml_matches_fixed_shoes_schema() {
        let dir = tempfile::tempdir().unwrap();
        let mut request = request(Protocol::Snell, dir.path().join("snell.yaml"));
        request.port = 23_456;
        let result = generate_inner(request, false).await.unwrap();
        let yaml = fs::read_to_string(result.config_path).unwrap();
        assert!(yaml.contains("address: 0.0.0.0:23456"));
        assert!(yaml.contains("type: snell"));
        assert!(yaml.contains("cipher: chacha20-ietf-poly1305"));
        assert!(yaml.contains("password:"));
        assert!(yaml.contains("udp_enabled: true"));
        assert!(!yaml.contains("udp_num_sockets"));
        let Credentials::Snell {
            cipher,
            password,
            udp_enabled,
        } = result.credentials
        else {
            panic!("expected Snell credentials");
        };
        assert_eq!(cipher, SnellCipher::Chacha20IetfPoly1305);
        assert!(!password.is_empty());
        assert!(udp_enabled);

        let state = ManagedState {
            schema_version: 2,
            profiles: vec![result.profile],
            chain_proxy: ChainProxyState::default(),
        };
        let restored: ManagedState = serde_json::from_slice(&serde_json::to_vec(&state).unwrap())
            .expect("Snell managed state should round-trip");
        let restored = &restored.profiles[0];
        assert_eq!(restored.protocol(), Protocol::Snell);
        assert_eq!(restored.port, 23_456);
        let Credentials::Snell {
            cipher,
            password,
            udp_enabled,
        } = &restored.credentials
        else {
            panic!("expected restored Snell credentials");
        };
        assert_eq!(*cipher, SnellCipher::Chacha20IetfPoly1305);
        assert!(!password.is_empty());
        assert!(*udp_enabled);
    }

    #[test]
    fn snell_v3_accepts_only_the_three_product_ciphers() {
        for (input, expected) in [
            (ShadowsocksCipher::Aes128Gcm, SnellCipher::Aes128Gcm),
            (ShadowsocksCipher::Aes256Gcm, SnellCipher::Aes256Gcm),
            (
                ShadowsocksCipher::Chacha20IetfPoly1305,
                SnellCipher::Chacha20IetfPoly1305,
            ),
        ] {
            assert_eq!(SnellCipher::from_shadowsocks(input).unwrap(), expected);
        }
        let error = SnellCipher::from_shadowsocks(ShadowsocksCipher::Aes256Gcm2022)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Snell v3 不支持加密方式"));
        assert!(error.contains("只允许 aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305"));
    }

    #[test]
    fn snell_v3_preserves_each_explicit_cipher_and_password() {
        for (index, cipher) in [
            SnellCipher::Aes128Gcm,
            SnellCipher::Aes256Gcm,
            SnellCipher::Chacha20IetfPoly1305,
        ]
        .into_iter()
        .enumerate()
        {
            let mut request = request(Protocol::Snell, PathBuf::from("unused.yaml"));
            request.port = 31_000 + index as u16;
            request.options.snell_cipher = cipher;
            request.options.snell_password = Some("chosen-snell-password".to_owned());
            let (server, credentials, _, _) =
                generate_parts(&request, Path::new("."), Uuid::nil()).unwrap();
            let ServerProtocol::Snell {
                cipher: server_cipher,
                password: server_password,
                udp_enabled,
            } = server.protocol
            else {
                panic!("expected Snell server");
            };
            assert_eq!(server.address, format!("0.0.0.0:{}", request.port));
            assert_eq!(server_cipher, cipher.as_str());
            assert_eq!(server_password, "chosen-snell-password");
            assert!(udp_enabled);
            let Credentials::Snell {
                cipher: state_cipher,
                password: state_password,
                ..
            } = credentials
            else {
                panic!("expected Snell credentials");
            };
            assert_eq!(state_cipher, cipher);
            assert_eq!(state_password, "chosen-snell-password");
        }
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

    #[tokio::test]
    async fn new_tls_and_reality_presets_match_shoes_schema() {
        let dir = tempfile::tempdir().unwrap();
        let cases = [
            (
                Protocol::VlessTlsVision,
                "vless-tls.yaml",
                vec!["tls_targets:", "vision: true", "type: vless"],
            ),
            (
                Protocol::VlessWsTls,
                "vless-ws.yaml",
                vec!["tls_targets:", "type: websocket", "type: vless"],
            ),
            (
                Protocol::TrojanTls,
                "trojan-tls.yaml",
                vec!["tls_targets:", "type: trojan", "password:"],
            ),
            (
                Protocol::TrojanReality,
                "trojan-reality.yaml",
                vec!["reality_targets:", "type: trojan", "vision: false"],
            ),
            (
                Protocol::VmessWsTls,
                "vmess-ws.yaml",
                vec!["tls_targets:", "type: websocket", "type: vmess"],
            ),
        ];
        let mut profiles = Vec::new();

        for (protocol, file_name, markers) in cases {
            let mut request = request(protocol, dir.path().join(file_name));
            if protocol.uses_websocket() {
                request.options.websocket_path = Some("/verified-path".to_owned());
            }
            let result = generate_inner(request, false).await.unwrap();
            let yaml = fs::read_to_string(&result.config_path).unwrap();
            for marker in markers {
                assert!(
                    yaml.contains(marker),
                    "{protocol:?} missing {marker}:\n{yaml}"
                );
            }
            assert!(
                result.profile.self_signed_certificate
                    == protocol.requires_certificate(AnyTlsMode::Tls)
            );
            ensure_servers_match_state(
                &load_servers(&result.config_path).unwrap(),
                std::slice::from_ref(&result.profile),
            )
            .unwrap();
            profiles.push(result.profile);
        }

        let state = ManagedState {
            schema_version: 2,
            profiles,
            chain_proxy: ChainProxyState::default(),
        };
        let round_trip: ManagedState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(round_trip.schema_version, 2);
        assert_eq!(round_trip.profiles.len(), 5);
    }

    #[test]
    fn every_registered_protocol_supports_base_changes_and_credential_regeneration() {
        let directory = tempfile::tempdir().unwrap();

        for protocol in Protocol::all() {
            let profile_id = Uuid::new_v4();
            let mut request = request(protocol, directory.path().join("unused.yaml"));
            if protocol == Protocol::AnyTls {
                request.options.anytls_users = vec![generated_anytls_user("default")];
            }
            let generated = presets::generate(&request, directory.path(), profile_id).unwrap();
            let mut server = generated.server;
            let mut profile = ManagedProfile {
                id: profile_id,
                name: format!("{}-test", protocol.slug()),
                port: request.port,
                server_address: None,
                credentials: generated.credentials,
                certificate_path: generated.certificate_path,
                certificate_key_path: generated.certificate_key_path,
                self_signed_certificate: protocol.requires_certificate(request.options.anytls_mode),
            };
            let credentials_before = serde_json::to_vec(&profile.credentials).unwrap();

            apply_profile_change(
                &mut server,
                &mut profile,
                ProfileChange::RegenerateCredentials,
            )
            .unwrap();
            apply_profile_change(&mut server, &mut profile, ProfileChange::Port(1443)).unwrap();
            apply_profile_change(
                &mut server,
                &mut profile,
                ProfileChange::Name("changed-name".to_owned()),
            )
            .unwrap();
            apply_profile_change(
                &mut server,
                &mut profile,
                ProfileChange::ServerAddress(Some("203.0.113.20".to_owned())),
            )
            .unwrap();

            assert_ne!(
                serde_json::to_vec(&profile.credentials).unwrap(),
                credentials_before,
                "{protocol:?} credentials were not regenerated"
            );
            assert_eq!(profile.port, 1443);
            assert_eq!(profile.name, "changed-name");
            assert_eq!(profile.server_address.as_deref(), Some("203.0.113.20"));
            ensure_servers_match_state(&[server], &[profile]).unwrap();
        }
    }

    #[test]
    fn rejects_invalid_or_misplaced_websocket_paths() {
        for path in ["missing-leading-slash", "/bad?query", "/bad#fragment"] {
            let mut request = request(Protocol::VlessWsTls, PathBuf::from("unused.yaml"));
            request.options.websocket_path = Some(path.to_owned());
            assert!(validate_request(&request).is_err(), "accepted {path}");
        }

        let mut request = request(Protocol::Reality, PathBuf::from("unused.yaml"));
        request.options.websocket_path = Some("/not-applicable".to_owned());
        assert!(validate_request(&request)
            .unwrap_err()
            .to_string()
            .contains("仅适用于"));
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
    fn legacy_snapshot_materializes_one_real_mapping_file_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        let state = dir.path().join("ping-rust-state.json");
        let (server, profile) = reality_server_and_profile(53453);
        fs::write(&config, serde_yaml::to_string(&vec![server]).unwrap()).unwrap();
        fs::write(
            &state,
            serde_json::to_vec(&ManagedState {
                schema_version: 1,
                profiles: vec![profile],
                chain_proxy: ChainProxyState::default(),
            })
            .unwrap(),
        )
        .unwrap();

        assert!(prepare_managed_snapshot(dir.path()).unwrap());
        let profile_path = dir.path().join("profiles").join("VLESS-REALITY-53453.yaml");
        let profile_yaml = fs::read_to_string(&profile_path).unwrap();
        let parsed: ServerConfig = serde_yaml::from_str(&profile_yaml).unwrap();
        assert_eq!(parsed.address, "0.0.0.0:53453");
        assert!(!profile_yaml.trim_start().starts_with('-'));
        assert!(!prepare_managed_snapshot(dir.path()).unwrap());
        validate_managed_snapshot(&config, &state).unwrap();
    }

    #[test]
    fn profile_writer_renames_port_and_rejects_foreign_files() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = dir.path().join("profiles");
        let (first_server, first_profile) = reality_server_and_profile(53453);
        let first = profile_documents(
            std::slice::from_ref(&first_server),
            std::slice::from_ref(&first_profile),
        )
        .unwrap();
        let aggregate =
            aggregate_profile_documents(&first, std::slice::from_ref(&first_profile)).unwrap();
        let aggregate_servers: Vec<ServerConfig> = serde_yaml::from_str(&aggregate).unwrap();
        assert_eq!(aggregate_servers.len(), 1);
        assert_eq!(aggregate_servers[0].address, "0.0.0.0:53453");
        write_profile_documents(&profiles, &first).unwrap();
        assert!(profiles.join("VLESS-REALITY-53453.yaml").is_file());

        let (second_server, second_profile) = reality_server_and_profile(53454);
        let second = profile_documents(&[second_server], &[second_profile]).unwrap();
        write_profile_documents(&profiles, &second).unwrap();
        assert!(!profiles.join("VLESS-REALITY-53453.yaml").exists());
        assert!(profiles.join("VLESS-REALITY-53454.yaml").is_file());

        fs::write(profiles.join("notes.txt"), b"do not overwrite").unwrap();
        let error = write_profile_documents(&profiles, &second).unwrap_err();
        assert!(error.to_string().contains("非 ping-rust 文件"));
        assert_eq!(
            fs::read(profiles.join("notes.txt")).unwrap(),
            b"do not overwrite"
        );
        assert!(is_managed_profile_file_name("VLESS-REALITY-65535.yaml"));
        for name in [
            "VLESS-TLS-VISION-443.yaml",
            "VLESS-WS-TLS-8443.yaml",
            "TROJAN-TLS-9443.yaml",
            "TROJAN-REALITY-10443.yaml",
            "VMESS-WS-TLS-11443.yaml",
            "SOCKS5-1080.yaml",
        ] {
            assert!(is_managed_profile_file_name(name), "rejected {name}");
        }
        assert!(!is_managed_profile_file_name("VLESS-REALITY-053453.yaml"));
        assert!(!is_managed_profile_file_name("VLESS-REALITY-0.yaml"));
    }

    #[test]
    fn deletion_result_delays_credential_cleanup_until_finish() {
        let dir = tempfile::tempdir().unwrap();
        let certificate = dir.path().join("cert.pem");
        let certificate_key = dir.path().join("key.pem");
        fs::write(&certificate, b"certificate").unwrap();
        fs::write(&certificate_key, b"private-key").unwrap();
        let (_, mut profile) = reality_server_and_profile(53453);
        profile.self_signed_certificate = true;
        profile.certificate_path = Some(certificate.clone());
        profile.certificate_key_path = Some(certificate_key.clone());
        let result = DeletionResult {
            profile,
            remaining_profiles: 0,
            rollback: None,
            _lock: None,
        };

        assert!(certificate.is_file());
        assert!(certificate_key.is_file());
        let deleted = result.finish_with(|path| {
            if let Some(path) = path {
                fs::remove_file(path).unwrap();
            }
            Ok(())
        });
        assert!(deleted.self_signed_certificate);
        assert!(!certificate.exists());
        assert!(!certificate_key.exists());
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
        let profiles = dir.path().join("profiles");
        fs::write(&config, b"old-config").unwrap();
        fs::create_dir(&profiles).unwrap();
        fs::write(profiles.join("VLESS-REALITY-443.yaml"), b"old-profile").unwrap();

        let error = commit_managed_with_state_writer(
            &config,
            &state,
            &profiles,
            &[],
            &ManagedState::default(),
            |_, _| Err(anyhow::anyhow!("injected state write failure")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("已回滚"));
        assert_eq!(fs::read(&config).unwrap(), b"old-config");
        assert!(!state.exists());
        assert_eq!(
            fs::read(profiles.join("VLESS-REALITY-443.yaml")).unwrap(),
            b"old-profile"
        );
    }

    #[test]
    fn managed_activation_rollback_restores_exact_files_and_removes_new_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        let state = dir.path().join("state.json");
        let profiles = dir.path().join("profiles");
        let certificate = dir.path().join("new.pem");
        let certificate_key = dir.path().join("new-key.pem");
        fs::write(&config, b"new-config").unwrap();
        fs::write(&state, b"new-state").unwrap();
        fs::create_dir(&profiles).unwrap();
        fs::write(profiles.join("VLESS-REALITY-443.yaml"), b"new-profile").unwrap();
        fs::write(&certificate, b"certificate").unwrap();
        fs::write(&certificate_key, b"private-key").unwrap();

        ManagedRollback {
            config: Some(b"old-config\n".to_vec()),
            state: None,
            profiles: ProfileDirectorySnapshot {
                existed: true,
                files: BTreeMap::from([(
                    "VLESS-REALITY-8443.yaml".to_owned(),
                    b"old-profile\n".to_vec(),
                )]),
            },
            generated_certificate: Some(certificate.clone()),
            generated_certificate_key: Some(certificate_key.clone()),
        }
        .restore_to(&config, &state, &profiles)
        .unwrap();

        assert_eq!(fs::read(config).unwrap(), b"old-config\n");
        assert!(!state.exists());
        assert!(!profiles.join("VLESS-REALITY-443.yaml").exists());
        assert_eq!(
            fs::read(profiles.join("VLESS-REALITY-8443.yaml")).unwrap(),
            b"old-profile\n"
        );
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
    fn shadowtls_regenerate_rotates_both_secrets_and_keeps_routing_fields() {
        let mut req = request(Protocol::Shadowsocks, PathBuf::from("unused.yaml"));
        req.server_name = "www.cloudflare.com".to_owned();
        req.options.shadowsocks_mode = ShadowsocksMode::ShadowTlsV3;
        req.options.shadowtls_handshake = Some("www.example.com:443".to_owned());
        let (mut server, credentials, _, _) = generate_shadowsocks(&req);
        let mut profile = ManagedProfile {
            id: Uuid::new_v4(),
            name: "ss-shadowtls".to_owned(),
            port: req.port,
            server_address: None,
            credentials,
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };
        let Credentials::Shadowsocks {
            password: old_key,
            shadowtls: Some(old_shadowtls),
            ..
        } = &profile.credentials
        else {
            panic!("expected ShadowTLS credentials");
        };
        let old_key = old_key.clone();
        let old_password = old_shadowtls.password.clone();
        let old_sni = old_shadowtls.server_name.clone();
        let old_handshake = old_shadowtls.handshake_address.clone();
        apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::RegenerateCredentials,
        )
        .unwrap();
        let Credentials::Shadowsocks {
            password,
            shadowtls: Some(shadowtls),
            ..
        } = &profile.credentials
        else {
            panic!("expected ShadowTLS credentials");
        };
        assert_ne!(password, &old_key);
        assert_ne!(shadowtls.password, old_password);
        assert_eq!(shadowtls.server_name, old_sni);
        assert_eq!(shadowtls.handshake_address, old_handshake);
        ensure_servers_match_state(&[server], &[profile]).unwrap();
    }

    #[test]
    fn snell_password_cipher_and_regeneration_keep_server_and_state_aligned() {
        let request = request(Protocol::Snell, PathBuf::from("unused.yaml"));
        let (mut server, credentials, _, _) =
            generate_parts(&request, Path::new("."), Uuid::nil()).unwrap();
        let mut profile = ManagedProfile {
            id: Uuid::new_v4(),
            name: "snell-main".to_owned(),
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
            ProfileChange::SnellCipher(SnellCipher::Aes128Gcm),
        )
        .unwrap();
        apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::Password("chosen-secret".to_owned()),
        )
        .unwrap();
        apply_profile_change(&mut server, &mut profile, ProfileChange::UdpEnabled(false)).unwrap();
        let before_regenerate = match &profile.credentials {
            Credentials::Snell {
                cipher, password, ..
            } => {
                assert_eq!(*cipher, SnellCipher::Aes128Gcm);
                assert_eq!(password, "chosen-secret");
                password.clone()
            }
            _ => unreachable!(),
        };
        apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::RegenerateCredentials,
        )
        .unwrap();
        let Credentials::Snell {
            cipher,
            password,
            udp_enabled,
        } = &profile.credentials
        else {
            unreachable!()
        };
        assert_eq!(*cipher, SnellCipher::Aes128Gcm);
        assert_ne!(password, &before_regenerate);
        assert!(!*udp_enabled);
        let ServerProtocol::Snell {
            cipher: server_cipher,
            password: server_password,
            udp_enabled: server_udp,
        } = &server.protocol
        else {
            unreachable!()
        };
        assert_eq!(server_cipher, cipher.as_str());
        assert_eq!(server_password, password);
        assert_eq!(server_udp, udp_enabled);
        ensure_servers_match_state(
            std::slice::from_ref(&server),
            std::slice::from_ref(&profile),
        )
        .unwrap();
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

    #[test]
    fn socks5_generation_round_trip_and_edits_preserve_exact_auth_and_udp_state() {
        let mut request = request(Protocol::Socks5, PathBuf::from("unused.yaml"));
        request.port = 10_880;
        request.options.socks5_username = Some("alice".to_owned());
        request.options.socks5_password = Some("chosen-secret".to_owned());
        request.options.udp_enabled = false;
        let (mut server, credentials, _, _) =
            generate_parts(&request, Path::new("."), Uuid::nil()).unwrap();
        let yaml = serde_yaml::to_string(&vec![server.clone()]).unwrap();
        assert!(yaml.contains("address: 0.0.0.0:10880"));
        assert!(yaml.contains("type: socks"));
        assert!(yaml.contains("username: alice"));
        assert!(yaml.contains("password: chosen-secret"));
        assert!(yaml.contains("udp_enabled: false"));

        let mut profile = ManagedProfile {
            id: Uuid::new_v4(),
            name: "socks-main".to_owned(),
            port: request.port,
            server_address: Some("203.0.113.20".to_owned()),
            credentials,
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };
        apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::Socks5Username("bob".to_owned()),
        )
        .unwrap();
        apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::Password("new-secret".to_owned()),
        )
        .unwrap();
        apply_profile_change(&mut server, &mut profile, ProfileChange::Port(20_880)).unwrap();
        apply_profile_change(&mut server, &mut profile, ProfileChange::UdpEnabled(true)).unwrap();
        apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::Socks5Authentication(false),
        )
        .unwrap();
        let no_auth_yaml = serde_yaml::to_string(&vec![server.clone()]).unwrap();
        assert!(!no_auth_yaml.contains("username:"));
        assert!(!no_auth_yaml.contains("password:"));
        assert!(no_auth_yaml.contains("udp_enabled: true"));
        assert!(matches!(
            profile.credentials,
            Credentials::Socks5 {
                username: None,
                password: None,
                udp_enabled: true
            }
        ));

        apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::Socks5Authentication(true),
        )
        .unwrap();
        let Credentials::Socks5 {
            username,
            password,
            udp_enabled,
        } = &profile.credentials
        else {
            unreachable!()
        };
        assert!(username
            .as_deref()
            .is_some_and(is_generated_socks5_username));
        assert!(password.as_ref().is_some_and(|value| value.len() >= 24));
        assert!(*udp_enabled);
        ensure_servers_match_state(&[server], &[profile.clone()]).unwrap();
        let restored: ManagedProfile =
            serde_json::from_slice(&serde_json::to_vec(&profile).unwrap()).unwrap();
        assert_eq!(restored.port, 20_880);
        assert_eq!(
            serde_json::to_vec(&restored.credentials).unwrap(),
            serde_json::to_vec(&profile.credentials).unwrap()
        );
    }

    #[test]
    fn socks5_defaults_to_authenticated_udp_and_no_auth_is_explicit() {
        let default_request = request(Protocol::Socks5, PathBuf::from("unused.yaml"));
        let (authenticated, credentials, _, _) =
            generate_parts(&default_request, Path::new("."), Uuid::nil()).unwrap();
        let Credentials::Socks5 {
            username,
            password,
            udp_enabled,
        } = credentials
        else {
            unreachable!()
        };
        assert!(username
            .as_deref()
            .is_some_and(is_generated_socks5_username));
        assert!(password.is_some());
        assert!(udp_enabled);
        let authenticated = serde_yaml::to_string(&vec![authenticated]).unwrap();
        assert!(!authenticated.contains("username: default"));
        assert!(authenticated.contains("udp_enabled: true"));

        let mut request = request(Protocol::Socks5, PathBuf::from("unused.yaml"));
        request.options.socks5_no_auth = true;
        let (anonymous, credentials, _, _) =
            generate_parts(&request, Path::new("."), Uuid::nil()).unwrap();
        assert!(matches!(
            credentials,
            Credentials::Socks5 {
                username: None,
                password: None,
                udp_enabled: true
            }
        ));
        let anonymous = serde_yaml::to_string(&vec![anonymous]).unwrap();
        assert!(!anonymous.contains("username:"));
        assert!(!anonymous.contains("password:"));
    }

    #[test]
    fn socks5_regenerate_rotates_username_and_password() {
        let mut request = request(Protocol::Socks5, PathBuf::from("unused.yaml"));
        request.options.socks5_username = Some("legacy-user".to_owned());
        request.options.socks5_password = Some("legacy-password".to_owned());
        let (mut server, credentials, _, _) =
            generate_parts(&request, Path::new("."), Uuid::nil()).unwrap();
        let mut profile = ManagedProfile {
            id: Uuid::new_v4(),
            name: "socks-main".to_owned(),
            port: request.port,
            server_address: Some("203.0.113.20".to_owned()),
            credentials,
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };

        apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::RegenerateCredentials,
        )
        .unwrap();

        let Credentials::Socks5 {
            username, password, ..
        } = &profile.credentials
        else {
            unreachable!()
        };
        assert!(username
            .as_deref()
            .is_some_and(is_generated_socks5_username));
        assert_ne!(username.as_deref(), Some("legacy-user"));
        assert!(password
            .as_deref()
            .is_some_and(|value| value != "legacy-password"));
        ensure_servers_match_state(&[server], &[profile]).unwrap();
    }

    #[test]
    fn existing_default_username_is_not_migrated_by_unrelated_edits() {
        let mut request = request(Protocol::Socks5, PathBuf::from("unused.yaml"));
        request.options.socks5_username = Some("default".to_owned());
        request.options.socks5_password = Some("existing-secret".to_owned());
        let (mut server, credentials, _, _) =
            generate_parts(&request, Path::new("."), Uuid::nil()).unwrap();
        let mut profile = ManagedProfile {
            id: Uuid::new_v4(),
            name: "legacy-socks".to_owned(),
            port: request.port,
            server_address: None,
            credentials,
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };

        apply_profile_change(&mut server, &mut profile, ProfileChange::Port(10_880)).unwrap();

        let Credentials::Socks5 { username, .. } = &profile.credentials else {
            unreachable!()
        };
        assert_eq!(username.as_deref(), Some("default"));
        ensure_servers_match_state(&[server], &[profile]).unwrap();
    }
}
