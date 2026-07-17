use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::ValueEnum;
use rand::RngCore;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::utils;

pub const DEFAULT_SNI: &str = "www.cloudflare.com";

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Protocol {
    Reality,
    Hysteria2,
    Tuic,
}

pub struct GenerationRequest {
    pub name: Option<String>,
    pub protocol: Protocol,
    pub port: u16,
    pub output: PathBuf,
    pub server_name: String,
    pub reality_dest: Option<String>,
    pub certificate: Option<PathBuf>,
    pub certificate_key: Option<PathBuf>,
}

pub struct GenerationResult {
    pub profile_id: Uuid,
    pub config_path: PathBuf,
    pub certificate_path: Option<PathBuf>,
    pub certificate_key_path: Option<PathBuf>,
    pub credentials: Credentials,
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
    },
    Tuic {
        user_id: Uuid,
        password: String,
        server_name: String,
    },
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
    pub credentials: Credentials,
    pub certificate_path: Option<PathBuf>,
    pub certificate_key_path: Option<PathBuf>,
    pub self_signed_certificate: bool,
}

impl ManagedProfile {
    pub fn protocol_name(&self) -> &'static str {
        match &self.credentials {
            Credentials::Reality { .. } => "VLESS-Reality-Vision",
            Credentials::Hysteria2 { .. } => "Hysteria2",
            Credentials::Tuic { .. } => "TUIC v5",
        }
    }

    pub fn server_name(&self) -> &str {
        match &self.credentials {
            Credentials::Reality { server_name, .. }
            | Credentials::Hysteria2 { server_name, .. }
            | Credentials::Tuic { server_name, .. } => server_name,
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
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ServerProtocol {
    Tls {
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
    Vless { user_id: Uuid, udp_enabled: bool },
}

pub async fn generate(request: GenerationRequest) -> Result<GenerationResult> {
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
    }
    let _lock = managed
        .then(|| utils::exclusive_lock(Path::new(utils::LOCK_FILE)))
        .transpose()?;
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
    let self_signed = request.certificate.is_none()
        && matches!(request.protocol, Protocol::Hysteria2 | Protocol::Tuic);

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
                            udp_enabled: true,
                        },
                    ),
                    Credentials::Hysteria2 {
                        password,
                        server_name: request.server_name.clone(),
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
                            zero_rtt_handshake: false,
                        },
                    ),
                    Credentials::Tuic {
                        user_id,
                        password,
                        server_name: request.server_name.clone(),
                    },
                    Some(cert),
                    Some(key),
                )
            }
        }
    };

    let profile = ManagedProfile {
        id: profile_id,
        name: request
            .name
            .clone()
            .unwrap_or_else(|| default_profile_name(request.protocol, profile_id)),
        port: request.port,
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
    if servers.len() != state.profiles.len() {
        bail!("配置文件与管理状态不一致；请先备份并修复，ping-rust 不会覆盖现有配置");
    }
    servers.push(server);
    state.profiles.push(profile);

    let yaml = serde_yaml::to_string(&servers).context("序列化 shoes YAML 失败")?;
    validate_yaml(&yaml)?;
    if managed {
        validate_candidate_with_shoes(&yaml, parent).await?;
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
    })
}

fn default_profile_name(protocol: Protocol, id: Uuid) -> String {
    let protocol = match protocol {
        Protocol::Reality => "reality",
        Protocol::Hysteria2 => "hysteria2",
        Protocol::Tuic => "tuic",
    };
    format!("{protocol}-{}", &id.simple().to_string()[..8])
}

fn load_servers(path: &Path) -> Result<Vec<ServerConfig>> {
    let yaml =
        fs::read_to_string(path).with_context(|| format!("读取配置 {} 失败", path.display()))?;
    serde_yaml::from_str(&yaml).context("现有 shoes 配置不是 ping-rust 可管理的格式")
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
    if servers.len() != state.profiles.len() {
        bail!("配置文件与管理状态不一致，已拒绝删除");
    }
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
    let short_id = random_hex(8);
    let user_id = Uuid::new_v4();
    let destination = request
        .reality_dest
        .clone()
        .unwrap_or_else(|| format!("{}:443", request.server_name));
    let target = RealityTarget {
        private_key: keypair.private_key.clone(),
        short_ids: vec![short_id.clone()],
        dest: destination,
        max_time_diff: 60_000,
        vision: true,
        protocol: InnerProtocol::Vless {
            user_id,
            udp_enabled: true,
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

fn quic_server(port: u16, cert: &str, key: &str, protocol: ServerProtocol) -> ServerConfig {
    ServerConfig {
        address: format!("0.0.0.0:{port}"),
        transport: Some("quic".to_owned()),
        quic_settings: Some(QuicSettings {
            cert: cert.to_owned(),
            key: key.to_owned(),
            alpn_protocols: vec!["h3".to_owned()],
        }),
        protocol,
        rules: vec!["allow-all-direct".to_owned()],
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
    if request.server_name.trim().is_empty()
        || request.server_name.len() > 253
        || request.server_name.contains(char::is_whitespace)
        || request.server_name.contains('/')
        || request.server_name.contains([':', '\\'])
    {
        bail!("SNI/服务器名称无效");
    }
    if let Some(destination) = &request.reality_dest {
        validate_host_port(destination)?;
    }
    if matches!(request.protocol, Protocol::Reality)
        && (request.certificate.is_some() || request.certificate_key.is_some())
    {
        bail!("Reality 不使用 --cert/--key；请改用 --server-name 和 --dest");
    }
    if !matches!(request.protocol, Protocol::Reality) && request.reality_dest.is_some() {
        bail!("--dest 仅适用于 Reality");
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
    if servers.len() != state.profiles.len() {
        bail!(
            "备份中的配置条目数 {} 与管理状态条目数 {} 不一致",
            servers.len(),
            state.profiles.len()
        );
    }
    for (server, profile) in servers.iter().zip(&state.profiles) {
        let expected = format!("0.0.0.0:{}", profile.port);
        if server.address != expected {
            bail!(
                "备份配置 {} 的监听地址 {} 与管理状态端口不一致",
                profile.id,
                server.address
            );
        }
    }
    Ok(())
}

pub async fn validate_with_shoes(config_path: &Path) -> Result<()> {
    validate_with_binary(Path::new(utils::SHOES_BIN), config_path).await
}

async fn validate_with_binary(binary: &Path, config_path: &Path) -> Result<()> {
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
            server_name: "www.cloudflare.com".to_owned(),
            reality_dest: None,
            certificate: None,
            certificate_key: None,
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
        let result = generate(request(Protocol::Reality, dir.path().join("reality.yaml")))
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
        let result = generate(request(Protocol::Hysteria2, dir.path().join("hy2.yaml")))
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
        let result = generate(request(Protocol::Tuic, dir.path().join("tuic.yaml")))
            .await
            .unwrap();
        let yaml = std::fs::read_to_string(result.config_path).unwrap();
        assert!(yaml.contains("type: tuic"));
        assert!(yaml.contains("uuid:"));
        assert!(yaml.contains("zero_rtt_handshake: false"));
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
