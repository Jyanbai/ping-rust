use std::{
    collections::BTreeMap,
    net::{TcpListener, TcpStream, ToSocketAddrs},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::utils;

const DEFAULT_PROXY_PROBE_URL: &str = "https://www.gstatic.com/generate_204";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainProxyState {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_node: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<ChainNode>,
}

impl ChainProxyState {
    pub fn validate(&self) -> Result<()> {
        if let Some(id) = self.active_node {
            self.require_node(id)?;
        }
        if self.enabled && self.active().is_none() {
            bail!("链式代理已标记启用，但当前节点不存在");
        }
        for (index, node) in self.nodes.iter().enumerate() {
            validate_node_name(&node.name)?;
            if self.nodes[..index].iter().any(|existing| {
                existing.id == node.id || existing.name.eq_ignore_ascii_case(&node.name)
            }) {
                bail!("链式代理状态包含重复节点：{}", node.name);
            }
        }
        Ok(())
    }

    pub fn active(&self) -> Option<&ChainNode> {
        self.active_node
            .and_then(|id| self.nodes.iter().find(|node| node.id == id))
    }

    pub fn effective(&self) -> Option<&ChainNode> {
        self.enabled.then(|| self.active()).flatten()
    }

    pub fn apply(&mut self, change: ChainProxyChange) -> Result<()> {
        match change {
            ChainProxyChange::Add(node) => {
                validate_node_name(&node.name)?;
                if self
                    .nodes
                    .iter()
                    .any(|existing| existing.name.eq_ignore_ascii_case(&node.name))
                {
                    bail!("链式节点名称已存在：{}", node.name);
                }
                if self.nodes.iter().any(|existing| existing.id == node.id) {
                    bail!("链式节点 ID 已存在：{}", node.id);
                }
                let id = node.id;
                self.nodes.push(node);
                if self.active_node.is_none() {
                    self.active_node = Some(id);
                }
            }
            ChainProxyChange::Select(id) => {
                self.require_node(id)?;
                self.active_node = Some(id);
            }
            ChainProxyChange::SetEnabled(enabled) => {
                if enabled && self.active().is_none() {
                    bail!("请先添加并选择一个链式代理节点");
                }
                self.enabled = enabled;
            }
            ChainProxyChange::Delete(id) => {
                self.require_node(id)?;
                self.nodes.retain(|node| node.id != id);
                if self.active_node == Some(id) {
                    self.active_node = None;
                    self.enabled = false;
                }
            }
        }
        self.validate()?;
        Ok(())
    }

    fn require_node(&self, id: Uuid) -> Result<()> {
        if self.nodes.iter().any(|node| node.id == id) {
            Ok(())
        } else {
            bail!("未找到链式代理节点 {id}")
        }
    }
}

#[derive(Clone, Debug)]
pub enum ChainProxyChange {
    Add(ChainNode),
    Select(Uuid),
    SetEnabled(bool),
    Delete(Uuid),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainNode {
    pub id: Uuid,
    pub name: String,
    pub client: ShoesClientConfig,
}

impl ChainNode {
    pub fn with_name(mut self, name: String) -> Result<Self> {
        validate_node_name(&name)?;
        self.name = name;
        Ok(self)
    }

    pub fn protocol_name(&self) -> &'static str {
        self.client.protocol.protocol_name()
    }

    pub fn address(&self) -> &str {
        &self.client.address
    }

    pub fn supports_udp_over_tcp(&self) -> bool {
        self.client.protocol.supports_udp_over_tcp()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShoesClientConfig {
    pub address: String,
    pub protocol: ShoesClientProtocol,
}

#[derive(Serialize)]
struct ProbeServer<'a> {
    address: String,
    protocol: ProbeSocksProtocol,
    rules: Vec<ProbeRule<'a>>,
}

#[derive(Serialize)]
struct ProbeSocksProtocol {
    #[serde(rename = "type")]
    kind: &'static str,
    udp_enabled: bool,
}

#[derive(Serialize)]
struct ProbeRule<'a> {
    masks: &'static str,
    action: &'static str,
    client_chains: &'a ShoesClientConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ShoesClientProtocol {
    Http {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    Socks {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    Shadowsocks {
        cipher: String,
        password: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },
    Vless {
        user_id: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },
    Trojan {
        password: String,
    },
    Reality {
        public_key: String,
        short_id: String,
        sni_hostname: String,
        #[serde(default, skip_serializing_if = "is_false")]
        vision: bool,
        protocol: Box<ShoesClientProtocol>,
    },
    Tls {
        #[serde(default = "default_true")]
        verify: bool,
        sni_hostname: String,
        #[serde(default, skip_serializing_if = "is_false")]
        vision: bool,
        protocol: Box<ShoesClientProtocol>,
    },
    Websocket {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        matching_path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        matching_headers: Option<BTreeMap<String, String>>,
        protocol: Box<ShoesClientProtocol>,
    },
}

impl ShoesClientProtocol {
    fn protocol_name(&self) -> &'static str {
        match self {
            Self::Http { .. } => "HTTP",
            Self::Socks { .. } => "SOCKS5",
            Self::Shadowsocks { .. } => "Shadowsocks",
            Self::Vless { .. } => "VLESS",
            Self::Trojan { .. } => "Trojan",
            Self::Reality { protocol, .. } => match protocol.as_ref() {
                Self::Vless { .. } => "VLESS-Reality",
                _ => "Reality",
            },
            Self::Tls { protocol, .. } => match protocol.as_ref() {
                Self::Websocket { protocol, .. } => match protocol.as_ref() {
                    Self::Vless { .. } => "VLESS-WS-TLS",
                    Self::Trojan { .. } => "Trojan-WS-TLS",
                    _ => "WebSocket-TLS",
                },
                Self::Vless { .. } => "VLESS-TLS",
                Self::Trojan { .. } => "Trojan-TLS",
                Self::Http { .. } => "HTTPS",
                _ => "TLS",
            },
            Self::Websocket { protocol, .. } => protocol.protocol_name(),
        }
    }

    fn supports_udp_over_tcp(&self) -> bool {
        match self {
            Self::Shadowsocks { udp_enabled, .. } | Self::Vless { udp_enabled, .. } => *udp_enabled,
            // shoes 0.2.8 still leaves Trojan UDP client handling unimplemented.
            Self::Trojan { .. } => false,
            Self::Reality { protocol, .. }
            | Self::Tls { protocol, .. }
            | Self::Websocket { protocol, .. } => protocol.supports_udp_over_tcp(),
            Self::Http { .. } | Self::Socks { .. } => false,
        }
    }
}

fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub fn parse_share_uri(input: &str) -> Result<ChainNode> {
    let input = input.trim();
    if input.is_empty() || input.len() > 8192 || input.chars().any(char::is_control) {
        bail!("分享链接不能为空、包含控制字符或超过 8192 字节");
    }
    let scheme = input
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .context("分享链接必须包含 ://")?;
    match scheme.as_str() {
        "hy2" | "hysteria2" => bail!("当前 shoes 内核不支持将 Hysteria2 作为链式代理出口"),
        "tuic" => bail!("当前 shoes 内核不支持将 TUIC 作为链式代理出口"),
        "wireguard" | "wg" | "warp" => {
            bail!("当前 shoes 内核不支持将 WireGuard/WARP 作为链式代理出口")
        }
        "socks" | "socks5" => parse_url_proxy(input, ProxyKind::Socks),
        "http" => parse_url_proxy(input, ProxyKind::Http),
        "https" => parse_url_proxy(input, ProxyKind::Https),
        "ss" => parse_shadowsocks(input),
        "vless" => parse_vless(input),
        "trojan" => parse_trojan(input),
        "vmess" | "anytls" => bail!(
            "当前版本尚未启用 {} 分享链接导入；未验证的格式不会被近似转换",
            scheme
        ),
        _ => bail!("不支持的链式代理分享链接协议：{scheme}"),
    }
}

enum ProxyKind {
    Socks,
    Http,
    Https,
}

fn parse_url_proxy(input: &str, kind: ProxyKind) -> Result<ChainNode> {
    let url = Url::parse(input).context("代理分享链接格式无效")?;
    url_address(&url)?;
    let default_sni = url_host(&url)?.to_owned();
    let username = optional_decoded(url.username())?;
    let password = url.password().map(decode_component).transpose()?;
    let base = match kind {
        ProxyKind::Socks => ShoesClientProtocol::Socks { username, password },
        ProxyKind::Http | ProxyKind::Https => ShoesClientProtocol::Http { username, password },
    };
    let protocol = if matches!(kind, ProxyKind::Https) {
        ShoesClientProtocol::Tls {
            verify: !query_flag(&url, &["insecure", "allowinsecure"]),
            sni_hostname: query_value(&url, "sni").unwrap_or(default_sni),
            vision: false,
            protocol: Box::new(base),
        }
    } else {
        base
    };
    build_node(&url, protocol)
}

fn parse_shadowsocks(input: &str) -> Result<ChainNode> {
    let without_scheme = input
        .strip_prefix("ss://")
        .context("Shadowsocks 链接格式无效")?;
    let payload = without_scheme
        .split('#')
        .next()
        .unwrap_or(without_scheme)
        .split('?')
        .next()
        .unwrap_or(without_scheme);
    if !payload.contains('@') {
        let decoded = decode_base64_text(payload).context("Shadowsocks Base64 主体无效")?;
        let suffix = &without_scheme[payload.len()..];
        return parse_shadowsocks(&format!("ss://{decoded}{suffix}"));
    }

    let url = Url::parse(input).context("Shadowsocks 分享链接格式无效")?;
    if url.query_pairs().any(|(key, _)| key == "plugin") {
        bail!("当前 shoes 内核不支持 Shadowsocks SIP003 插件链式出口");
    }
    let raw_user = decode_component(url.username())?;
    let (cipher, password) = if let Some(password) = url.password() {
        (raw_user, decode_component(password)?)
    } else {
        let decoded = decode_base64_text(&raw_user).context("Shadowsocks 用户信息 Base64 无效")?;
        decoded
            .split_once(':')
            .map(|(cipher, password)| (cipher.to_owned(), password.to_owned()))
            .context("Shadowsocks 用户信息必须包含 加密方式:密码")?
    };
    validate_shadowsocks(&cipher, &password)?;
    let protocol = ShoesClientProtocol::Shadowsocks {
        cipher,
        password,
        udp_enabled: true,
    };
    build_node(&url, protocol)
}

fn parse_vless(input: &str) -> Result<ChainNode> {
    let url = Url::parse(input).context("VLESS 分享链接格式无效")?;
    let user_id = decode_component(url.username())?;
    Uuid::parse_str(&user_id).context("VLESS 用户 ID 必须是有效 UUID")?;
    let query = query_map(&url);
    if query.get("encryption").is_some_and(|value| value != "none") {
        bail!("VLESS encryption 只支持 none");
    }
    let transport = query.get("type").map(String::as_str).unwrap_or("tcp");
    let security = query.get("security").map(String::as_str).unwrap_or("none");
    let flow = query.get("flow").map(String::as_str).unwrap_or("");
    let vision = match flow {
        "" => false,
        "xtls-rprx-vision" => true,
        other => bail!("不支持的 VLESS flow：{other}"),
    };
    let mut protocol = ShoesClientProtocol::Vless {
        user_id,
        udp_enabled: true,
    };
    protocol = wrap_transport(protocol, transport, &query)?;
    protocol = match security {
        "none" => {
            if vision {
                bail!("VLESS Vision 必须搭配 TLS 或 Reality");
            }
            protocol
        }
        "tls" => {
            if vision && transport != "tcp" {
                bail!("VLESS Vision 只能搭配 TCP 传输");
            }
            ShoesClientProtocol::Tls {
                verify: !query_flag_map(&query, &["insecure", "allowinsecure"]),
                sni_hostname: required_sni(&url, &query)?,
                vision,
                protocol: Box::new(protocol),
            }
        }
        "reality" => {
            if transport != "tcp" {
                bail!("Reality 链式节点当前只支持 TCP 传输");
            }
            let public_key = query
                .get("pbk")
                .filter(|value| !value.is_empty())
                .cloned()
                .context("Reality 分享链接缺少 pbk 公钥")?;
            validate_reality_public_key(&public_key)?;
            let short_id = query.get("sid").cloned().unwrap_or_default();
            validate_reality_short_id(&short_id)?;
            ShoesClientProtocol::Reality {
                public_key,
                short_id,
                sni_hostname: required_sni(&url, &query)?,
                vision,
                protocol: Box::new(protocol),
            }
        }
        other => bail!("不支持的 VLESS security：{other}"),
    };
    build_node(&url, protocol)
}

fn parse_trojan(input: &str) -> Result<ChainNode> {
    let url = Url::parse(input).context("Trojan 分享链接格式无效")?;
    let password = decode_component(url.username())?;
    if password.is_empty() {
        bail!("Trojan 密码不能为空");
    }
    let query = query_map(&url);
    if query
        .get("security")
        .is_some_and(|value| !matches!(value.as_str(), "tls" | "reality"))
    {
        bail!("Trojan 链式节点只支持 TLS；不能把 security=none 近似转换为 TLS");
    }
    if query
        .get("security")
        .is_some_and(|value| value == "reality")
    {
        bail!("当前版本尚未验证 Trojan-Reality 分享链接导入");
    }
    let transport = query.get("type").map(String::as_str).unwrap_or("tcp");
    let protocol = wrap_transport(ShoesClientProtocol::Trojan { password }, transport, &query)?;
    let protocol = ShoesClientProtocol::Tls {
        verify: !query_flag_map(&query, &["insecure", "allowinsecure"]),
        sni_hostname: required_sni(&url, &query)?,
        vision: false,
        protocol: Box::new(protocol),
    };
    build_node(&url, protocol)
}

fn wrap_transport(
    protocol: ShoesClientProtocol,
    transport: &str,
    query: &BTreeMap<String, String>,
) -> Result<ShoesClientProtocol> {
    match transport {
        "tcp" => Ok(protocol),
        "ws" | "websocket" => {
            let path = query.get("path").cloned().unwrap_or_else(|| "/".to_owned());
            if !path.starts_with('/')
                || path.contains(['?', '#'])
                || path.chars().any(char::is_control)
            {
                bail!("WebSocket 路径必须以 / 开头，且不能包含 ?、# 或控制字符");
            }
            let headers = query
                .get("host")
                .filter(|host| !host.is_empty())
                .map(|host| BTreeMap::from([("Host".to_owned(), host.clone())]));
            Ok(ShoesClientProtocol::Websocket {
                matching_path: Some(path),
                matching_headers: headers,
                protocol: Box::new(protocol),
            })
        }
        other => bail!("当前链式代理不支持传输类型：{other}"),
    }
}

fn build_node(url: &Url, protocol: ShoesClientProtocol) -> Result<ChainNode> {
    let address = url_address(url)?;
    let name = url
        .fragment()
        .map(decode_component)
        .transpose()?
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}-{}",
                protocol.protocol_name().to_ascii_lowercase(),
                address
            )
        });
    validate_node_name(&name)?;
    Ok(ChainNode {
        id: Uuid::new_v4(),
        name,
        client: ShoesClientConfig { address, protocol },
    })
}

fn url_address(url: &Url) -> Result<String> {
    let host = url_host(url)?;
    let port = url
        .port_or_known_default()
        .context("分享链接缺少服务器端口")?;
    if port == 0 {
        bail!("分享链接端口必须在 1..=65535 范围内");
    }
    Ok(if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

fn url_host(url: &Url) -> Result<&str> {
    url.host_str().context("分享链接缺少服务器地址")
}

fn query_map(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(key, value)| (key.to_ascii_lowercase(), value.into_owned()))
        .collect()
}

fn query_value(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.into_owned())
}

fn query_flag(url: &Url, keys: &[&str]) -> bool {
    query_flag_map(&query_map(url), keys)
}

fn query_flag_map(query: &BTreeMap<String, String>, keys: &[&str]) -> bool {
    keys.iter().any(|key| {
        query
            .get(*key)
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"))
    })
}

fn required_sni(url: &Url, query: &BTreeMap<String, String>) -> Result<String> {
    if let Some(server_name) = query
        .get("sni")
        .or_else(|| query.get("servername"))
        .filter(|value| !value.is_empty())
    {
        return Ok(server_name.clone());
    }
    url_host(url).map(ToOwned::to_owned)
}

fn validate_reality_public_key(public_key: &str) -> Result<()> {
    let decoded = URL_SAFE_NO_PAD
        .decode(public_key)
        .context("Reality pbk 必须是不带填充的 Base64URL")?;
    if decoded.len() != 32 {
        bail!("Reality pbk 解码后必须为 32 字节");
    }
    Ok(())
}

fn validate_reality_short_id(short_id: &str) -> Result<()> {
    if short_id.len() > 16
        || !short_id
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        bail!("Reality sid 必须是 0..=16 个十六进制字符");
    }
    Ok(())
}

fn optional_decoded(value: &str) -> Result<Option<String>> {
    if value.is_empty() {
        Ok(None)
    } else {
        decode_component(value).map(Some)
    }
}

fn decode_component(value: &str) -> Result<String> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .context("分享链接包含无效的 UTF-8 转义")
}

fn decode_base64_text(value: &str) -> Result<String> {
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(value) {
            return String::from_utf8(bytes).context("Base64 解码结果不是 UTF-8");
        }
    }
    bail!("Base64 编码无效")
}

fn validate_shadowsocks(cipher: &str, password: &str) -> Result<()> {
    let expected_key_len = match cipher {
        "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305" | "chacha20-poly1305" => None,
        "2022-blake3-aes-128-gcm" => Some(16),
        "2022-blake3-aes-256-gcm"
        | "2022-blake3-chacha20-ietf-poly1305"
        | "2022-blake3-chacha20-poly1305" => Some(32),
        _ => bail!("当前 shoes 内核不支持 Shadowsocks 加密方式：{cipher}"),
    };
    if password.is_empty() || password.chars().any(char::is_control) {
        bail!("Shadowsocks 密码不能为空或包含控制字符");
    }
    if let Some(expected) = expected_key_len {
        let decoded = STANDARD
            .decode(password)
            .context("Shadowsocks 2022 密码必须使用标准 Base64 编码")?;
        if decoded.len() != expected {
            bail!("{cipher} 密码解码后必须为 {expected} 字节");
        }
    }
    Ok(())
}

fn validate_node_name(name: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
        bail!("链式节点名称必须为 1..=64 个非控制字符");
    }
    Ok(())
}

fn probe_config(node: &ChainNode, port: u16) -> Result<String> {
    let servers = [ProbeServer {
        address: format!("127.0.0.1:{port}"),
        protocol: ProbeSocksProtocol {
            kind: "socks",
            udp_enabled: false,
        },
        rules: vec![ProbeRule {
            masks: "0.0.0.0/0",
            action: "allow",
            client_chains: &node.client,
        }],
    }];
    serde_yaml::to_string(&servers).context("生成链式节点测试配置失败")
}

fn reserve_loopback_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("无法分配链式节点测试端口")?;
    listener
        .local_addr()
        .map(|address| address.port())
        .context("无法读取链式节点测试端口")
}

fn wait_for_loopback_port(port: u16, timeout: Duration) -> Result<()> {
    let address = ("127.0.0.1", port)
        .to_socket_addrs()
        .context("无法解析链式节点测试监听地址")?
        .next()
        .context("链式节点测试监听地址为空")?;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("临时 shoes 测试入口未能在限定时间内启动")
}

fn validate_probe_status(status: reqwest::StatusCode, node_name: &str) -> Result<()> {
    if status != reqwest::StatusCode::NO_CONTENT {
        bail!("完整代理请求返回 HTTP {status}，期望 204 No Content；节点 {node_name} 不可用");
    }
    Ok(())
}

pub async fn test_proxy_handshake(node: &ChainNode, timeout: Duration) -> Result<Duration> {
    utils::require_linux_root()?;
    if !std::path::Path::new(utils::SHOES_BIN).is_file() {
        bail!("未找到 shoes：{}", utils::SHOES_BIN);
    }

    let directory = tempfile::tempdir().context("创建链式节点测试目录失败")?;
    let config_path = directory.path().join("probe.yaml");
    let port = reserve_loopback_port()?;
    let yaml = probe_config(node, port)?;
    utils::atomic_write(&config_path, yaml.as_bytes(), 0o600)?;

    let dry_run = tokio::process::Command::new(utils::SHOES_BIN)
        .arg("--dry-run")
        .arg(&config_path)
        .output()
        .await
        .context("无法执行临时 shoes 配置校验")?;
    if !dry_run.status.success() {
        let error = String::from_utf8_lossy(&dry_run.stderr);
        bail!("shoes 拒绝链式节点测试配置：{}", error.trim());
    }

    let mut child = tokio::process::Command::new(utils::SHOES_BIN)
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("无法启动临时 shoes 节点测试进程")?;

    let result = async {
        tokio::task::spawn_blocking(move || wait_for_loopback_port(port, Duration::from_secs(3)))
            .await
            .context("等待临时 shoes 测试入口的任务异常退出")??;

        let probe_url = std::env::var("PING_RUST_CHAIN_TEST_URL")
            .unwrap_or_else(|_| DEFAULT_PROXY_PROBE_URL.to_owned());
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
            .context("创建链式节点测试代理失败")?;
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("创建链式节点测试客户端失败")?;
        let started = Instant::now();
        let response = client
            .get(&probe_url)
            .send()
            .await
            .with_context(|| format!("完整代理请求失败，节点 {} 未通过协议握手", node.name))?;
        validate_probe_status(response.status(), &node.name)?;
        Ok(started.elapsed())
    }
    .await;

    let _ = child.kill().await;
    let _ = child.wait().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_socks_and_http_credentials() {
        let socks = parse_share_uri("socks5://alice:p%40ss@127.0.0.1:1080#edge").unwrap();
        assert_eq!(socks.name, "edge");
        assert_eq!(socks.address(), "127.0.0.1:1080");
        assert!(matches!(
            socks.client.protocol,
            ShoesClientProtocol::Socks {
                username: Some(ref user),
                password: Some(ref password)
            } if user == "alice" && password == "p@ss"
        ));
        assert!(!socks.supports_udp_over_tcp());

        let https = parse_share_uri("https://proxy.example.com:443?sni=edge.example.com").unwrap();
        assert!(matches!(
            https.client.protocol,
            ShoesClientProtocol::Tls { .. }
        ));
    }

    #[test]
    fn rejects_proxy_urls_without_a_server_address_without_panicking() {
        let error = parse_share_uri("socks5:///missing-host")
            .unwrap_err()
            .to_string();
        assert!(error.contains("服务器地址"), "{error}");
    }

    #[test]
    fn proxy_probe_requires_exactly_http_204() {
        validate_probe_status(reqwest::StatusCode::NO_CONTENT, "edge").unwrap();
        let error = validate_probe_status(reqwest::StatusCode::OK, "edge")
            .unwrap_err()
            .to_string();
        assert!(error.contains("HTTP 200"), "{error}");
        assert!(error.contains("204 No Content"), "{error}");
    }

    #[test]
    fn parses_both_sip002_shadowsocks_forms() {
        let user = URL_SAFE_NO_PAD.encode("aes-128-gcm:secret");
        let first = parse_share_uri(&format!("ss://{user}@example.com:8388#ss-one")).unwrap();
        assert_eq!(first.protocol_name(), "Shadowsocks");

        let whole = URL_SAFE_NO_PAD.encode("aes-256-gcm:secret@example.com:8389");
        let second = parse_share_uri(&format!("ss://{whole}#whole-form")).unwrap();
        assert_eq!(second.address(), "example.com:8389");
        assert_eq!(second.name, "whole-form");
    }

    #[test]
    fn parses_vless_reality_and_trojan_websocket() {
        let public_key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let vless = parse_share_uri(
            &format!("vless://b85798ef-e9dc-46a4-9a87-8da4499d36d0@example.com:443?security=reality&type=tcp&sni=www.cloudflare.com&pbk={public_key}&sid=0123456789abcdef&flow=xtls-rprx-vision#reality"),
        )
        .unwrap();
        assert_eq!(vless.protocol_name(), "VLESS-Reality");
        assert!(vless.supports_udp_over_tcp());

        let trojan = parse_share_uri(
            "trojan://secret@example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com&sni=example.com#trojan",
        )
        .unwrap();
        assert_eq!(trojan.protocol_name(), "Trojan-WS-TLS");
        assert!(!trojan.supports_udp_over_tcp());
    }

    #[test]
    fn rejects_unimplemented_outbounds_and_invalid_combinations() {
        for uri in [
            "hysteria2://secret@example.com:443",
            "tuic://id:secret@example.com:443",
            "wireguard://example.com:51820",
        ] {
            assert!(parse_share_uri(uri).is_err(), "accepted {uri}");
        }
        let invalid = "vless://b85798ef-e9dc-46a4-9a87-8da4499d36d0@example.com:443?security=reality&type=ws&sni=example.com&pbk=public";
        assert!(parse_share_uri(invalid).is_err());
        let invalid_public_key = "vless://b85798ef-e9dc-46a4-9a87-8da4499d36d0@example.com:443?security=reality&type=tcp&sni=example.com&pbk=short&sid=0123456789abcdef";
        assert!(parse_share_uri(invalid_public_key).is_err());
        let invalid_short_id = format!(
            "vless://b85798ef-e9dc-46a4-9a87-8da4499d36d0@example.com:443?security=reality&type=tcp&sni=example.com&pbk={}&sid=not-hex",
            URL_SAFE_NO_PAD.encode([7_u8; 32])
        );
        assert!(parse_share_uri(&invalid_short_id).is_err());
        assert!(parse_share_uri("trojan://secret@example.com:443?security=none&type=tcp").is_err());
    }

    #[test]
    fn state_requires_selection_before_enable_and_disables_on_active_delete() {
        let mut state = ChainProxyState::default();
        assert!(state.apply(ChainProxyChange::SetEnabled(true)).is_err());
        let node = parse_share_uri("socks5://127.0.0.1:1080#edge").unwrap();
        let id = node.id;
        state.apply(ChainProxyChange::Add(node)).unwrap();
        state.apply(ChainProxyChange::Select(id)).unwrap();
        state.apply(ChainProxyChange::SetEnabled(true)).unwrap();
        assert!(state.effective().is_some());
        state.apply(ChainProxyChange::Delete(id)).unwrap();
        assert!(!state.enabled);
        assert!(state.active_node.is_none());
    }

    #[test]
    fn proxy_probe_uses_the_selected_node_as_client_chain() {
        let node = parse_share_uri("socks5://alice:secret@127.0.0.1:1080#edge").unwrap();
        let yaml = probe_config(&node, 19080).unwrap();
        assert!(yaml.contains("address: 127.0.0.1:19080"));
        assert!(yaml.contains("client_chains:"));
        assert!(yaml.contains("address: 127.0.0.1:1080"));
        assert!(yaml.contains("username: alice"));
        assert!(yaml.contains("password: secret"));
    }
}
