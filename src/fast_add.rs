use std::{net::IpAddr, path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use rand::Rng;
use reqwest::Client;

use crate::{
    client,
    config::{self, GenerationOptions, GenerationRequest, Protocol, ShadowsocksCipher},
    deployment, operations, utils,
};

const RANDOM_PORT_MIN: u16 = 20_000;
const RANDOM_PORT_ATTEMPTS: usize = 233;
const ADDRESS_ENDPOINTS: &[&str] = &[
    "https://api.ipify.org",
    "https://api64.ipify.org",
    "https://icanhazip.com",
    "https://one.one.one.one/cdn-cgi/trace",
];

pub struct AddRequest {
    pub name: Option<String>,
    pub protocol: Protocol,
    pub port: Option<u16>,
    pub server_address: Option<String>,
    pub server_name: Option<String>,
    pub shadowsocks_cipher: Option<ShadowsocksCipher>,
    pub shadowsocks_password: Option<String>,
}

pub struct AddResult {
    pub generation: config::GenerationResult,
    pub share_uri: String,
}

pub async fn execute(request: AddRequest) -> Result<AddResult> {
    utils::require_linux_root()?;
    if !Path::new(utils::SHOES_BIN).is_file() {
        bail!("shoes 尚未安装；请先运行 ping-rust install，或为 add 添加 --yes 自动安装");
    }

    let server_address = resolve_server_address(request.server_address.as_deref()).await?;
    let port = select_port(request.protocol, request.port)?;
    let server_name = request
        .server_name
        .unwrap_or_else(|| config::DEFAULT_SNI.to_owned());
    let mut options = GenerationOptions::default();
    if matches!(request.protocol, Protocol::Shadowsocks) {
        options.shadowsocks_cipher = request.shadowsocks_cipher.unwrap_or_default();
        options.shadowsocks_password = request.shadowsocks_password;
    }
    if matches!(request.protocol, Protocol::AnyTls) {
        options
            .anytls_users
            .push(config::generated_anytls_user("default"));
        options.anytls_padding_scheme = Some(vec![
            "stop=8".to_owned(),
            "0=30-30".to_owned(),
            "1=50-100".to_owned(),
        ]);
    }

    let generation = deployment::generate_and_activate(GenerationRequest {
        name: request.name,
        protocol: request.protocol,
        port,
        output: utils::CONFIG_FILE.into(),
        server_address: Some(server_address.clone()),
        server_name: server_name.clone(),
        reality_dest: is_reality_outer(request.protocol).then(|| format!("{server_name}:443")),
        certificate: None,
        certificate_key: None,
        options,
    })
    .await?;
    let share_uri = client::share_uri(&generation.profile, &server_address)?;
    Ok(AddResult {
        generation,
        share_uri,
    })
}

pub fn protocol_from_menu_number(number: usize) -> Result<Protocol> {
    match number {
        1 => Ok(Protocol::Tuic),
        2 => Ok(Protocol::Hysteria2),
        3 => Ok(Protocol::Shadowsocks),
        4 => Ok(Protocol::Reality),
        5 => Ok(Protocol::AnyTls),
        _ => bail!("协议编号无效；可选 1、2、3、4、5"),
    }
}

#[cfg(test)]
fn menu_number(protocol: Protocol) -> usize {
    match protocol {
        Protocol::Tuic => 1,
        Protocol::Hysteria2 => 2,
        Protocol::Shadowsocks => 3,
        Protocol::Reality => 4,
        Protocol::AnyTls => 5,
    }
}

pub async fn resolve_server_address(explicit: Option<&str>) -> Result<String> {
    if let Some(explicit) = explicit {
        return client::normalize_server_address(explicit);
    }
    let client = Client::builder()
        .user_agent(concat!("ping-rust/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .build()
        .context("创建公网地址探测客户端失败")?;
    let mut failures = Vec::new();
    for endpoint in ADDRESS_ENDPOINTS {
        match detect_from_endpoint(&client, endpoint).await {
            Ok(address) => return Ok(address),
            Err(error) => failures.push(format!("{endpoint}: {error}")),
        }
    }
    bail!(
        "自动检测服务器公网 IP 失败；请使用 --server-address 指定。探测结果：{}",
        failures.join("；")
    )
}

async fn detect_from_endpoint(client: &Client, endpoint: &str) -> Result<String> {
    let body = client
        .get(endpoint)
        .send()
        .await
        .context("请求失败")?
        .error_for_status()
        .context("服务器返回错误")?
        .text()
        .await
        .context("读取响应失败")?;
    parse_detected_address(&body).context("响应中没有有效公网 IP")
}

fn parse_detected_address(body: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let line = line.trim();
        let value = line.strip_prefix("ip=").unwrap_or(line);
        let address = value.parse::<IpAddr>().ok()?;
        (!address.is_unspecified()
            && !address.is_loopback()
            && !address.is_multicast()
            && !is_private_address(address))
        .then(|| address.to_string())
    })
}

fn is_private_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private() || address.is_link_local(),
        IpAddr::V6(address) => address.is_unique_local() || address.is_unicast_link_local(),
    }
}

fn select_port(protocol: Protocol, requested: Option<u16>) -> Result<u16> {
    select_port_excluding(protocol, requested, None)
}

pub(crate) fn select_port_for_update(
    protocol: Protocol,
    requested: Option<u16>,
    profile_id: uuid::Uuid,
    current_port: u16,
) -> Result<u16> {
    if requested == Some(current_port) {
        return Ok(current_port);
    }
    select_port_excluding(protocol, requested, Some(profile_id))
}

fn select_port_excluding(
    protocol: Protocol,
    requested: Option<u16>,
    excluded_profile: Option<uuid::Uuid>,
) -> Result<u16> {
    if let Some(port) = requested {
        ensure_port_available(protocol, port, excluded_profile)?;
        return Ok(port);
    }
    let mut random = rand::rng();
    for _ in 0..RANDOM_PORT_ATTEMPTS {
        let port = random.random_range(RANDOM_PORT_MIN..=u16::MAX);
        if ensure_port_available(protocol, port, excluded_profile).is_ok() {
            return Ok(port);
        }
    }
    bail!("自动获取可用端口失败次数达到 233 次，请检查端口占用情况")
}

fn ensure_port_available(
    protocol: Protocol,
    port: u16,
    excluded_profile: Option<uuid::Uuid>,
) -> Result<()> {
    if port == 0 {
        bail!("端口必须在 1..=65535 范围内");
    }
    if Path::new(utils::STATE_FILE).exists()
        && config::load_state()?
            .profiles
            .iter()
            .any(|profile| Some(profile.id) != excluded_profile && profile.port == port)
    {
        bail!("端口 {port} 已由 ping-rust 配置使用");
    }
    let (tcp, udp) = required_sockets(protocol);
    let status = operations::check_port(port, tcp, udp);
    if status.tcp_available.is_some_and(|result| result.is_err()) {
        bail!("TCP 端口 {port} 已被占用或无法绑定");
    }
    if status.udp_available.is_some_and(|result| result.is_err()) {
        bail!("UDP 端口 {port} 已被占用或无法绑定");
    }
    Ok(())
}

fn required_sockets(protocol: Protocol) -> (bool, bool) {
    match protocol {
        Protocol::Reality | Protocol::AnyTls => (true, false),
        Protocol::Hysteria2 | Protocol::Tuic => (false, true),
        Protocol::Shadowsocks => (true, true),
    }
}

fn is_reality_outer(protocol: Protocol) -> bool {
    matches!(protocol, Protocol::Reality)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_sequential_protocol_numbers() {
        for (number, protocol) in [
            (1, Protocol::Tuic),
            (2, Protocol::Hysteria2),
            (3, Protocol::Shadowsocks),
            (4, Protocol::Reality),
            (5, Protocol::AnyTls),
        ] {
            assert_eq!(protocol_from_menu_number(number).unwrap(), protocol);
            assert_eq!(menu_number(protocol), number);
        }
        assert!(protocol_from_menu_number(0).is_err());
        assert!(protocol_from_menu_number(6).is_err());
    }

    #[test]
    fn parses_plain_and_cloudflare_addresses() {
        assert_eq!(
            parse_detected_address("203.0.113.7\n"),
            Some("203.0.113.7".to_owned())
        );
        assert_eq!(
            parse_detected_address("fl=1\nip=2001:4860:4860::8888\nts=1\n"),
            Some("2001:4860:4860::8888".to_owned())
        );
        assert_eq!(parse_detected_address("ip=127.0.0.1"), None);
    }
}
