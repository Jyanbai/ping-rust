use std::{net::IpAddr, path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use rand::Rng;
use reqwest::Client;

use crate::{
    client,
    config::{
        self, AnyTlsMode, GenerationOptions, GenerationRequest, Protocol, ShadowsocksCipher,
        ShadowsocksMode,
    },
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
    pub interactive: bool,
    pub xhttp_path: Option<String>,
    pub vless_enc: crate::vless_encryption::Options,
    pub name: Option<String>,
    pub protocol: Protocol,
    pub anytls_mode: AnyTlsMode,
    pub port: Option<u16>,
    pub server_address: Option<String>,
    pub server_name: Option<String>,
    pub shadowsocks_cipher: Option<ShadowsocksCipher>,
    pub shadowsocks_password: Option<String>,
    pub shadowsocks_mode: ShadowsocksMode,
    pub shadowtls_password: Option<String>,
    pub shadowtls_handshake: Option<String>,
    pub certificate: Option<std::path::PathBuf>,
    pub certificate_key: Option<std::path::PathBuf>,
    pub naive_self_signed: bool,
    pub naive_username: Option<String>,
    pub naive_password: Option<String>,
    pub naive_padding: bool,
    pub naive_fallback: Option<String>,
}

impl AddRequest {
    fn probes_sni(&self) -> bool {
        self.protocol.uses_reality(self.anytls_mode)
            || (self.protocol == Protocol::Shadowsocks
                && self.shadowsocks_mode == ShadowsocksMode::ShadowTlsV3)
    }
}

pub struct AddResult {
    pub generation: config::GenerationResult,
    pub share_uri: Option<String>,
}

pub async fn execute(request: AddRequest) -> Result<AddResult> {
    execute_inner(request, None).await
}

/// 菜单已完成自动选择、手动检测或完整推荐检测，复用结果而不重复探测。
pub(crate) async fn execute_with_sni(
    request: AddRequest,
    server_name: String,
) -> Result<AddResult> {
    config::validate_server_name(&server_name)?;
    execute_inner(request, Some(server_name)).await
}

async fn execute_inner(request: AddRequest, checked_sni: Option<String>) -> Result<AddResult> {
    request.vless_enc.sudoku.validate_for(request.protocol)?;
    utils::require_linux_root()?;
    if !Path::new(utils::SHOES_BIN).is_file() {
        bail!("shoes 尚未安装；请先运行 ping-rust install，或为 add 添加 --yes 自动安装");
    }

    let server_address = resolve_server_address(request.server_address.as_deref()).await?;
    let port = select_port(request.protocol, request.port)?;
    let probes_sni = request.probes_sni();
    let server_name = if let Some(server_name) = checked_sni {
        server_name
    } else if probes_sni {
        crate::sni_probe::resolve(request.server_name.clone(), request.interactive).await?
    } else {
        config::resolve_server_name(
            request.server_name.clone(),
            request.protocol,
            request.anytls_mode,
        )
    };
    let generation = add_activation_context(
        deployment::generate_and_activate(prepare_generation_request(
            request,
            server_address.clone(),
            port,
            server_name,
        )?)
        .await,
        port,
    )?;
    let share_uri = share_uri_after_activation(&generation.profile, &server_address)?;
    Ok(AddResult {
        generation,
        share_uri,
    })
}

// Keep the selected outer mode in the same request as all generation options.
fn prepare_generation_request(
    request: AddRequest,
    server_address: String,
    port: u16,
    server_name: String,
) -> Result<GenerationRequest> {
    let mut options = GenerationOptions {
        anytls_mode: request.anytls_mode,
        xhttp_path: request.xhttp_path,
        vless_enc_mode: request.vless_enc.mode,
        vless_enc_auth: request.vless_enc.auth,
        vless_enc_vision: request.vless_enc.vision,
        sudoku: request.vless_enc.sudoku.config_for(request.protocol)?,
        ..Default::default()
    };
    if request.protocol == Protocol::VlessEnc {
        request.vless_enc.warn();
    }
    if matches!(request.protocol, Protocol::Shadowsocks) {
        options.shadowsocks_cipher = request.shadowsocks_cipher.unwrap_or_default();
        options.shadowsocks_password = request.shadowsocks_password;
        options.shadowsocks_mode = request.shadowsocks_mode;
        options.shadowtls_password = request.shadowtls_password;
        options.shadowtls_handshake = request.shadowtls_handshake;
        if request.shadowsocks_mode == ShadowsocksMode::ShadowTlsV3 {
            options.udp_enabled = false;
        }
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
    if matches!(request.protocol, Protocol::NaiveProxy) {
        options.naive_self_signed = request.naive_self_signed;
        options.naive_username = request.naive_username;
        options.naive_password = request.naive_password;
        options.naive_padding = request.naive_padding;
        options.naive_fallback = request.naive_fallback;
    }

    Ok(GenerationRequest {
        name: request.name,
        protocol: request.protocol,
        port,
        output: utils::CONFIG_FILE.into(),
        server_address: Some(server_address),
        server_name: server_name.clone(),
        reality_dest: request
            .protocol
            .uses_reality(request.anytls_mode)
            .then(|| format!("{server_name}:443")),
        certificate: request.certificate,
        certificate_key: request.certificate_key,
        options,
    })
}

fn share_uri_after_activation(
    profile: &config::ManagedProfile,
    server_address: &str,
) -> Result<Option<String>> {
    if matches!(
        profile.credentials,
        config::Credentials::Snell { .. }
            | config::Credentials::NaiveProxy { .. }
            | config::Credentials::Shadowsocks {
                shadowtls: Some(_),
                ..
            }
            | config::Credentials::AnyTls {
                security: config::AnyTlsSecurity::Reality { .. },
                ..
            }
    ) {
        Ok(None)
    } else {
        client::share_uri(profile, server_address).map(Some)
    }
}

fn add_activation_context<T>(result: Result<T>, port: u16) -> Result<T> {
    match result {
        Err(error)
            if error
                .downcast_ref::<deployment::ActivationFailure>()
                .is_some() =>
        {
            Err(error.context(format!(
                "shoes 激活阶段失败；若日志显示地址被占用，说明监听端口 {port} 在预检查后被其它进程抢占，请重试"
            )))
        }
        result => result,
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
    // shoes 当前会在启动时自行创建并绑定监听套接字，未接收 systemd
    // socket activation 的 LISTEN_FDS，因此这里的检查只能用于尽早报错。
    // 检查结束到 shoes 绑定之间仍可能发生竞争；激活失败由 deployment
    // 的配置与服务快照回滚兜底。
    let (tcp, udp) = protocol.required_sockets();
    let status = operations::check_port(port, tcp, udp);
    if status.tcp_available.is_some_and(|result| result.is_err()) {
        bail!("TCP 端口 {port} 已被占用或无法绑定");
    }
    if status.udp_available.is_some_and(|result| result.is_err()) {
        bail!("UDP 端口 {port} 已被占用或无法绑定");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    fn anytls_request(mode: AnyTlsMode) -> AddRequest {
        AddRequest {
            interactive: false,
            protocol: Protocol::AnyTls,
            anytls_mode: mode,
            name: None,
            port: Some(443),
            server_address: Some("203.0.113.10".into()),
            server_name: Some("target.example.com".into()),
            vless_enc: Default::default(),
            xhttp_path: None,
            shadowsocks_cipher: None,
            shadowsocks_password: None,
            shadowsocks_mode: ShadowsocksMode::Plain,
            shadowtls_password: None,
            shadowtls_handshake: None,
            certificate: None,
            certificate_key: None,
            naive_self_signed: false,
            naive_username: None,
            naive_password: None,
            naive_padding: true,
            naive_fallback: None,
        }
    }

    #[test]
    fn anytls_fast_modes_keep_sni_destination_certificate_and_generation_consistent() {
        assert_eq!(AnyTlsMode::default(), AnyTlsMode::Tls);
        for mode in [AnyTlsMode::default(), AnyTlsMode::Reality] {
            let request = anytls_request(mode);
            let reality = mode == AnyTlsMode::Reality;
            assert_eq!(request.probes_sni(), reality);
            let request = prepare_generation_request(
                request,
                "203.0.113.10".into(),
                443,
                "target.example.com".into(),
            )
            .unwrap();
            assert_eq!(request.options.anytls_mode, mode);
            assert_eq!(request.server_name, "target.example.com");
            assert_eq!(
                request.reality_dest.as_deref(),
                reality.then_some("target.example.com:443")
            );
            assert_eq!(
                request
                    .protocol
                    .requires_certificate(request.options.anytls_mode),
                !reality
            );
            assert_eq!(request.options.anytls_users.len(), 1);
            assert_eq!(request.options.anytls_users[0].name, "default");
            assert!(!request.options.anytls_users[0].password.is_empty());
            assert_eq!(
                request.options.anytls_padding_scheme.unwrap(),
                ["stop=8", "0=30-30", "1=50-100"]
            );
            assert!(request.options.udp_enabled);
        }
    }

    #[test]
    fn anytls_fast_result_keeps_reality_success_without_a_tls_uri() {
        let mut profile = config::ManagedProfile {
            id: uuid::Uuid::nil(),
            name: "anytls-test".into(),
            port: 443,
            server_address: Some("203.0.113.10".into()),
            h2mux: Default::default(),
            credentials: config::Credentials::AnyTls {
                users: vec![config::AnyTlsUser {
                    name: "default".into(),
                    password: "test-password".into(),
                }],
                server_name: "target.example.com".into(),
                alpn_protocols: vec!["h2".into(), "http/1.1".into()],
                udp_enabled: true,
                security: config::AnyTlsSecurity::Tls,
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
            naive_certificate_validity: None,
        };
        let tls = share_uri_after_activation(&profile, "203.0.113.10")
            .unwrap()
            .unwrap();
        assert!(tls.starts_with("anytls://"));
        let config::Credentials::AnyTls { security, .. } = &mut profile.credentials else {
            unreachable!()
        };
        *security = config::AnyTlsSecurity::Reality {
            private_key: "never-export-private".into(),
            public_key: "public-key".into(),
            short_id: "0123456789abcdef".into(),
        };
        assert!(share_uri_after_activation(&profile, "203.0.113.10")
            .unwrap()
            .is_none());
        let error = client::share_uri(&profile, "203.0.113.10").unwrap_err();
        assert!(error.to_string().contains("请改用 sing-box 导出"));
        assert!(client::render(&profile, client::ClientFormat::ClashMeta, "203.0.113.10").is_err());
        assert!(client::render(&profile, client::ClientFormat::Nekobox, "203.0.113.10").is_err());
        let exported =
            client::render(&profile, client::ClientFormat::SingBox, "203.0.113.10").unwrap();
        assert!(exported.contains("public-key"));
        assert!(!exported.contains("never-export-private"));
        let details = crate::cli::profile_details_text(&profile, None);
        assert!(details.contains("public-key"));
        assert!(!details.contains("never-export-private"));
    }

    #[test]
    fn uses_sequential_protocol_numbers() {
        for protocol in Protocol::all() {
            assert_eq!(
                Protocol::from_menu_number(protocol.menu_number()),
                Some(protocol)
            );
        }
        assert_eq!(Protocol::from_menu_number(0), None);
        assert_eq!(Protocol::from_menu_number(15), Some(Protocol::Socks5));
        assert_eq!(Protocol::from_menu_number(13), Some(Protocol::Snell));
        assert_eq!(Protocol::from_menu_number(6), Some(Protocol::NaiveProxy));
    }

    #[test]
    fn port_race_guidance_only_wraps_activation_failures() {
        let ordinary = add_activation_context::<()>(Err(anyhow!("配置名称重复")), 443).unwrap_err();
        assert!(!format!("{ordinary:#}").contains("监听端口 443"));

        let activation = anyhow::Error::new(deployment::ActivationFailure::new(
            "shoes 激活失败，配置和服务状态已回滚",
            anyhow!("systemctl restart 失败"),
        ));
        let activation = add_activation_context::<()>(Err(activation), 443).unwrap_err();
        let message = format!("{activation:#}");
        assert!(message.contains("监听端口 443"));
        assert!(message.contains("配置和服务状态已回滚"));
        assert!(message.contains("systemctl restart 失败"));
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

    #[test]
    fn socks5_random_port_is_valid() {
        let port = select_port(Protocol::Socks5, None).unwrap();
        assert!((RANDOM_PORT_MIN..=u16::MAX).contains(&port));
    }
}
