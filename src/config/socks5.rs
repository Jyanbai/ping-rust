use std::net::{IpAddr, SocketAddr};

use super::*;

mod secure;
pub(crate) use secure::{secure, SecureMode};

/// SOCKS5 的监听策略随 profile 存储。旧版例外绑定原地址，启用认证后撤销。
#[derive(Clone, Serialize, Deserialize)]
pub struct Socks5Listen {
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_public_address: Option<String>,
}

impl Socks5Listen {
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_owned(),
            legacy_public_address: None,
        }
    }
}

fn ip(address: &str) -> Option<IpAddr> {
    if let Some(address) = address.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return address.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6);
    }
    address.parse().ok()
}

pub(super) fn socks5_is_loopback(address: &str) -> bool {
    ip(address).is_some_and(|ip| ip.is_loopback())
}

pub(crate) fn socks5_listen_host(no_auth: bool, server_address: Option<&str>) -> &'static str {
    if !no_auth {
        "0.0.0.0"
    } else if server_address.is_some_and(|host| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::Ipv6Addr>()
            .is_ok()
    }) {
        "::1"
    } else {
        "127.0.0.1"
    }
}

pub(super) fn socks5_address(host: &str, port: u16) -> String {
    match ip(host) {
        Some(IpAddr::V6(_)) if !host.starts_with('[') => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

impl ManagedProfile {
    /// 配置变更统一撤销已认证节点的旧版例外，避免遗漏任何凭据写入路径。
    pub(super) fn revoke_authenticated_socks5_legacy_exemption(&mut self) {
        if let Credentials::Socks5 {
            username: Some(_),
            password: Some(_),
            listen: Some(listen),
            ..
        } = &mut self.credentials
        {
            listen.legacy_public_address = None;
        }
    }

    pub(crate) fn socks5_loopback(&self) -> Option<&str> {
        match &self.credentials {
            Credentials::Socks5 {
                listen: Some(listen),
                ..
            } if socks5_is_loopback(&listen.address) => Some(&listen.address),
            _ => None,
        }
    }

    pub(crate) fn listen_address(&self) -> Result<String> {
        if let Credentials::Socks5 { listen, .. } = &self.credentials {
            let listen = listen
                .as_ref()
                .context("SOCKS5 profile 缺少显式 listen，请先迁移旧配置")?;
            return Ok(socks5_address(&listen.address, self.port));
        }
        Ok(format!("0.0.0.0:{}", self.port))
    }

    pub(super) fn validate_socks5_anonymous(&self) -> Result<()> {
        let Credentials::Socks5 { listen, .. } = &self.credentials else {
            return Ok(());
        };
        let listen = listen
            .as_ref()
            .context("SOCKS5 profile 缺少显式 listen，请先迁移旧配置")?;
        if !socks5_is_loopback(&listen.address)
            && listen.legacy_public_address.as_deref() != Some(listen.address.as_str())
        {
            bail!("无认证 SOCKS5 必须监听回环 IP；请改用回环监听或保留用户名密码认证");
        }
        Ok(())
    }

    pub(crate) fn validate_socks5_listen(&self) -> Result<()> {
        if let Credentials::Socks5 {
            listen,
            username,
            password,
            ..
        } = &self.credentials
        {
            let listen = listen
                .as_ref()
                .context("SOCKS5 profile 缺少显式 listen，请先迁移旧配置")?;
            if ip(&listen.address).is_none() {
                bail!("SOCKS5 listen 必须是明确的 IP 地址");
            }
            match (username, password) {
                (None, None) => self.validate_socks5_anonymous()?,
                (Some(_), Some(_)) => {}
                _ => bail!("SOCKS5 管理状态中的用户名和密码不完整"),
            }
        }
        Ok(())
    }

    pub(crate) fn socks5_risk_warning(&self) -> Option<String> {
        if !matches!(&self.credentials, Credentials::Socks5 {
            username: None, password: None, listen: Some(listen), ..
        } if !socks5_is_loopback(&listen.address))
        {
            return None;
        }
        Some(format!(
            "警告：旧节点 {}（端口 {}）为无认证非回环 SOCKS5，有开放代理风险；修复：运行 `sudo prs menu` → 2) 更改配置 → 选择该节点 → 更改认证模式 → 启用用户名 + 密码认证（输入 y）。也可运行 `sudo prs socks5 secure <节点>`。",
            self.name, self.port
        ))
    }
}

pub(super) fn migrate_listen(state: &mut ManagedState, servers: &[ServerConfig]) -> Result<()> {
    if servers.len() != state.profiles.len() {
        bail!("SOCKS5 迁移失败：运行配置与状态条目数不一致");
    }
    for (profile, server) in state.profiles.iter_mut().zip(servers) {
        if let Credentials::Socks5 {
            listen,
            username,
            password,
            ..
        } = &mut profile.credentials
        {
            if listen.is_some() {
                continue;
            }
            let address: SocketAddr = server
                .address
                .parse()
                .context("旧 SOCKS5 的 address 必须含明确 IP 和端口，拒绝猜测默认绑定")?;
            if address.port() != profile.port {
                bail!("旧 SOCKS5 端口与管理状态不一致");
            }
            let host = server
                .address
                .rsplit_once(':')
                .context("旧 SOCKS5 address 缺少端口")?
                .0
                .to_owned();
            *listen = Some(Socks5Listen {
                legacy_public_address: (username.is_none()
                    && password.is_none()
                    && !address.ip().is_loopback())
                .then(|| host.clone()),
                address: host,
            });
        }
    }
    ensure_servers_match_state(servers, &state.profiles)
}

pub(super) fn listen_migration_pending(path: &Path) -> Result<bool> {
    let state: ManagedState = serde_json::from_slice(&fs::read(path)?)?;
    Ok(state.profiles.iter().any(|profile| {
        matches!(
            profile.credentials,
            Credentials::Socks5 { listen: None, .. }
        )
    }))
}
