use std::{net::IpAddr, path::Path};

use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use clap::ValueEnum;
use serde_json::{json, Value};
use url::form_urlencoded::{byte_serialize, Serializer};
use uuid::Uuid;

use crate::{
    config::{self, Credentials, ManagedProfile},
    utils,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ClientFormat {
    ClashMeta,
    SingBox,
    Nekobox,
}

pub fn export(
    profile_id: Option<Uuid>,
    format: ClientFormat,
    server: &str,
    output: Option<&Path>,
) -> Result<String> {
    let state = config::load_state()?;
    let profile = match profile_id {
        Some(id) => state
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .with_context(|| format!("未找到配置 {id}"))?,
        None if state.profiles.len() == 1 => &state.profiles[0],
        None => bail!("存在多个配置，请用 --profile <UUID> 指定导出对象"),
    };
    let content = render(profile, format, server)?;
    if let Some(path) = output {
        utils::atomic_write(path, content.as_bytes(), 0o600)?;
    }
    Ok(content)
}

pub fn select_profile<'a>(
    profiles: &'a [ManagedProfile],
    selector: Option<&str>,
) -> Result<&'a ManagedProfile> {
    match selector {
        Some(selector) => {
            let selector = selector.trim();
            if let Ok(id) = Uuid::parse_str(selector) {
                if let Some(profile) = profiles.iter().find(|profile| profile.id == id) {
                    return Ok(profile);
                }
            }
            let mut matches = profiles
                .iter()
                .filter(|profile| profile.name.eq_ignore_ascii_case(selector));
            let profile = matches
                .next()
                .with_context(|| format!("未找到配置 {selector}"))?;
            if matches.next().is_some() {
                bail!("配置名称 {selector} 存在重复，请改用 UUID 指定");
            }
            Ok(profile)
        }
        None if profiles.len() == 1 => Ok(&profiles[0]),
        None if profiles.is_empty() => bail!("没有可用配置"),
        None => bail!("存在多个配置，请指定配置 UUID 或名称"),
    }
}

pub fn stored_share_uri(profile: &ManagedProfile, override_server: Option<&str>) -> Result<String> {
    let server = override_server
        .or(profile.server_address.as_deref())
        .context("该配置没有保存公网地址；请使用 --server-address 指定")?;
    share_uri(profile, server)
}

pub fn render(profile: &ManagedProfile, format: ClientFormat, server: &str) -> Result<String> {
    let server = normalize_server_address(server)?;
    match format {
        ClientFormat::ClashMeta => clash_meta(profile, &server),
        ClientFormat::SingBox => sing_box(profile, &server),
        ClientFormat::Nekobox => share_uri(profile, &server),
    }
}

fn clash_meta(profile: &ManagedProfile, server: &str) -> Result<String> {
    let proxy = match &profile.credentials {
        Credentials::Reality {
            user_id,
            public_key,
            short_id,
            server_name,
            ..
        } => json!({
            "name": profile.name,
            "type": "vless",
            "server": server,
            "port": profile.port,
            "uuid": user_id,
            "network": "tcp",
            "udp": true,
            "tls": true,
            "servername": server_name,
            "flow": "xtls-rprx-vision",
            "client-fingerprint": config::REALITY_FINGERPRINT,
            "reality-opts": { "public-key": public_key, "short-id": short_id }
        }),
        Credentials::Hysteria2 {
            password,
            server_name,
            alpn_protocols,
        } => json!({
            "name": profile.name,
            "type": "hysteria2",
            "server": server,
            "port": profile.port,
            "password": password,
            "sni": server_name,
            "alpn": alpn_protocols,
            "skip-cert-verify": profile.self_signed_certificate
        }),
        Credentials::Tuic {
            user_id,
            password,
            server_name,
            alpn_protocols,
            zero_rtt_handshake,
        } => json!({
            "name": profile.name,
            "type": "tuic",
            "server": server,
            "port": profile.port,
            "uuid": user_id,
            "password": password,
            "sni": server_name,
            "alpn": alpn_protocols,
            "reduce-rtt": zero_rtt_handshake,
            "congestion-controller": "bbr",
            "udp-relay-mode": "native",
            "skip-cert-verify": profile.self_signed_certificate
        }),
        Credentials::Shadowsocks {
            cipher,
            password,
            udp_enabled,
        } => json!({
            "name": profile.name,
            "type": "ss",
            "server": server,
            "port": profile.port,
            "cipher": cipher.client_name(),
            "password": password,
            "udp": udp_enabled
        }),
        Credentials::AnyTls {
            users,
            server_name,
            alpn_protocols,
            udp_enabled,
            security,
        } => {
            let password = single_anytls_password(users)?;
            if matches!(security, config::AnyTlsSecurity::Reality { .. }) {
                bail!("Clash Meta 不支持 AnyTLS+Reality，请改用 sing-box 导出");
            }
            json!({
                "name": profile.name,
                "type": "anytls",
                "server": server,
                "port": profile.port,
                "password": password,
                "client-fingerprint": config::REALITY_FINGERPRINT,
                "udp": udp_enabled,
                "sni": server_name,
                "alpn": alpn_protocols,
                "skip-cert-verify": profile.self_signed_certificate
            })
        }
        Credentials::VlessTls {
            user_id,
            server_name,
            alpn_protocols,
            vision,
            websocket_path,
        } => {
            let mut proxy = json!({
                "name": profile.name,
                "type": "vless",
                "server": server,
                "port": profile.port,
                "uuid": user_id,
                "udp": true,
                "tls": true,
                "servername": server_name,
                "alpn": alpn_protocols,
                "client-fingerprint": config::REALITY_FINGERPRINT,
                "skip-cert-verify": profile.self_signed_certificate,
                "network": if websocket_path.is_some() { "ws" } else { "tcp" }
            });
            if *vision {
                proxy["flow"] = json!("xtls-rprx-vision");
            }
            if let Some(path) = websocket_path {
                proxy["ws-opts"] = json!({
                    "path": path,
                    "headers": { "Host": server_name }
                });
            }
            proxy
        }
        Credentials::Trojan {
            password,
            server_name,
            alpn_protocols,
            security,
        } => {
            let mut proxy = json!({
                "name": profile.name,
                "type": "trojan",
                "server": server,
                "port": profile.port,
                "password": password,
                "udp": true,
                "sni": server_name,
                "alpn": alpn_protocols,
                "client-fingerprint": config::REALITY_FINGERPRINT,
                "network": "tcp"
            });
            match security {
                config::TlsSecurity::Tls => {
                    proxy["skip-cert-verify"] = json!(profile.self_signed_certificate);
                }
                config::TlsSecurity::Reality {
                    public_key,
                    short_id,
                    ..
                } => {
                    proxy["reality-opts"] =
                        json!({ "public-key": public_key, "short-id": short_id });
                }
            }
            proxy
        }
        Credentials::VmessTls {
            user_id,
            server_name,
            alpn_protocols,
            websocket_path,
        } => json!({
            "name": profile.name,
            "type": "vmess",
            "server": server,
            "port": profile.port,
            "uuid": user_id,
            "alterId": 0,
            "cipher": "auto",
            "udp": true,
            "tls": true,
            "servername": server_name,
            "alpn": alpn_protocols,
            "client-fingerprint": config::REALITY_FINGERPRINT,
            "skip-cert-verify": profile.self_signed_certificate,
            "network": "ws",
            "ws-opts": {
                "path": websocket_path,
                "headers": { "Host": server_name }
            }
        }),
    };
    serde_yaml::to_string(&json!({ "proxies": [proxy] })).context("生成 Clash Meta YAML 失败")
}

fn sing_box(profile: &ManagedProfile, server: &str) -> Result<String> {
    let tls = |server_name: &str, insecure: bool, alpn: &[String]| {
        json!({
            "enabled": true,
            "server_name": server_name,
            "insecure": insecure,
            "alpn": alpn
        })
    };
    let outbound: Value = match &profile.credentials {
        Credentials::Reality {
            user_id,
            public_key,
            short_id,
            server_name,
            ..
        } => json!({
            "type": "vless",
            "tag": profile.name,
            "server": server,
            "server_port": profile.port,
            "uuid": user_id,
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": true,
                "server_name": server_name,
                "utls": { "enabled": true, "fingerprint": config::REALITY_FINGERPRINT },
                "reality": { "enabled": true, "public_key": public_key, "short_id": short_id }
            }
        }),
        Credentials::Hysteria2 {
            password,
            server_name,
            alpn_protocols,
        } => json!({
            "type": "hysteria2",
            "tag": profile.name,
            "server": server,
            "server_port": profile.port,
            "password": password,
            "tls": tls(server_name, profile.self_signed_certificate, alpn_protocols)
        }),
        Credentials::Tuic {
            user_id,
            password,
            server_name,
            alpn_protocols,
            zero_rtt_handshake,
        } => json!({
            "type": "tuic",
            "tag": profile.name,
            "server": server,
            "server_port": profile.port,
            "uuid": user_id,
            "password": password,
            "congestion_control": "bbr",
            "zero_rtt_handshake": zero_rtt_handshake,
            "tls": tls(server_name, profile.self_signed_certificate, alpn_protocols)
        }),
        Credentials::Shadowsocks {
            cipher, password, ..
        } => json!({
            "type": "shadowsocks",
            "tag": profile.name,
            "server": server,
            "server_port": profile.port,
            "method": cipher.client_name(),
            "password": password
        }),
        Credentials::AnyTls {
            users,
            server_name,
            alpn_protocols,
            security,
            ..
        } => {
            let password = single_anytls_password(users)?;
            let tls = match security {
                config::AnyTlsSecurity::Tls => {
                    tls(server_name, profile.self_signed_certificate, alpn_protocols)
                }
                config::AnyTlsSecurity::Reality {
                    public_key,
                    short_id,
                    ..
                } => json!({
                    "enabled": true,
                    "server_name": server_name,
                    "utls": { "enabled": true, "fingerprint": config::REALITY_FINGERPRINT },
                    "reality": {
                        "enabled": true,
                        "public_key": public_key,
                        "short_id": short_id
                    }
                }),
            };
            json!({
                "type": "anytls",
                "tag": profile.name,
                "server": server,
                "server_port": profile.port,
                "password": password,
                "tls": tls
            })
        }
        Credentials::VlessTls {
            user_id,
            server_name,
            alpn_protocols,
            vision,
            websocket_path,
        } => {
            let mut outbound = json!({
                "type": "vless",
                "tag": profile.name,
                "server": server,
                "server_port": profile.port,
                "uuid": user_id,
                "tls": tls(server_name, profile.self_signed_certificate, alpn_protocols)
            });
            if *vision {
                outbound["flow"] = json!("xtls-rprx-vision");
            }
            if let Some(path) = websocket_path {
                outbound["transport"] = json!({
                    "type": "ws",
                    "path": path,
                    "headers": { "Host": server_name }
                });
            }
            outbound
        }
        Credentials::Trojan {
            password,
            server_name,
            alpn_protocols,
            security,
        } => {
            let tls = match security {
                config::TlsSecurity::Tls => {
                    tls(server_name, profile.self_signed_certificate, alpn_protocols)
                }
                config::TlsSecurity::Reality {
                    public_key,
                    short_id,
                    ..
                } => json!({
                    "enabled": true,
                    "server_name": server_name,
                    "utls": { "enabled": true, "fingerprint": config::REALITY_FINGERPRINT },
                    "reality": {
                        "enabled": true,
                        "public_key": public_key,
                        "short_id": short_id
                    }
                }),
            };
            json!({
                "type": "trojan",
                "tag": profile.name,
                "server": server,
                "server_port": profile.port,
                "password": password,
                "tls": tls
            })
        }
        Credentials::VmessTls {
            user_id,
            server_name,
            alpn_protocols,
            websocket_path,
        } => json!({
            "type": "vmess",
            "tag": profile.name,
            "server": server,
            "server_port": profile.port,
            "uuid": user_id,
            "security": "auto",
            "alter_id": 0,
            "tls": tls(server_name, profile.self_signed_certificate, alpn_protocols),
            "transport": {
                "type": "ws",
                "path": websocket_path,
                "headers": { "Host": server_name }
            }
        }),
    };
    serde_json::to_string_pretty(&json!({ "outbounds": [outbound] }))
        .context("生成 sing-box JSON 失败")
}

pub fn share_uri(profile: &ManagedProfile, server: &str) -> Result<String> {
    let server = normalize_server_address(server)?;
    let host = authority_host(&server);
    let fragment = encode(&profile.display_name());
    match &profile.credentials {
        Credentials::Reality {
            user_id,
            public_key,
            short_id,
            server_name,
            ..
        } => {
            let mut query = Serializer::new(String::new());
            query
                .append_pair("encryption", "none")
                .append_pair("flow", "xtls-rprx-vision")
                .append_pair("security", "reality")
                .append_pair("sni", server_name)
                .append_pair("fp", config::REALITY_FINGERPRINT)
                .append_pair("pbk", public_key)
                .append_pair("sid", short_id)
                .append_pair("type", "tcp");
            Ok(format!(
                "vless://{user_id}@{host}:{}?{}#{fragment}",
                profile.port,
                query.finish()
            ))
        }
        Credentials::Hysteria2 {
            password,
            server_name,
            ..
        } => {
            let mut query = Serializer::new(String::new());
            query
                .append_pair("sni", server_name)
                .append_pair("alpn", "h3");
            if profile.self_signed_certificate {
                query
                    .append_pair("insecure", "1")
                    .append_pair("allowInsecure", "1");
            }
            Ok(format!(
                "hysteria2://{}@{host}:{}?{}#{fragment}",
                encode(password),
                profile.port,
                query.finish()
            ))
        }
        Credentials::Tuic {
            user_id,
            password,
            server_name,
            ..
        } => {
            let mut query = Serializer::new(String::new());
            query
                .append_pair("congestion_control", "bbr")
                .append_pair("alpn", "h3")
                .append_pair("sni", server_name);
            if profile.self_signed_certificate {
                query
                    .append_pair("insecure", "1")
                    .append_pair("allowInsecure", "1");
            }
            Ok(format!(
                "tuic://{user_id}:{}@{host}:{}?{}#{fragment}",
                encode(password),
                profile.port,
                query.finish()
            ))
        }
        Credentials::Shadowsocks {
            cipher, password, ..
        } => {
            let auth = URL_SAFE_NO_PAD.encode(format!("{}:{password}", cipher.client_name()));
            Ok(format!("ss://{auth}@{host}:{}#{fragment}", profile.port))
        }
        Credentials::AnyTls {
            users,
            server_name,
            security,
            ..
        } => {
            let password = single_anytls_password(users)?;
            if matches!(security, config::AnyTlsSecurity::Reality { .. }) {
                bail!("Nekobox/标准 AnyTLS URI 不支持 Reality 参数，请改用 sing-box 导出");
            }
            let mut query = Serializer::new(String::new());
            query.append_pair("sni", server_name);
            if profile.self_signed_certificate {
                query
                    .append_pair("insecure", "1")
                    .append_pair("allowInsecure", "1");
            }
            Ok(format!(
                "anytls://{}@{host}:{}/?{}#{fragment}",
                encode(password),
                profile.port,
                query.finish()
            ))
        }
        Credentials::VlessTls {
            user_id,
            server_name,
            vision,
            websocket_path,
            ..
        } => {
            let mut query = Serializer::new(String::new());
            query.append_pair("encryption", "none");
            if *vision {
                query.append_pair("flow", "xtls-rprx-vision");
            }
            query
                .append_pair("security", "tls")
                .append_pair("sni", server_name)
                .append_pair("fp", config::REALITY_FINGERPRINT);
            if profile.self_signed_certificate {
                query
                    .append_pair("insecure", "1")
                    .append_pair("allowInsecure", "1");
            }
            if let Some(path) = websocket_path {
                query
                    .append_pair("type", "ws")
                    .append_pair("host", server_name)
                    .append_pair("path", path);
            } else {
                query.append_pair("type", "tcp");
            }
            Ok(format!(
                "vless://{user_id}@{host}:{}?{}#{fragment}",
                profile.port,
                query.finish()
            ))
        }
        Credentials::Trojan {
            password,
            server_name,
            security,
            ..
        } => {
            let mut query = Serializer::new(String::new());
            match security {
                config::TlsSecurity::Tls => {
                    query.append_pair("security", "tls");
                    if profile.self_signed_certificate {
                        query
                            .append_pair("insecure", "1")
                            .append_pair("allowInsecure", "1");
                    }
                }
                config::TlsSecurity::Reality {
                    public_key,
                    short_id,
                    ..
                } => {
                    query
                        .append_pair("security", "reality")
                        .append_pair("pbk", public_key)
                        .append_pair("sid", short_id);
                }
            }
            query
                .append_pair("sni", server_name)
                .append_pair("fp", config::REALITY_FINGERPRINT)
                .append_pair("type", "tcp");
            Ok(format!(
                "trojan://{}@{host}:{}?{}#{fragment}",
                encode(password),
                profile.port,
                query.finish()
            ))
        }
        Credentials::VmessTls {
            user_id,
            server_name,
            alpn_protocols,
            websocket_path,
        } => {
            let payload = json!({
                "v": 2,
                "ps": profile.name,
                "add": server,
                "port": profile.port,
                "id": user_id,
                "aid": 0,
                "scy": "auto",
                "net": "ws",
                "type": "none",
                "host": server_name,
                "path": websocket_path,
                "tls": "tls",
                "sni": server_name,
                "alpn": alpn_protocols.join(","),
                "fp": config::REALITY_FINGERPRINT,
                "insecure": if profile.self_signed_certificate { "1" } else { "0" }
            });
            let encoded =
                STANDARD.encode(serde_json::to_vec(&payload).context("序列化 VMess 分享链接失败")?);
            Ok(format!("vmess://{encoded}"))
        }
    }
}

pub fn normalize_server_address(server: &str) -> Result<String> {
    let value = server.trim();
    let value = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value);
    if value.is_empty() || value.len() > 253 || value.contains(char::is_whitespace) {
        bail!("客户端 server 地址无效");
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        if address.is_unspecified() || address.is_multicast() {
            bail!("客户端 server 地址不能是未指定或组播地址");
        }
        return Ok(address.to_string());
    }
    if !value.contains('.')
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        bail!("客户端 server 地址必须是公网 IP 或有效域名");
    }
    Ok(value.to_ascii_lowercase())
}

fn single_anytls_password(users: &[config::AnyTlsUser]) -> Result<&str> {
    match users {
        [user] => Ok(user.password.as_str()),
        [] => bail!("AnyTLS 配置没有可导出的用户"),
        users => bail!(
            "AnyTLS 配置包含 {} 个用户；单节点客户端配置只能使用一个密码，拒绝静默选择用户。请为每个用户分别创建客户端节点",
            users.len()
        ),
    }
}

fn authority_host(server: &str) -> String {
    if server.contains(':') && !(server.starts_with('[') && server.ends_with(']')) {
        format!("[{server}]")
    } else {
        server.to_owned()
    }
}

fn encode(value: &str) -> String {
    byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AnyTlsSecurity, AnyTlsUser, Credentials, ShadowsocksCipher, TlsSecurity};

    fn reality_profile() -> ManagedProfile {
        ManagedProfile {
            id: Uuid::nil(),
            name: "reality-test".to_owned(),
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
        }
    }

    #[test]
    fn exports_reality_to_all_formats_without_private_key() {
        let profile = reality_profile();
        for format in [
            ClientFormat::ClashMeta,
            ClientFormat::SingBox,
            ClientFormat::Nekobox,
        ] {
            let output = render(&profile, format, "203.0.113.1").unwrap();
            assert!(output.contains("public"));
            assert!(!output.contains("private"));
        }
    }

    #[test]
    fn stored_reality_uri_contains_all_v2rayn_reality_parameters() {
        let mut profile = reality_profile();
        profile.port = 28101;
        profile.server_address = Some("203.0.113.8".to_owned());
        let uri = stored_share_uri(&profile, None).unwrap();
        assert!(uri.starts_with("vless://00000000-0000-0000-0000-000000000000@203.0.113.8:28101?"));
        for parameter in [
            "encryption=none",
            "flow=xtls-rprx-vision",
            "security=reality",
            "sni=www.cloudflare.com",
            "fp=chrome",
            "pbk=public",
            "sid=0123456789abcdef",
            "type=tcp",
        ] {
            assert!(uri.contains(parameter), "missing {parameter}: {uri}");
        }
        assert!(
            uri.ends_with("#VLESS-REALITY-28101"),
            "unexpected profile label: {uri}"
        );
        assert!(!uri.contains("private"));
    }

    #[test]
    fn exports_new_presets_to_all_client_formats() {
        let base =
            |name: &str, credentials: Credentials, self_signed_certificate: bool| ManagedProfile {
                id: Uuid::new_v4(),
                name: name.to_owned(),
                port: 443,
                server_address: None,
                credentials,
                certificate_path: None,
                certificate_key_path: None,
                self_signed_certificate,
            };
        let profiles = [
            base(
                "vless-tls",
                Credentials::VlessTls {
                    user_id: Uuid::nil(),
                    server_name: "tls.example.com".to_owned(),
                    alpn_protocols: vec!["h2".to_owned(), "http/1.1".to_owned()],
                    vision: true,
                    websocket_path: None,
                },
                true,
            ),
            base(
                "vless-ws",
                Credentials::VlessTls {
                    user_id: Uuid::nil(),
                    server_name: "ws.example.com".to_owned(),
                    alpn_protocols: vec!["http/1.1".to_owned()],
                    vision: false,
                    websocket_path: Some("/vless".to_owned()),
                },
                true,
            ),
            base(
                "trojan-tls",
                Credentials::Trojan {
                    password: "trojan-secret".to_owned(),
                    server_name: "trojan.example.com".to_owned(),
                    alpn_protocols: vec!["h2".to_owned(), "http/1.1".to_owned()],
                    security: TlsSecurity::Tls,
                },
                true,
            ),
            base(
                "trojan-reality",
                Credentials::Trojan {
                    password: "trojan-reality-secret".to_owned(),
                    server_name: "www.cloudflare.com".to_owned(),
                    alpn_protocols: Vec::new(),
                    security: TlsSecurity::Reality {
                        private_key: "must-not-export".to_owned(),
                        public_key: "public-key".to_owned(),
                        short_id: "0123456789abcdef".to_owned(),
                    },
                },
                false,
            ),
            base(
                "vmess-ws",
                Credentials::VmessTls {
                    user_id: Uuid::nil(),
                    server_name: "vmess.example.com".to_owned(),
                    alpn_protocols: vec!["http/1.1".to_owned()],
                    websocket_path: "/vmess".to_owned(),
                },
                true,
            ),
        ];

        for profile in &profiles {
            for format in [
                ClientFormat::ClashMeta,
                ClientFormat::SingBox,
                ClientFormat::Nekobox,
            ] {
                let output = render(profile, format, "203.0.113.10").unwrap();
                assert!(!output.contains("must-not-export"));
                assert!(!output.is_empty());
            }
        }

        let vless_ws = share_uri(&profiles[1], "203.0.113.10").unwrap();
        for marker in [
            "security=tls",
            "type=ws",
            "path=%2Fvless",
            "allowInsecure=1",
        ] {
            assert!(vless_ws.contains(marker), "missing {marker}: {vless_ws}");
        }
        let trojan_reality = share_uri(&profiles[3], "203.0.113.10").unwrap();
        for marker in ["security=reality", "pbk=public-key", "sid=0123456789abcdef"] {
            assert!(
                trojan_reality.contains(marker),
                "missing {marker}: {trojan_reality}"
            );
        }
        let vmess = share_uri(&profiles[4], "203.0.113.10").unwrap();
        let payload = STANDARD
            .decode(vmess.trim_start_matches("vmess://"))
            .unwrap();
        let payload: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["net"], "ws");
        assert_eq!(payload["path"], "/vmess");
        assert_eq!(payload["insecure"], "1");
    }

    #[test]
    fn profile_selection_accepts_name_or_uuid_and_requires_disambiguation() {
        let first = reality_profile();
        let mut second = reality_profile();
        second.id = Uuid::new_v4();
        second.name = "Second".to_owned();
        let profiles = vec![first, second.clone()];
        assert_eq!(
            select_profile(&profiles, Some("second")).unwrap().id,
            second.id
        );
        assert_eq!(
            select_profile(&profiles, Some(&second.id.to_string()))
                .unwrap()
                .id,
            second.id
        );
        assert!(select_profile(&profiles, None).is_err());

        let mut duplicate = second.clone();
        duplicate.id = Uuid::new_v4();
        duplicate.name = "SECOND".to_owned();
        let duplicates = vec![second, duplicate.clone()];
        assert!(select_profile(&duplicates, Some("second")).is_err());
        assert_eq!(
            select_profile(&duplicates, Some(&duplicate.id.to_string()))
                .unwrap()
                .id,
            duplicate.id
        );
    }

    #[test]
    fn normalizes_domains_ipv6_and_local_test_addresses() {
        assert_eq!(
            normalize_server_address(" EXAMPLE.COM ").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_server_address("[2001:db8::1]").unwrap(),
            "2001:db8::1"
        );
        assert_eq!(normalize_server_address("127.0.0.1").unwrap(), "127.0.0.1");
        assert!(normalize_server_address("not-a-domain").is_err());
    }

    #[test]
    fn wraps_ipv6_authority() {
        let output = render(&reality_profile(), ClientFormat::Nekobox, "2001:db8::1").unwrap();
        assert!(output.contains("@[2001:db8::1]:443"));
    }

    #[test]
    fn exports_hysteria2_self_signed_warning_flag() {
        let profile = ManagedProfile {
            id: Uuid::nil(),
            name: "hy2".to_owned(),
            port: 8443,
            server_address: None,
            credentials: Credentials::Hysteria2 {
                password: "secret".to_owned(),
                server_name: "proxy.example.com".to_owned(),
                alpn_protocols: vec!["h3".to_owned()],
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: true,
        };
        let clash = render(&profile, ClientFormat::ClashMeta, "203.0.113.2").unwrap();
        let sing_box = render(&profile, ClientFormat::SingBox, "203.0.113.2").unwrap();
        assert!(clash.contains("skip-cert-verify: true"));
        assert!(sing_box.contains("\"insecure\": true"));
    }

    #[test]
    fn self_signed_share_uris_include_v2rayn_insecure_flags() {
        let hysteria2 = ManagedProfile {
            id: Uuid::nil(),
            name: "hy2".to_owned(),
            port: 443,
            server_address: None,
            credentials: Credentials::Hysteria2 {
                password: "secret".to_owned(),
                server_name: "proxy.example.com".to_owned(),
                alpn_protocols: vec!["h3".to_owned()],
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: true,
        };
        let tuic = ManagedProfile {
            id: Uuid::nil(),
            name: "tuic".to_owned(),
            port: 443,
            server_address: None,
            credentials: Credentials::Tuic {
                user_id: Uuid::nil(),
                password: "secret".to_owned(),
                server_name: "proxy.example.com".to_owned(),
                alpn_protocols: vec!["h3".to_owned()],
                zero_rtt_handshake: false,
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: true,
        };
        for uri in [
            share_uri(&hysteria2, "203.0.113.2").unwrap(),
            share_uri(&tuic, "203.0.113.3").unwrap(),
            share_uri(&anytls_profile(AnyTlsSecurity::Tls), "203.0.113.5").unwrap(),
        ] {
            assert!(uri.contains("insecure=1"), "missing insecure flag: {uri}");
            assert!(
                uri.contains("allowInsecure=1"),
                "missing v2rayN allowInsecure flag: {uri}"
            );
        }
        let hysteria2_uri = share_uri(&hysteria2, "203.0.113.2").unwrap();
        assert!(hysteria2_uri.contains("alpn=h3"));
    }

    #[test]
    fn exports_tuic_required_fields() {
        let profile = ManagedProfile {
            id: Uuid::nil(),
            name: "tuic".to_owned(),
            port: 443,
            server_address: None,
            credentials: Credentials::Tuic {
                user_id: Uuid::nil(),
                password: "secret".to_owned(),
                server_name: "proxy.example.com".to_owned(),
                alpn_protocols: vec!["h3".to_owned()],
                zero_rtt_handshake: false,
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };
        let clash = render(&profile, ClientFormat::ClashMeta, "203.0.113.3").unwrap();
        let sing_box = render(&profile, ClientFormat::SingBox, "203.0.113.3").unwrap();
        assert!(clash.contains("congestion-controller: bbr"));
        assert!(sing_box.contains("\"congestion_control\": \"bbr\""));
    }

    #[test]
    fn exports_shadowsocks_to_parseable_formats() {
        let profile = ManagedProfile {
            id: Uuid::nil(),
            name: "ss-2022".to_owned(),
            port: 8388,
            server_address: None,
            credentials: Credentials::Shadowsocks {
                cipher: ShadowsocksCipher::Chacha20IetfPoly13052022,
                password: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
                udp_enabled: true,
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };
        let clash = render(&profile, ClientFormat::ClashMeta, "203.0.113.4").unwrap();
        let sing_box = render(&profile, ClientFormat::SingBox, "203.0.113.4").unwrap();
        let uri = render(&profile, ClientFormat::Nekobox, "203.0.113.4").unwrap();
        let clash_value: serde_yaml::Value = serde_yaml::from_str(&clash).unwrap();
        let sing_value: Value = serde_json::from_str(&sing_box).unwrap();
        assert!(clash_value.is_mapping());
        assert!(sing_value.is_object());
        assert!(clash.contains("2022-blake3-chacha20-poly1305"));
        assert!(sing_box.contains("2022-blake3-chacha20-poly1305"));
        assert!(uri.starts_with("ss://"));
    }

    fn anytls_profile(security: AnyTlsSecurity) -> ManagedProfile {
        ManagedProfile {
            id: Uuid::nil(),
            name: "anytls-test".to_owned(),
            port: 443,
            server_address: None,
            credentials: Credentials::AnyTls {
                users: vec![AnyTlsUser {
                    name: "alice".to_owned(),
                    password: "anytls-secret".to_owned(),
                }],
                server_name: "proxy.example.com".to_owned(),
                alpn_protocols: vec!["h2".to_owned(), "http/1.1".to_owned()],
                udp_enabled: true,
                security,
            },
            certificate_path: Some("/etc/shoes/server.pem".into()),
            certificate_key_path: Some("/etc/shoes/server-private.pem".into()),
            self_signed_certificate: true,
        }
    }

    #[test]
    fn exports_anytls_tls_and_rejects_unsupported_reality_formats() {
        let tls = anytls_profile(AnyTlsSecurity::Tls);
        let clash = render(&tls, ClientFormat::ClashMeta, "203.0.113.5").unwrap();
        let sing_box = render(&tls, ClientFormat::SingBox, "203.0.113.5").unwrap();
        let uri = render(&tls, ClientFormat::Nekobox, "203.0.113.5").unwrap();
        serde_yaml::from_str::<serde_yaml::Value>(&clash).unwrap();
        serde_json::from_str::<Value>(&sing_box).unwrap();
        url::Url::parse(&uri).unwrap();
        assert!(uri.contains("sni=proxy.example.com"));
        assert!(!clash.contains("server-private"));
        assert!(!sing_box.contains("server-private"));

        let reality = anytls_profile(AnyTlsSecurity::Reality {
            private_key: "never-export-this-private-key".to_owned(),
            public_key: "public-key".to_owned(),
            short_id: "0123456789abcdef".to_owned(),
        });
        assert!(render(&reality, ClientFormat::ClashMeta, "203.0.113.5").is_err());
        assert!(render(&reality, ClientFormat::Nekobox, "203.0.113.5").is_err());
        let sing_box = render(&reality, ClientFormat::SingBox, "203.0.113.5").unwrap();
        serde_json::from_str::<Value>(&sing_box).unwrap();
        assert!(sing_box.contains("public-key"));
        assert!(!sing_box.contains("never-export-this-private-key"));
    }

    #[test]
    fn rejects_multi_user_anytls_exports_without_silent_selection() {
        let mut profile = anytls_profile(AnyTlsSecurity::Tls);
        let Credentials::AnyTls { users, .. } = &mut profile.credentials else {
            unreachable!("test profile is AnyTLS");
        };
        users.push(AnyTlsUser {
            name: "bob".to_owned(),
            password: "second-secret".to_owned(),
        });

        for format in [
            ClientFormat::ClashMeta,
            ClientFormat::SingBox,
            ClientFormat::Nekobox,
        ] {
            let error = render(&profile, format, "203.0.113.5").unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("2 个用户"), "{format:?}: {message}");
            assert!(
                message.contains("拒绝静默选择用户"),
                "{format:?}: {message}"
            );
        }
    }
}
