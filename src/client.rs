use std::{net::IpAddr, path::Path};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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
            if matches!(security, config::AnyTlsSecurity::Reality { .. }) {
                bail!("Clash Meta 不支持 AnyTLS+Reality，请改用 sing-box 导出");
            }
            json!({
                "name": profile.name,
                "type": "anytls",
                "server": server,
                "port": profile.port,
                "password": first_anytls_password(users)?,
                "client-fingerprint": config::REALITY_FINGERPRINT,
                "udp": udp_enabled,
                "sni": server_name,
                "alpn": alpn_protocols,
                "skip-cert-verify": profile.self_signed_certificate
            })
        }
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
                "password": first_anytls_password(users)?,
                "tls": tls
            })
        }
    };
    serde_json::to_string_pretty(&json!({ "outbounds": [outbound] }))
        .context("生成 sing-box JSON 失败")
}

pub fn share_uri(profile: &ManagedProfile, server: &str) -> Result<String> {
    let server = normalize_server_address(server)?;
    let host = authority_host(&server);
    let fragment = encode(&profile.name);
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
                encode(first_anytls_password(users)?),
                profile.port,
                query.finish()
            ))
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

fn first_anytls_password(users: &[config::AnyTlsUser]) -> Result<&str> {
    users
        .first()
        .map(|user| user.password.as_str())
        .context("AnyTLS 配置没有可导出的用户")
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
    use crate::config::{AnyTlsSecurity, AnyTlsUser, Credentials, ShadowsocksCipher};

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
        profile.server_address = Some("203.0.113.8".to_owned());
        let uri = stored_share_uri(&profile, None).unwrap();
        assert!(uri.starts_with("vless://00000000-0000-0000-0000-000000000000@203.0.113.8:443?"));
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
        assert!(!uri.contains("private"));
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
}
