use std::path::Path;

use anyhow::{bail, Context, Result};
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
    if server.trim().is_empty() || server.contains(char::is_whitespace) {
        bail!("客户端 server 地址无效");
    }
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

pub fn render(profile: &ManagedProfile, format: ClientFormat, server: &str) -> Result<String> {
    match format {
        ClientFormat::ClashMeta => clash_meta(profile, server),
        ClientFormat::SingBox => sing_box(profile, server),
        ClientFormat::Nekobox => Ok(share_uri(profile, server)),
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
            "client-fingerprint": "chrome",
            "reality-opts": { "public-key": public_key, "short-id": short_id }
        }),
        Credentials::Hysteria2 {
            password,
            server_name,
        } => json!({
            "name": profile.name,
            "type": "hysteria2",
            "server": server,
            "port": profile.port,
            "password": password,
            "sni": server_name,
            "skip-cert-verify": profile.self_signed_certificate
        }),
        Credentials::Tuic {
            user_id,
            password,
            server_name,
        } => json!({
            "name": profile.name,
            "type": "tuic",
            "server": server,
            "port": profile.port,
            "uuid": user_id,
            "password": password,
            "sni": server_name,
            "alpn": ["h3"],
            "congestion-controller": "bbr",
            "udp-relay-mode": "native",
            "skip-cert-verify": profile.self_signed_certificate
        }),
    };
    serde_yaml::to_string(&json!({ "proxies": [proxy] })).context("生成 Clash Meta YAML 失败")
}

fn sing_box(profile: &ManagedProfile, server: &str) -> Result<String> {
    let tls = |server_name: &str, insecure: bool| {
        json!({
            "enabled": true,
            "server_name": server_name,
            "insecure": insecure
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
                "utls": { "enabled": true, "fingerprint": "chrome" },
                "reality": { "enabled": true, "public_key": public_key, "short_id": short_id }
            }
        }),
        Credentials::Hysteria2 {
            password,
            server_name,
        } => json!({
            "type": "hysteria2",
            "tag": profile.name,
            "server": server,
            "server_port": profile.port,
            "password": password,
            "tls": tls(server_name, profile.self_signed_certificate)
        }),
        Credentials::Tuic {
            user_id,
            password,
            server_name,
        } => json!({
            "type": "tuic",
            "tag": profile.name,
            "server": server,
            "server_port": profile.port,
            "uuid": user_id,
            "password": password,
            "congestion_control": "bbr",
            "tls": tls(server_name, profile.self_signed_certificate)
        }),
    };
    serde_json::to_string_pretty(&json!({ "outbounds": [outbound] }))
        .context("生成 sing-box JSON 失败")
}

fn share_uri(profile: &ManagedProfile, server: &str) -> String {
    let host = authority_host(server);
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
                .append_pair("fp", "chrome")
                .append_pair("pbk", public_key)
                .append_pair("sid", short_id)
                .append_pair("type", "tcp");
            format!(
                "vless://{user_id}@{host}:{}?{}#{fragment}",
                profile.port,
                query.finish()
            )
        }
        Credentials::Hysteria2 {
            password,
            server_name,
        } => {
            let mut query = Serializer::new(String::new());
            query.append_pair("sni", server_name);
            if profile.self_signed_certificate {
                query.append_pair("insecure", "1");
            }
            format!(
                "hysteria2://{}@{host}:{}?{}#{fragment}",
                encode(password),
                profile.port,
                query.finish()
            )
        }
        Credentials::Tuic {
            user_id,
            password,
            server_name,
        } => {
            let mut query = Serializer::new(String::new());
            query
                .append_pair("congestion_control", "bbr")
                .append_pair("alpn", "h3")
                .append_pair("sni", server_name);
            if profile.self_signed_certificate {
                query.append_pair("allow_insecure", "1");
            }
            format!(
                "tuic://{user_id}:{}@{host}:{}?{}#{fragment}",
                encode(password),
                profile.port,
                query.finish()
            )
        }
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
    use crate::config::Credentials;

    fn reality_profile() -> ManagedProfile {
        ManagedProfile {
            id: Uuid::nil(),
            name: "reality-test".to_owned(),
            port: 443,
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
            credentials: Credentials::Hysteria2 {
                password: "secret".to_owned(),
                server_name: "proxy.example.com".to_owned(),
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
    fn exports_tuic_required_fields() {
        let profile = ManagedProfile {
            id: Uuid::nil(),
            name: "tuic".to_owned(),
            port: 443,
            credentials: Credentials::Tuic {
                user_id: Uuid::nil(),
                password: "secret".to_owned(),
                server_name: "proxy.example.com".to_owned(),
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
}
