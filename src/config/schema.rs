use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{AnyTlsUser, ShoesClientConfig};

pub(super) fn default_h3_alpn() -> Vec<String> {
    vec!["h3".to_owned()]
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ServerConfig {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quic_settings: Option<QuicSettings>,
    pub protocol: ServerProtocol,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ServerRule>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(super) enum ServerRule {
    Group(String),
    Inline(ChainRule),
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct ChainRule {
    pub masks: String,
    pub action: String,
    #[serde(rename = "client_chains", alias = "client_chain")]
    pub client_chains: ShoesClientConfig,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct QuicSettings {
    pub cert: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn_protocols: Vec<String>,
    #[serde(default)]
    pub num_endpoints: usize,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(super) enum ServerProtocol {
    Tls {
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        tls_targets: BTreeMap<String, TlsTarget>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        shadowtls_targets: BTreeMap<String, ShadowTlsTarget>,
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
    Socks {
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        udp_enabled: bool,
    },
    Snell {
        cipher: String,
        password: String,
        udp_enabled: bool,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct TlsTarget {
    pub cert: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn_protocols: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub vision: bool,
    pub protocol: InnerProtocol,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct RealityTarget {
    pub private_key: String,
    pub short_ids: Vec<String>,
    pub dest: String,
    pub max_time_diff: u64,
    pub vision: bool,
    pub protocol: InnerProtocol,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(super) enum InnerProtocol {
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
    #[serde(rename = "naiveproxy")]
    Naiveproxy {
        users: Vec<NaiveUser>,
        padding: bool,
        udp_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        fallback: Option<String>,
    },
    Trojan {
        password: String,
    },
    Vmess {
        cipher: String,
        user_id: Uuid,
        udp_enabled: bool,
    },
    Shadowsocks {
        cipher: String,
        password: String,
        udp_enabled: bool,
    },
    #[serde(rename = "websocket")]
    Websocket {
        targets: Vec<WebsocketTarget>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct NaiveUser {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ShadowTlsTarget {
    pub password: String,
    pub handshake: ShadowTlsHandshake,
    pub protocol: InnerProtocol,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ShadowTlsHandshake {
    pub address: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct WebsocketTarget {
    pub matching_path: String,
    pub protocol: InnerProtocol,
}
