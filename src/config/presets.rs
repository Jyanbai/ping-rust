use std::path::{Path, PathBuf};

use anyhow::Result;
use uuid::Uuid;

use super::{Credentials, GenerationRequest, Protocol, ServerConfig};

mod anytls;
mod hysteria2;
mod reality;
mod shadowsocks;
mod tls;
mod trojan_reality;
mod trojan_tls;
mod tuic;
mod vless_tls_vision;
mod vless_ws_tls;
mod vmess_ws_tls;

type Generator = fn(&GenerationRequest, &Path, Uuid) -> Result<GeneratedPreset>;

pub(super) struct PresetDescriptor {
    pub protocol: Protocol,
    pub menu_number: usize,
    pub menu_label: &'static str,
    pub advanced_label: &'static str,
    pub slug: &'static str,
    pub display_prefix: &'static str,
    pub tcp_required: bool,
    pub udp_required: bool,
    generator: Generator,
}

pub(super) struct GeneratedPreset {
    pub server: ServerConfig,
    pub credentials: Credentials,
    pub certificate_path: Option<PathBuf>,
    pub certificate_key_path: Option<PathBuf>,
}

const PRESETS: &[PresetDescriptor] = &[
    PresetDescriptor {
        protocol: Protocol::Tuic,
        menu_number: 1,
        menu_label: "TUIC",
        advanced_label: "TUIC v5",
        slug: "tuic",
        display_prefix: "TUIC",
        tcp_required: false,
        udp_required: true,
        generator: tuic::generate,
    },
    PresetDescriptor {
        protocol: Protocol::Hysteria2,
        menu_number: 2,
        menu_label: "Hysteria2",
        advanced_label: "Hysteria2",
        slug: "hysteria2",
        display_prefix: "HYSTERIA2",
        tcp_required: false,
        udp_required: true,
        generator: hysteria2::generate,
    },
    PresetDescriptor {
        protocol: Protocol::Shadowsocks,
        menu_number: 3,
        menu_label: "Shadowsocks",
        advanced_label: "Shadowsocks 2022",
        slug: "shadowsocks",
        display_prefix: "SHADOWSOCKS",
        tcp_required: true,
        udp_required: true,
        generator: shadowsocks::generate,
    },
    PresetDescriptor {
        protocol: Protocol::Reality,
        menu_number: 4,
        menu_label: "VLESS-REALITY（推荐）",
        advanced_label: "VLESS-Reality-Vision（推荐）",
        slug: "reality",
        display_prefix: "VLESS-REALITY",
        tcp_required: true,
        udp_required: false,
        generator: reality::generate,
    },
    PresetDescriptor {
        protocol: Protocol::AnyTls,
        menu_number: 5,
        menu_label: "AnyTLS",
        advanced_label: "AnyTLS",
        slug: "anytls",
        display_prefix: "ANYTLS",
        tcp_required: true,
        udp_required: false,
        generator: anytls::generate,
    },
    PresetDescriptor {
        protocol: Protocol::VlessTlsVision,
        menu_number: 6,
        menu_label: "VLESS-TLS-Vision",
        advanced_label: "VLESS-TLS-Vision",
        slug: "vless-tls-vision",
        display_prefix: "VLESS-TLS-VISION",
        tcp_required: true,
        udp_required: false,
        generator: vless_tls_vision::generate,
    },
    PresetDescriptor {
        protocol: Protocol::VlessWsTls,
        menu_number: 7,
        menu_label: "VLESS-WS-TLS",
        advanced_label: "VLESS-WS-TLS",
        slug: "vless-ws-tls",
        display_prefix: "VLESS-WS-TLS",
        tcp_required: true,
        udp_required: false,
        generator: vless_ws_tls::generate,
    },
    PresetDescriptor {
        protocol: Protocol::TrojanTls,
        menu_number: 8,
        menu_label: "Trojan-TLS",
        advanced_label: "Trojan-TLS",
        slug: "trojan-tls",
        display_prefix: "TROJAN-TLS",
        tcp_required: true,
        udp_required: false,
        generator: trojan_tls::generate,
    },
    PresetDescriptor {
        protocol: Protocol::TrojanReality,
        menu_number: 9,
        menu_label: "Trojan-REALITY",
        advanced_label: "Trojan-REALITY",
        slug: "trojan-reality",
        display_prefix: "TROJAN-REALITY",
        tcp_required: true,
        udp_required: false,
        generator: trojan_reality::generate,
    },
    PresetDescriptor {
        protocol: Protocol::VmessWsTls,
        menu_number: 10,
        menu_label: "VMess-WS-TLS",
        advanced_label: "VMess-WS-TLS",
        slug: "vmess-ws-tls",
        display_prefix: "VMESS-WS-TLS",
        tcp_required: true,
        udp_required: false,
        generator: vmess_ws_tls::generate,
    },
];

pub(super) fn all() -> &'static [PresetDescriptor] {
    PRESETS
}

pub(super) fn descriptor(protocol: Protocol) -> &'static PresetDescriptor {
    PRESETS
        .iter()
        .find(|preset| preset.protocol == protocol)
        .expect("every Protocol variant must have one preset descriptor")
}

pub(super) fn from_menu_number(number: usize) -> Option<Protocol> {
    PRESETS
        .iter()
        .find(|preset| preset.menu_number == number)
        .map(|preset| preset.protocol)
}

pub(super) fn generate(
    request: &GenerationRequest,
    parent: &Path,
    profile_id: Uuid,
) -> Result<GeneratedPreset> {
    (descriptor(request.protocol).generator)(request, parent, profile_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_one_contiguous_entry_for_every_protocol() {
        let expected = [
            Protocol::Tuic,
            Protocol::Hysteria2,
            Protocol::Shadowsocks,
            Protocol::Reality,
            Protocol::AnyTls,
            Protocol::VlessTlsVision,
            Protocol::VlessWsTls,
            Protocol::TrojanTls,
            Protocol::TrojanReality,
            Protocol::VmessWsTls,
        ];
        assert_eq!(PRESETS.len(), expected.len());
        for (index, (preset, protocol)) in PRESETS.iter().zip(expected).enumerate() {
            assert_eq!(preset.menu_number, index + 1);
            assert_eq!(preset.protocol, protocol);
            assert_eq!(from_menu_number(index + 1), Some(protocol));
            assert_eq!(descriptor(protocol).menu_number, index + 1);
        }
        assert_eq!(from_menu_number(0), None);
        assert_eq!(from_menu_number(PRESETS.len() + 1), None);
    }
}
