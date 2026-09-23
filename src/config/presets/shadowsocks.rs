use std::{collections::BTreeMap, path::Path};

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{
        direct_rules, generate_shadowsocks_password, generated_password, Credentials,
        InnerProtocol, ServerConfig, ServerProtocol, ShadowTlsCredentials, ShadowTlsHandshake,
        ShadowTlsTarget, ShadowsocksMode,
    },
    GeneratedPreset, GenerationRequest,
};

pub(super) fn generate(
    request: &GenerationRequest,
    _parent: &Path,
    _profile_id: Uuid,
) -> Result<GeneratedPreset> {
    let cipher = request.options.shadowsocks_cipher;
    let password = request
        .options
        .shadowsocks_password
        .clone()
        .unwrap_or_else(|| generate_shadowsocks_password(cipher));
    if request.options.shadowsocks_mode == ShadowsocksMode::ShadowTlsV3 {
        let shadowtls_password = request
            .options
            .shadowtls_password
            .clone()
            .unwrap_or_else(generated_password);
        let handshake_address = request
            .options
            .shadowtls_handshake
            .clone()
            .unwrap_or_else(|| format!("{}:443", request.server_name));
        let shadowtls = ShadowTlsCredentials {
            password: shadowtls_password.clone(),
            server_name: request.server_name.clone(),
            handshake_address: handshake_address.clone(),
        };
        let mut shadowtls_targets = BTreeMap::new();
        shadowtls_targets.insert(
            request.server_name.clone(),
            ShadowTlsTarget {
                password: shadowtls_password,
                handshake: ShadowTlsHandshake {
                    address: handshake_address,
                },
                protocol: InnerProtocol::Shadowsocks {
                    cipher: cipher.as_str().to_owned(),
                    password: password.clone(),
                    udp_enabled: false,
                },
            },
        );
        return Ok(GeneratedPreset {
            server: ServerConfig {
                address: format!("0.0.0.0:{}", request.port),
                transport: None,
                quic_settings: None,
                protocol: ServerProtocol::Tls {
                    tls_targets: BTreeMap::new(),
                    shadowtls_targets,
                    reality_targets: BTreeMap::new(),
                },
                rules: direct_rules(),
            },
            credentials: Credentials::Shadowsocks {
                cipher,
                password,
                udp_enabled: false,
                shadowtls: Some(shadowtls),
            },
            certificate_path: None,
            certificate_key_path: None,
        });
    }
    Ok(GeneratedPreset {
        server: ServerConfig {
            address: format!("0.0.0.0:{}", request.port),
            transport: None,
            quic_settings: None,
            protocol: ServerProtocol::Shadowsocks {
                cipher: cipher.as_str().to_owned(),
                password: password.clone(),
                udp_enabled: request.options.udp_enabled,
            },
            rules: direct_rules(),
        },
        credentials: Credentials::Shadowsocks {
            cipher,
            password,
            udp_enabled: request.options.udp_enabled,
            shadowtls: None,
        },
        certificate_path: None,
        certificate_key_path: None,
    })
}
