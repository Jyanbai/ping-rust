use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{
        direct_rules, generate_shadowsocks_password, Credentials, ServerConfig, ServerProtocol,
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
        },
        certificate_path: None,
        certificate_key_path: None,
    })
}
