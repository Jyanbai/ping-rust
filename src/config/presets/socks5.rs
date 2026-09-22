use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{
        direct_rules, generated_password, generated_socks5_username, Credentials, ServerConfig,
        ServerProtocol,
    },
    GeneratedPreset, GenerationRequest,
};

pub(super) fn generate(
    request: &GenerationRequest,
    _parent: &Path,
    _profile_id: Uuid,
) -> Result<GeneratedPreset> {
    let (username, password) = if request.options.socks5_no_auth {
        (None, None)
    } else {
        (
            Some(
                request
                    .options
                    .socks5_username
                    .clone()
                    .unwrap_or_else(generated_socks5_username),
            ),
            Some(
                request
                    .options
                    .socks5_password
                    .clone()
                    .unwrap_or_else(generated_password),
            ),
        )
    };
    Ok(GeneratedPreset {
        server: ServerConfig {
            address: format!("0.0.0.0:{}", request.port),
            transport: None,
            quic_settings: None,
            protocol: ServerProtocol::Socks {
                username: username.clone(),
                password: password.clone(),
                udp_enabled: request.options.udp_enabled,
            },
            rules: direct_rules(),
        },
        credentials: Credentials::Socks5 {
            username,
            password,
            udp_enabled: request.options.udp_enabled,
        },
        certificate_path: None,
        certificate_key_path: None,
    })
}
