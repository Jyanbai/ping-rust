use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{direct_rules, Credentials, ServerConfig, ServerProtocol},
    GeneratedPreset, GenerationRequest,
};
use crate::vless_encryption::{self, CredentialPair};

pub(super) fn generate(
    request: &GenerationRequest,
    _parent: &Path,
    _id: Uuid,
) -> Result<GeneratedPreset> {
    let pair = vless_encryption::generate(
        request.options.vless_enc_mode,
        request.options.vless_enc_auth,
    )?;
    Ok(from_pair(request, pair))
}

pub(in crate::config) fn from_pair(
    request: &GenerationRequest,
    pair: CredentialPair,
) -> GeneratedPreset {
    let user_id = Uuid::new_v4();
    let protocol = ServerProtocol::Vless {
        user_id,
        udp_enabled: request.options.udp_enabled,
        decryption: pair.decryption,
        vision: request.options.vless_enc_vision,
    };
    let protocol = match &request.options.sudoku {
        Some(settings) => ServerProtocol::SudokuMask {
            settings: settings.clone(),
            protocol: Box::new(protocol),
        },
        None => protocol,
    };
    GeneratedPreset {
        server: ServerConfig {
            address: format!("0.0.0.0:{}", request.port),
            transport: None,
            quic_settings: None,
            rules: direct_rules(),
            protocol,
        },
        credentials: Credentials::VlessEnc {
            sudoku: request.options.sudoku.clone(),
            user_id,
            encryption: pair.encryption,
            mode: request.options.vless_enc_mode,
            auth: request.options.vless_enc_auth,
            vision: request.options.vless_enc_vision,
            udp_enabled: request.options.udp_enabled,
        },
        certificate_path: None,
        certificate_key_path: None,
        naive_certificate_validity: None,
    }
}
