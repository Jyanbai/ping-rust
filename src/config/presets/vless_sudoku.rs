use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{direct_rules, Credentials, ServerConfig, ServerProtocol},
    GeneratedPreset, GenerationRequest,
};

pub(super) fn generate(
    request: &GenerationRequest,
    _parent: &Path,
    _id: Uuid,
) -> Result<GeneratedPreset> {
    let user_id = Uuid::new_v4();
    let sudoku = request
        .options
        .sudoku
        .clone()
        .unwrap_or_else(crate::sudoku::SudokuConfig::generated);
    sudoku.validate()?;
    Ok(GeneratedPreset {
        server: ServerConfig {
            address: format!("0.0.0.0:{}", request.port),
            transport: None,
            quic_settings: None,
            protocol: ServerProtocol::SudokuMask {
                settings: sudoku.clone(),
                protocol: Box::new(ServerProtocol::Vless {
                    user_id,
                    udp_enabled: request.options.udp_enabled,
                    decryption: String::new(),
                    vision: false,
                }),
            },
            rules: direct_rules(),
        },
        credentials: Credentials::VlessSudoku {
            user_id,
            sudoku,
            udp_enabled: request.options.udp_enabled,
        },
        certificate_path: None,
        certificate_key_path: None,
        naive_certificate_validity: None,
    })
}
