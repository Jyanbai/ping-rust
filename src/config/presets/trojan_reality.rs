use std::{collections::BTreeMap, path::Path};

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{
        generate_reality_keypair, generated_password, random_hex, Credentials, InnerProtocol,
        RealityTarget, ServerConfig, ServerProtocol, TlsSecurity,
    },
    GeneratedPreset, GenerationRequest,
};

pub(super) fn generate(
    request: &GenerationRequest,
    _parent: &Path,
    _profile_id: Uuid,
) -> Result<GeneratedPreset> {
    let keypair = generate_reality_keypair();
    let short_id = request
        .options
        .reality_short_id
        .clone()
        .unwrap_or_else(|| random_hex(8));
    let password = generated_password();
    let mut reality_targets = BTreeMap::new();
    reality_targets.insert(
        request.server_name.clone(),
        RealityTarget {
            private_key: keypair.private_key.clone(),
            short_ids: vec![short_id.clone()],
            dest: request
                .reality_dest
                .clone()
                .unwrap_or_else(|| format!("{}:443", request.server_name)),
            max_time_diff: request.options.reality_max_time_diff,
            vision: false,
            protocol: InnerProtocol::Trojan {
                password: password.clone(),
            },
        },
    );

    Ok(GeneratedPreset {
        server: ServerConfig {
            address: format!("0.0.0.0:{}", request.port),
            transport: None,
            quic_settings: None,
            protocol: ServerProtocol::Tls {
                tls_targets: BTreeMap::new(),
                shadowtls_targets: BTreeMap::new(),
                reality_targets,
            },
            rules: Vec::new(),
        },
        credentials: Credentials::Trojan {
            password,
            server_name: request.server_name.clone(),
            alpn_protocols: Vec::new(),
            security: TlsSecurity::Reality {
                private_key: keypair.private_key,
                public_key: keypair.public_key,
                short_id,
            },
        },
        certificate_path: None,
        certificate_key_path: None,
    })
}
