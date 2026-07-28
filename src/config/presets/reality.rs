use std::{collections::BTreeMap, path::Path};

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{
        generate_reality_keypair, random_hex, Credentials, InnerProtocol, RealityTarget,
        ServerConfig, ServerProtocol,
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
    let user_id = Uuid::new_v4();
    let destination = request
        .reality_dest
        .clone()
        .unwrap_or_else(|| format!("{}:443", request.server_name));
    let target = RealityTarget {
        private_key: keypair.private_key.clone(),
        short_ids: vec![short_id.clone()],
        dest: destination,
        max_time_diff: request.options.reality_max_time_diff,
        vision: true,
        protocol: InnerProtocol::Vless {
            user_id,
            udp_enabled: request.options.udp_enabled,
        },
    };
    let mut reality_targets = BTreeMap::new();
    reality_targets.insert(request.server_name.clone(), target);

    Ok(GeneratedPreset {
        server: ServerConfig {
            address: format!("0.0.0.0:{}", request.port),
            transport: None,
            quic_settings: None,
            protocol: ServerProtocol::Tls {
                tls_targets: BTreeMap::new(),
                reality_targets,
            },
            rules: Vec::new(),
        },
        credentials: Credentials::Reality {
            user_id,
            private_key: keypair.private_key,
            public_key: keypair.public_key,
            short_id,
            server_name: request.server_name.clone(),
        },
        certificate_path: None,
        certificate_key_path: None,
    })
}
