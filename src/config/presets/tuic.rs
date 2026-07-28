use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{
        default_h3_alpn, quic_server, random_secret, resolve_certificate, Credentials,
        ServerProtocol,
    },
    GeneratedPreset, GenerationRequest,
};

pub(super) fn generate(
    request: &GenerationRequest,
    parent: &Path,
    profile_id: Uuid,
) -> Result<GeneratedPreset> {
    let (cert, key) = resolve_certificate(request, parent, profile_id)?;
    let password = random_secret(24);
    let user_id = Uuid::new_v4();
    let server = quic_server(
        request.port,
        &cert.to_string_lossy(),
        &key.to_string_lossy(),
        ServerProtocol::Tuic {
            uuid: user_id,
            password: password.clone(),
            zero_rtt_handshake: request.options.tuic_zero_rtt,
        },
        request.options.quic_endpoints,
    );
    Ok(GeneratedPreset {
        server,
        credentials: Credentials::Tuic {
            user_id,
            password,
            server_name: request.server_name.clone(),
            alpn_protocols: default_h3_alpn(),
            zero_rtt_handshake: request.options.tuic_zero_rtt,
        },
        certificate_path: Some(cert),
        certificate_key_path: Some(key),
    })
}
