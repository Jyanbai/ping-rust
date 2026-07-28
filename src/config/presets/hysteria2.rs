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
    let server = quic_server(
        request.port,
        &cert.to_string_lossy(),
        &key.to_string_lossy(),
        ServerProtocol::Hysteria2 {
            password: password.clone(),
            udp_enabled: request.options.udp_enabled,
        },
        request.options.quic_endpoints,
    );
    Ok(GeneratedPreset {
        server,
        credentials: Credentials::Hysteria2 {
            password,
            server_name: request.server_name.clone(),
            alpn_protocols: default_h3_alpn(),
        },
        certificate_path: Some(cert),
        certificate_key_path: Some(key),
    })
}
