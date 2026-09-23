use std::{collections::BTreeMap, path::Path};

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{resolve_certificate, Credentials, InnerProtocol, ServerConfig, ServerProtocol},
    GeneratedPreset, GenerationRequest,
};
use crate::config::schema::{TlsTarget, WebsocketTarget};

pub(super) fn finish(
    request: &GenerationRequest,
    parent: &Path,
    profile_id: Uuid,
    alpn_protocols: Vec<String>,
    vision: bool,
    protocol: InnerProtocol,
    credentials: Credentials,
) -> Result<GeneratedPreset> {
    let (certificate, certificate_key) = resolve_certificate(request, parent, profile_id)?;
    let mut tls_targets = BTreeMap::new();
    tls_targets.insert(
        request.server_name.clone(),
        TlsTarget {
            cert: certificate.to_string_lossy().into_owned(),
            key: certificate_key.to_string_lossy().into_owned(),
            alpn_protocols,
            vision,
            protocol,
        },
    );
    Ok(GeneratedPreset {
        server: ServerConfig {
            address: format!("0.0.0.0:{}", request.port),
            transport: None,
            quic_settings: None,
            protocol: ServerProtocol::Tls {
                tls_targets,
                shadowtls_targets: BTreeMap::new(),
                reality_targets: BTreeMap::new(),
            },
            rules: Vec::new(),
        },
        credentials,
        certificate_path: Some(certificate),
        certificate_key_path: Some(certificate_key),
    })
}

pub(super) fn websocket(path: String, protocol: InnerProtocol) -> InnerProtocol {
    InnerProtocol::Websocket {
        targets: vec![WebsocketTarget {
            matching_path: path,
            protocol,
        }],
    }
}
