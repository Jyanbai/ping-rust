use std::{collections::BTreeMap, path::Path};

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{
        generate_reality_keypair, random_hex, resolve_certificate, AnyTlsMode, AnyTlsSecurity,
        Credentials, InnerProtocol, RealityTarget, ServerConfig, ServerProtocol,
    },
    GeneratedPreset, GenerationRequest,
};
use crate::config::schema::TlsTarget;

pub(super) fn generate(
    request: &GenerationRequest,
    parent: &Path,
    profile_id: Uuid,
) -> Result<GeneratedPreset> {
    let inner = InnerProtocol::AnyTls {
        users: request.options.anytls_users.clone(),
        padding_scheme: request.options.anytls_padding_scheme.clone(),
        udp_enabled: request.options.udp_enabled,
        fallback: request.options.anytls_fallback.clone(),
    };
    let alpn_protocols = vec!["h2".to_owned(), "http/1.1".to_owned()];
    let mut tls_targets = BTreeMap::new();
    let mut reality_targets = BTreeMap::new();

    let (security, certificate_path, certificate_key_path) = match request.options.anytls_mode {
        AnyTlsMode::Tls => {
            let (certificate, certificate_key) = resolve_certificate(request, parent, profile_id)?;
            tls_targets.insert(
                request.server_name.clone(),
                TlsTarget {
                    cert: certificate.to_string_lossy().into_owned(),
                    key: certificate_key.to_string_lossy().into_owned(),
                    alpn_protocols: alpn_protocols.clone(),
                    vision: false,
                    protocol: inner,
                },
            );
            (
                AnyTlsSecurity::Tls,
                Some(certificate),
                Some(certificate_key),
            )
        }
        AnyTlsMode::Reality => {
            let keypair = generate_reality_keypair();
            let short_id = request
                .options
                .reality_short_id
                .clone()
                .unwrap_or_else(|| random_hex(8));
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
                    protocol: inner,
                },
            );
            (
                AnyTlsSecurity::Reality {
                    private_key: keypair.private_key,
                    public_key: keypair.public_key,
                    short_id,
                },
                None,
                None,
            )
        }
    };

    Ok(GeneratedPreset {
        server: ServerConfig {
            address: format!("0.0.0.0:{}", request.port),
            transport: None,
            quic_settings: None,
            protocol: ServerProtocol::Tls {
                tls_targets,
                shadowtls_targets: BTreeMap::new(),
                reality_targets,
            },
            rules: Vec::new(),
        },
        credentials: Credentials::AnyTls {
            users: request.options.anytls_users.clone(),
            server_name: request.server_name.clone(),
            alpn_protocols,
            udp_enabled: request.options.udp_enabled,
            security,
        },
        certificate_path,
        certificate_key_path,
    })
}
