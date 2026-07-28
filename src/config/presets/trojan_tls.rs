use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{generated_password, Credentials, InnerProtocol, TlsSecurity},
    tls, GeneratedPreset, GenerationRequest,
};

pub(super) fn generate(
    request: &GenerationRequest,
    parent: &Path,
    profile_id: Uuid,
) -> Result<GeneratedPreset> {
    let password = generated_password();
    let alpn_protocols = vec!["h2".to_owned(), "http/1.1".to_owned()];
    tls::finish(
        request,
        parent,
        profile_id,
        alpn_protocols.clone(),
        false,
        InnerProtocol::Trojan {
            password: password.clone(),
        },
        Credentials::Trojan {
            password,
            server_name: request.server_name.clone(),
            alpn_protocols,
            security: TlsSecurity::Tls,
        },
    )
}
