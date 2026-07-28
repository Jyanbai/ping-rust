use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{Credentials, InnerProtocol},
    tls, GeneratedPreset, GenerationRequest,
};

pub(super) fn generate(
    request: &GenerationRequest,
    parent: &Path,
    profile_id: Uuid,
) -> Result<GeneratedPreset> {
    let user_id = Uuid::new_v4();
    let alpn_protocols = vec!["h2".to_owned(), "http/1.1".to_owned()];
    tls::finish(
        request,
        parent,
        profile_id,
        alpn_protocols.clone(),
        true,
        InnerProtocol::Vless {
            user_id,
            udp_enabled: request.options.udp_enabled,
        },
        Credentials::VlessTls {
            user_id,
            server_name: request.server_name.clone(),
            alpn_protocols,
            vision: true,
            websocket_path: None,
        },
    )
}
