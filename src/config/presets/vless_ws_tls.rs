use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{generated_websocket_path, Credentials, InnerProtocol},
    tls, GeneratedPreset, GenerationRequest,
};

pub(super) fn generate(
    request: &GenerationRequest,
    parent: &Path,
    profile_id: Uuid,
) -> Result<GeneratedPreset> {
    let user_id = Uuid::new_v4();
    let path = request
        .options
        .websocket_path
        .clone()
        .unwrap_or_else(generated_websocket_path);
    let alpn_protocols = vec!["http/1.1".to_owned()];
    tls::finish(
        request,
        parent,
        profile_id,
        alpn_protocols.clone(),
        false,
        tls::websocket(
            path.clone(),
            InnerProtocol::Vless {
                user_id,
                udp_enabled: request.options.udp_enabled,
            },
        ),
        Credentials::VlessTls {
            user_id,
            server_name: request.server_name.clone(),
            alpn_protocols,
            vision: false,
            websocket_path: Some(path),
        },
    )
}
