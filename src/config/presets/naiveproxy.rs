use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use super::{
    super::{generated_password, generated_socks5_username, Credentials, InnerProtocol, NaiveUser},
    tls, GeneratedPreset, GenerationRequest,
};

pub(super) fn generate(
    request: &GenerationRequest,
    parent: &Path,
    profile_id: Uuid,
) -> Result<GeneratedPreset> {
    let username = request
        .options
        .naive_username
        .clone()
        .unwrap_or_else(generated_socks5_username);
    let password = request
        .options
        .naive_password
        .clone()
        .unwrap_or_else(generated_password);
    let padding = request.options.naive_padding;
    let udp_enabled = request.options.naive_udp_enabled;
    let fallback = request.options.naive_fallback.clone();
    tls::finish(
        request,
        parent,
        profile_id,
        vec!["h2".to_owned()],
        false,
        InnerProtocol::Naiveproxy {
            users: vec![NaiveUser {
                username: username.clone(),
                password: password.clone(),
            }],
            padding,
            udp_enabled,
            fallback: fallback.clone(),
        },
        Credentials::NaiveProxy {
            username,
            password,
            server_name: request.server_name.clone(),
            padding,
            udp_enabled,
            fallback,
        },
    )
}
