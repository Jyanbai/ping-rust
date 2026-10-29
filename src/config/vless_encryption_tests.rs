use super::*;
use crate::{
    client::{self, ClientFormat},
    vless_encryption::{CredentialPair, VlessEncAuth, VlessEncMode},
};

fn sample(vision: bool) -> (ServerConfig, ManagedProfile) {
    let request = GenerationRequest {
        name: None,
        protocol: Protocol::VlessEnc,
        port: 24444,
        output: "unused.yaml".into(),
        server_address: Some("example.test".into()),
        server_name: String::new(),
        reality_dest: None,
        certificate: None,
        certificate_key: None,
        options: GenerationOptions {
            vless_enc_vision: vision,
            ..Default::default()
        },
    };
    let pair = CredentialPair {
        encryption: format!(
            "mlkem768x25519plus.native.0rtt.{}",
            URL_SAFE_NO_PAD.encode([7; 32])
        ),
        decryption: format!(
            "mlkem768x25519plus.native.600s.{}",
            URL_SAFE_NO_PAD.encode([9; 32])
        ),
    };
    let generated = presets::vless_enc::from_pair(&request, pair);
    let profile = ManagedProfile {
        id: Uuid::new_v4(),
        name: "VLESS-ENC-24444".into(),
        port: request.port,
        server_address: request.server_address,
        credentials: generated.credentials,
        certificate_path: None,
        certificate_key_path: None,
        self_signed_certificate: false,
        naive_certificate_validity: None,
        h2mux: Default::default(),
    };
    (generated.server, profile)
}

#[test]
fn vless_enc_yaml_is_native_tcp_with_default_limits_and_secret_only_in_runtime() {
    for vision in [false, true] {
        let (server, profile) = sample(vision);
        let yaml = crate::yaml::to_value(&server).unwrap();
        assert_eq!(yaml["protocol"]["type"], "vless");
        assert_eq!(
            yaml["protocol"]["vision"].as_bool().unwrap_or(false),
            vision
        );
        assert!(yaml["protocol"]["decryption"]
            .as_str()
            .unwrap()
            .contains(".600s."));
        assert!(yaml.get("transport").is_none());
        assert!(yaml.get("quic_settings").is_none());
        assert!(yaml["protocol"].get("encryption_limits").is_none());
        assert!(profile.certificate_path.is_none());
        assert!(!profile.h2mux_eligible());
        let state = serde_json::to_string(&profile).unwrap();
        assert!(!state.contains("decryption"));
        assert!(!state.contains(&URL_SAFE_NO_PAD.encode([9; 32])));
        assert!(ensure_servers_match_state(&[server], &[profile]).is_ok());
    }
    assert_eq!(Protocol::from_menu_number(14), Some(Protocol::VlessEnc));
    assert!(commit::is_managed_profile_file_name("VLESS-ENC-24444.yaml"));
}

#[test]
fn vless_enc_links_exports_and_details_never_expose_server_secret() {
    for vision in [false, true] {
        let (_, mut profile) = sample(vision);
        let link = client::share_uri(&profile, "example.test").unwrap();
        let url = url::Url::parse(&link).unwrap();
        let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["security"], "none");
        assert_eq!(query["type"], "tcp");
        assert!(query["encryption"].contains(".0rtt."));
        assert_eq!(
            query.get("flow").map(String::as_str),
            vision.then_some("xtls-rprx-vision")
        );
        assert_eq!(url.fragment(), Some("VLESS-ENC-24444"));
        assert!(client::share_uri(&profile, "::1")
            .unwrap()
            .contains("@[::1]:24444?"));
        let exported = client::render(&profile, ClientFormat::ClashMeta, "example.test").unwrap();
        let mihomo: serde_json::Value = crate::yaml::from_str(&exported).unwrap();
        assert_eq!(mihomo["proxies"][0]["encryption"], query["encryption"]);
        assert_eq!(mihomo["proxies"][0]["tls"], false);
        assert_eq!(
            mihomo["proxies"][0].get("flow").and_then(|v| v.as_str()),
            vision.then_some("xtls-rprx-vision")
        );
        for format in [ClientFormat::SingBox, ClientFormat::Nekobox] {
            let error = client::render(&profile, format, "example.test").unwrap_err();
            assert!(error.to_string().contains("不支持 VLESS Encryption"));
        }
        let details = crate::cli::profile_details_text(&profile, Some(&link));
        assert!(details.contains("Encryption"));
        assert!(details.contains("native"));
        for output in [&link, &exported, &details] {
            assert!(!output.contains("decryption"));
            assert!(!output.contains(&URL_SAFE_NO_PAD.encode([9; 32])));
        }
        profile.h2mux.enabled = true;
        assert!(profile.validate_h2mux().is_err());
    }
}

#[test]
fn vless_enc_vision_change_preserves_keys_and_updates_runtime_and_state() {
    let (mut server, mut profile) = sample(false);
    let before = crate::yaml::to_value(&server).unwrap();
    apply_profile_change(
        &mut server,
        &mut profile,
        ProfileChange::VlessEncVision(true),
    )
    .unwrap();
    let after = crate::yaml::to_value(&server).unwrap();
    assert!(before["protocol"]["decryption"] == after["protocol"]["decryption"]);
    assert_eq!(after["protocol"]["vision"], true);
    assert!(matches!(
        profile.credentials,
        Credentials::VlessEnc {
            vision: true,
            mode: VlessEncMode::Native,
            auth: VlessEncAuth::X25519,
            ..
        }
    ));
    assert!(ensure_servers_match_state(&[server], &[profile]).is_ok());
}

#[test]
fn vless_enc_rejects_options_on_other_protocols() {
    let request = GenerationRequest {
        name: None,
        protocol: Protocol::Socks5,
        port: 24444,
        output: "unused.yaml".into(),
        server_address: None,
        server_name: String::new(),
        reality_dest: None,
        certificate: None,
        certificate_key: None,
        options: GenerationOptions {
            vless_enc_vision: true,
            ..Default::default()
        },
    };
    assert!(validate_request(&request).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn vless_enc_dry_run_failure_does_not_echo_secret() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("shoes");
    fs::write(&binary, "#!/bin/sh\necho secret-sentinel >&2\nexit 1\n").unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let config = dir.path().join("config.yaml");
    fs::write(
        &config,
        "- protocol: {type: vless, decryption: secret-sentinel}\n",
    )
    .unwrap();
    let error = validate_with_binary(&binary, &config).await.unwrap_err();
    assert!(!format!("{error:#}").contains("secret-sentinel"));
}

#[tokio::test]
async fn vless_enc_mode_auth_and_regeneration_use_shoes_and_keep_state_public() {
    let (mut server, mut profile) = sample(false);
    let binary = std::env::var_os("PING_RUST_TEST_SHOES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(crate::utils::SHOES_BIN));
    for change in [
        ProfileChange::VlessEncMode(VlessEncMode::Random),
        ProfileChange::VlessEncAuth(VlessEncAuth::Mlkem768),
        ProfileChange::RegenerateCredentials,
        ProfileChange::VlessEncVision(true),
    ] {
        apply_profile_change(&mut server, &mut profile, change).unwrap();
        assert!(ensure_servers_match_state(&[server.clone()], &[profile.clone()]).is_ok());
        let state = serde_json::to_string(&profile).unwrap();
        let ServerProtocol::Vless { decryption, .. } = &server.protocol else {
            panic!("VLESS required");
        };
        assert!(!state.contains(decryption));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.yaml");
        let yaml = crate::yaml::to_string(&vec![&server]).unwrap();
        crate::utils::atomic_write(&path, yaml.as_bytes(), 0o600).unwrap();
        assert!(validate_with_binary(&binary, &path).await.is_ok());
    }
}
