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
    assert_eq!(Protocol::from_menu_number(5), Some(Protocol::VlessEnc));
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
    // 未设置变量时沿用原来的回退（已安装的 shoes），不跳过；CI 设置 REQUIRE 后不允许回退。
    let binary = crate::shoes_e2e::shoes_binary_or(
        "config::vless_encryption_tests::vless_enc_mode_auth_and_regeneration_use_shoes_and_keep_state_public",
        &[crate::shoes_e2e::TEST_SHOES],
        crate::utils::SHOES_BIN,
    );
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

#[test]
fn sudoku_wraps_vless_and_roundtrips_finalmask_without_changing_inner_protocol() {
    use crate::sudoku::{SudokuAscii, SudokuConfig};
    for vision in [false, true] {
        for ascii in [
            SudokuAscii::PreferEntropy,
            SudokuAscii::Entropy,
            SudokuAscii::PreferAscii,
            SudokuAscii::Ascii,
        ] {
            let (mut server, mut profile) = sample(vision);
            let original = crate::yaml::to_value(&server).unwrap();
            let mask = SudokuConfig {
                password: " test +&?/密码% ".into(),
                ascii,
                padding_min: 0,
                padding_max: 10,
            };
            apply_profile_change(
                &mut server,
                &mut profile,
                ProfileChange::Sudoku(Some(mask.clone())),
            )
            .unwrap();
            let yaml = crate::yaml::to_value(&server).unwrap();
            assert_eq!(yaml["protocol"]["type"], "sudoku_mask");
            assert_eq!(yaml["protocol"]["password"], mask.password);
            assert_eq!(yaml["protocol"]["ascii"], ascii.as_str());
            assert_eq!(yaml["protocol"]["padding_min"], 0);
            assert_eq!(yaml["protocol"]["padding_max"], 10);
            assert_eq!(yaml["protocol"]["protocol"], original["protocol"]);
            let uri = client::share_uri(&profile, "203.0.113.10").unwrap();
            let parsed = url::Url::parse(&uri).unwrap();
            let fm = parsed
                .query_pairs()
                .find(|(key, _)| key == "fm")
                .unwrap()
                .1
                .into_owned();
            let value: serde_json::Value = serde_json::from_str(&fm).unwrap();
            assert_eq!(
                fm,
                serde_json::to_string(&value).unwrap(),
                "must be compact JSON"
            );
            assert_eq!(
                value,
                serde_json::json!({"tcp": [{"type": "sudoku", "settings": {"password": mask.password, "ascii": ascii.as_str(), "paddingMin": 0, "paddingMax": 10}}]})
            );
            assert!(uri.contains("fm=%7B%22"));
            let rebuilt = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("fm", &fm)
                .finish();
            assert!(uri.contains(&rebuilt));
            let decoded_server: ServerConfig =
                crate::yaml::from_str(&crate::yaml::to_string(&server).unwrap()).unwrap();
            let decoded_profile: ManagedProfile =
                serde_json::from_str(&serde_json::to_string(&profile).unwrap()).unwrap();
            assert!(ensure_servers_match_state(&[decoded_server], &[decoded_profile]).is_ok());
            let details = crate::cli::profile_details_text(&profile, None);
            assert!(details.contains(&format!(
                "外观：Sudoku（{}、padding 0–10%）",
                ascii.as_str()
            )));
            assert!(!details.contains(&mask.password));
            for format in [
                ClientFormat::ClashMeta,
                ClientFormat::SingBox,
                ClientFormat::Nekobox,
            ] {
                assert_eq!(client::render(&profile, format, "203.0.113.10").unwrap_err().to_string(), "该客户端导出不支持 Xray FinalMask Sudoku，请用分享链接导入 v2rayN 或 Xray ≥ v26.3.27");
            }
            apply_profile_change(
                &mut server,
                &mut profile,
                ProfileChange::VlessEncVision(!vision),
            )
            .unwrap();
            assert_eq!(
                crate::yaml::to_value(&server).unwrap()["protocol"]["protocol"]["vision"]
                    .as_bool()
                    .unwrap_or(false),
                !vision
            );
            assert!(ensure_servers_match_state(&[server.clone()], &[profile.clone()]).is_ok());
            let mut wrong = profile.clone();
            let Credentials::VlessEnc {
                sudoku: Some(sudoku),
                ..
            } = &mut wrong.credentials
            else {
                panic!()
            };
            sudoku.password.push('x');
            assert!(ensure_servers_match_state(&[server.clone()], &[wrong]).is_err());
            apply_profile_change(&mut server, &mut profile, ProfileChange::Sudoku(None)).unwrap();
            assert_eq!(
                crate::yaml::to_value(&server).unwrap()["protocol"]["type"],
                "vless"
            );
            assert!(!client::share_uri(&profile, "203.0.113.10")
                .unwrap()
                .contains("fm="));
        }
    }
}

#[test]
fn sudoku_toggle_and_password_rotation_preserve_credentials_and_restore_original_bytes() {
    let (mut server, mut profile) = sample(false);
    let yaml_before = crate::yaml::to_string(&server).unwrap();
    let state_before = serde_json::to_string(&profile).unwrap();
    let link_before = client::share_uri(&profile, "203.0.113.10").unwrap();
    apply_profile_change(
        &mut server,
        &mut profile,
        ProfileChange::RegenerateSudokuPassword,
    )
    .unwrap_err();
    apply_profile_change(
        &mut server,
        &mut profile,
        ProfileChange::Sudoku(Some(crate::sudoku::SudokuConfig::generated())),
    )
    .unwrap();
    let first = client::share_uri(&profile, "203.0.113.10").unwrap();
    apply_profile_change(
        &mut server,
        &mut profile,
        ProfileChange::RegenerateSudokuPassword,
    )
    .unwrap();
    assert_ne!(first, client::share_uri(&profile, "203.0.113.10").unwrap());
    assert!(ensure_servers_match_state(&[server.clone()], &[profile.clone()]).is_ok());
    apply_profile_change(&mut server, &mut profile, ProfileChange::Sudoku(None)).unwrap();
    assert_eq!(crate::yaml::to_string(&server).unwrap(), yaml_before);
    assert_eq!(serde_json::to_string(&profile).unwrap(), state_before);
    assert_eq!(
        client::share_uri(&profile, "203.0.113.10").unwrap(),
        link_before
    );
    let restored: ManagedProfile = serde_json::from_str(&state_before).unwrap();
    assert_eq!(serde_json::to_string(&restored).unwrap(), state_before);
}

#[test]
fn sudoku_preset_generation_and_new_fixture_match() {
    let state =
        load_state_from(Path::new("tests/fixtures/yaml/vless-enc-sudoku/state.json")).unwrap();
    let servers = load_servers(Path::new(
        "tests/fixtures/yaml/vless-enc-sudoku/config.yaml",
    ))
    .unwrap();
    ensure_servers_match_state(&servers, &state.profiles).unwrap();
    let Credentials::VlessEnc { sudoku, .. } = &state.profiles[0].credentials else {
        panic!()
    };
    let request = GenerationRequest {
        options: GenerationOptions {
            sudoku: sudoku.clone(),
            ..Default::default()
        },
        ..tests::request(Protocol::VlessEnc, "unused.yaml".into())
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
    let value = crate::yaml::to_value(&generated.server).unwrap();
    let expected = crate::yaml::to_value(&servers[0]).unwrap();
    for key in ["type", "password", "ascii", "padding_min", "padding_max"] {
        assert_eq!(value["protocol"][key], expected["protocol"][key]);
    }
    assert_eq!(value["protocol"]["protocol"]["type"], "vless");
    assert_eq!(
        value["protocol"]["protocol"]["decryption"],
        expected["protocol"]["protocol"]["decryption"]
    );
}

#[test]
fn sudoku_disabled_legacy_state_keeps_original_serialization_bytes() {
    let state = load_state_from(Path::new("tests/fixtures/yaml/vless-enc/state.json")).unwrap();
    let expected =
        include_str!("../../tests/fixtures/yaml/vless-enc-sudoku/disabled-profile.json").trim_end();
    assert_eq!(serde_json::to_string(&state.profiles[0]).unwrap(), expected);
    let mut value: serde_json::Value = serde_json::from_str(expected).unwrap();
    value["credentials"]["VlessEnc"]["sudoku"] = serde_json::Value::Null;
    let explicit_null: ManagedProfile = serde_json::from_value(value).unwrap();
    assert_eq!(serde_json::to_string(&explicit_null).unwrap(), expected);
    assert_eq!(client::share_uri(&state.profiles[0], "203.0.113.10").unwrap(), "vless://b85798ef-e9dc-46a4-9a87-8da4499d36d0@203.0.113.10:24444?encryption=mlkem768x25519plus.native.0rtt.BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc&security=none&type=tcp#VLESS-ENC-24444");
    assert!(!crate::cli::profile_details_text(&state.profiles[0], None).contains("外观："));
}

#[test]
fn sudoku_rejects_invalid_requests_and_mismatched_or_nested_masks() {
    use crate::sudoku::SudokuConfig;
    let mut request = tests::request(Protocol::VlessEnc, "unused.yaml".into());
    for (min, max) in [(101, 101), (0, 101), (10, 9)] {
        request.options.sudoku = Some(SudokuConfig {
            padding_min: min,
            padding_max: max,
            ..SudokuConfig::generated()
        });
        assert!(validate_request(&request).is_err());
        let (mut server, mut profile) = sample(false);
        let before = crate::yaml::to_string(&server).unwrap();
        assert!(apply_profile_change(
            &mut server,
            &mut profile,
            ProfileChange::Sudoku(request.options.sudoku.clone())
        )
        .is_err());
        assert_eq!(crate::yaml::to_string(&server).unwrap(), before);
    }
    request.options.sudoku = Some(SudokuConfig::generated());
    request.protocol = Protocol::Socks5;
    assert!(validate_request(&request).is_err());
    let (mut server, mut profile) = sample(false);
    let unmasked = server.clone();
    let old_profile = profile.clone();
    apply_profile_change(
        &mut server,
        &mut profile,
        ProfileChange::Sudoku(request.options.sudoku.clone()),
    )
    .unwrap();
    assert!(ensure_servers_match_state(&[unmasked], &[profile.clone()]).is_err());
    assert!(ensure_servers_match_state(&[server.clone()], &[old_profile]).is_err());
    let nested = ServerConfig {
        protocol: ServerProtocol::SudokuMask {
            settings: request.options.sudoku.unwrap(),
            protocol: Box::new(server.protocol.clone()),
        },
        ..server
    };
    assert!(ensure_servers_match_state(&[nested], &[profile]).is_err());
}
