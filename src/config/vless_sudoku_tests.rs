use super::*;
use crate::{
    cli::{Cli, Command},
    client::{self, ClientFormat},
    sudoku::{SudokuAscii, SudokuConfig},
};
use clap::Parser;

fn sample() -> (ServerConfig, ManagedProfile) {
    let protocol = Protocol::from_menu_number(16).expect("缺少 VLESS-Sudoku");
    let mut request = tests::request(protocol, "unused.yaml".into());
    request.server_name.clear();
    request.options.sudoku = Some(SudokuConfig {
        password: " test +&?/密码% ".into(),
        ascii: SudokuAscii::Ascii,
        padding_min: 0,
        padding_max: 10,
    });
    validate_request(&request).unwrap();
    let generated = presets::generate(&request, Path::new("."), Uuid::nil()).unwrap();
    let profile = ManagedProfile {
        id: Uuid::nil(),
        name: "sudoku-test".into(),
        port: request.port,
        server_address: Some("203.0.113.10".into()),
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
fn vless_sudoku_yaml_link_exports_and_info_agree() {
    let (server, profile) = sample();
    assert_eq!(profile.protocol().slug(), "vless-sudoku");
    assert_eq!(
        profile.protocol().advanced_label(),
        "VLESS-Sudoku（无加密）"
    );
    assert!(commit::is_managed_profile_file_name(
        "VLESS-SUDOKU-443.yaml"
    ));
    let yaml = crate::yaml::to_value(&server).unwrap();
    assert_eq!(yaml["protocol"]["type"], "sudoku_mask");
    assert_eq!(yaml["protocol"]["ascii"], "ascii");
    let inner = &yaml["protocol"]["protocol"];
    assert_eq!(inner["type"], "vless");
    for field in ["encryption", "decryption", "vision"] {
        assert!(inner.get(field).is_none(), "{field}");
    }
    assert!(server.transport.is_none());
    assert!(!profile.h2mux_eligible());
    ensure_servers_match_state(&[server], std::slice::from_ref(&profile)).unwrap();
    let link = client::stored_share_uri(&profile, None).unwrap();
    assert!(link.contains("fm=%7B%22"));
    let parsed = url::Url::parse(&link).unwrap();
    let query: BTreeMap<_, _> = parsed.query_pairs().into_owned().collect();
    for (key, value) in [
        ("encryption", "none"),
        ("security", "none"),
        ("type", "tcp"),
    ] {
        assert_eq!(query[key], value);
    }
    assert_eq!(query.len(), 4);
    let fm: serde_json::Value = serde_json::from_str(&query["fm"]).unwrap();
    assert_eq!(query["fm"], serde_json::to_string(&fm).unwrap());
    assert_eq!(fm["tcp"][0]["settings"]["password"], " test +&?/密码% ");
    assert_eq!(fm["tcp"][0]["settings"]["ascii"], "ascii");
    assert_eq!(fm["tcp"][0]["settings"]["paddingMax"], 10);
    for format in [
        ClientFormat::ClashMeta,
        ClientFormat::SingBox,
        ClientFormat::Nekobox,
    ] {
        assert_eq!(
            client::render(&profile, format, "203.0.113.10")
                .unwrap_err()
                .to_string(),
            crate::sudoku::UNSUPPORTED
        );
    }
    let info = crate::cli::profile_details_text(&profile, Some(&link));
    assert!(info.contains("加密：无"));
    assert!(info.contains("外观：Sudoku（ascii、padding 0–10%）"));
    for required in [
        "没有任何加密和认证",
        "UUID",
        "目标地址",
        "非 HTTPS",
        "VLESS-ENC + Sudoku",
        "VLESS-REALITY",
    ] {
        assert!(info.contains(required), "{required}");
    }
}

#[test]
fn vless_sudoku_cli_needs_no_switch_and_rejects_other_protocol_options() {
    for extra in [
        vec![],
        vec![
            "--sudoku-password",
            " password ",
            "--sudoku-ascii",
            "ascii",
            "--sudoku-padding-max",
            "10",
        ],
    ] {
        let cli =
            Cli::try_parse_from(["prs", "add", "vless-sudoku"].into_iter().chain(extra)).unwrap();
        let Some(Command::Add(args)) = cli.command else {
            panic!()
        };
        args.vless_enc.sudoku.validate_for(args.protocol).unwrap();
        let mask = args
            .vless_enc
            .sudoku
            .config_for(args.protocol)
            .unwrap()
            .unwrap();
        mask.validate().unwrap();
        if args.vless_enc.sudoku.password.is_some() {
            assert_eq!(mask.password, " password ");
            assert_eq!(mask.ascii, SudokuAscii::Ascii);
            assert_eq!((mask.padding_min, mask.padding_max), (0, 10));
        } else {
            assert_eq!(mask.password.len(), 24);
            assert_eq!(mask.ascii, SudokuAscii::PreferEntropy);
            assert_eq!((mask.padding_min, mask.padding_max), (0, 0));
        }
    }
}

#[test]
fn vless_sudoku_changes_preserve_plain_vless_and_require_mask() {
    let (mut server, mut profile) = sample();
    let inner = crate::yaml::to_value(&server).unwrap()["protocol"]["protocol"].clone();
    let before = client::stored_share_uri(&profile, None).unwrap();
    apply_profile_change(&mut server, &mut profile, ProfileChange::Port(24445)).unwrap();
    apply_profile_change(
        &mut server,
        &mut profile,
        ProfileChange::Sudoku(Some(SudokuConfig {
            password: "test-password".into(),
            ascii: SudokuAscii::PreferEntropy,
            padding_min: 5,
            padding_max: 20,
        })),
    )
    .unwrap();
    apply_profile_change(
        &mut server,
        &mut profile,
        ProfileChange::RegenerateSudokuPassword,
    )
    .unwrap();
    assert_ne!(before, client::stored_share_uri(&profile, None).unwrap());
    assert_eq!(
        crate::yaml::to_value(&server).unwrap()["protocol"]["protocol"],
        inner
    );
    ensure_servers_match_state(&[server.clone()], std::slice::from_ref(&profile)).unwrap();
    let original = serde_json::to_vec(&server).unwrap();
    assert!(apply_profile_change(&mut server, &mut profile, ProfileChange::Sudoku(None)).is_err());
    assert_eq!(serde_json::to_vec(&server).unwrap(), original);
    let before_regenerate = crate::yaml::to_value(&server).unwrap();
    apply_profile_change(
        &mut server,
        &mut profile,
        ProfileChange::RegenerateCredentials,
    )
    .unwrap();
    let regenerated = crate::yaml::to_value(&server).unwrap();
    assert_ne!(
        regenerated["protocol"]["password"],
        before_regenerate["protocol"]["password"]
    );
    assert_ne!(
        regenerated["protocol"]["protocol"]["user_id"],
        inner["user_id"]
    );
    assert!(regenerated["protocol"]["protocol"]
        .get("decryption")
        .is_none());
    ensure_servers_match_state(
        std::slice::from_ref(&server),
        std::slice::from_ref(&profile),
    )
    .unwrap();
    server.protocol = vless_enc_inner_mut(&mut server.protocol).clone();
    assert!(ensure_servers_match_state(&[server], &[profile]).is_err());
}

#[tokio::test]
async fn vless_sudoku_generated_yaml_passes_shoes_dry_run() {
    let Some(binary) = crate::shoes_e2e::shoes_binary(
        "config::vless_sudoku_tests::vless_sudoku_generated_yaml_passes_shoes_dry_run",
        &[
            crate::shoes_e2e::TEST_SHOES,
            crate::shoes_e2e::SHOES_E2E_BIN,
        ],
    ) else {
        return;
    };
    let (server, _) = sample();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sudoku.yaml");
    utils::atomic_write(
        &path,
        crate::yaml::to_string(&vec![server]).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    validate_with_binary(&binary, &path).await.unwrap();
}

#[test]
fn vless_sudoku_state_fixture_roundtrips_and_keeps_legacy_bytes() {
    let fixture = include_str!("../../tests/fixtures/yaml/vless-sudoku/state.json");
    let state: ManagedState = serde_json::from_str(fixture).unwrap();
    let servers = load_servers(Path::new("tests/fixtures/yaml/vless-sudoku/config.yaml")).unwrap();
    ensure_servers_match_state(&servers, &state.profiles).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    save_state_to(&path, &state).unwrap();
    let written = fs::read_to_string(&path).unwrap();
    assert_eq!(written, fixture.trim_end());
    assert_eq!(
        serde_json::to_vec(&load_state_from(&path).unwrap()).unwrap(),
        serde_json::to_vec(&state).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    for old in [
        include_str!("../../tests/fixtures/yaml/compat/state.json"),
        include_str!("../../tests/fixtures/yaml/chain-v2/state.json"),
        include_str!("../../tests/fixtures/yaml/vless-xhttp-reality/compatible-state.json"),
    ] {
        let state: ManagedState = serde_json::from_str(old).unwrap();
        assert_eq!(serde_json::to_string_pretty(&state).unwrap() + "\n", old);
    }
    // Both extensions use absolute positions; interleaving must retain order.
    let xhttp: ManagedState = serde_json::from_str(include_str!(
        "../../tests/fixtures/yaml/vless-xhttp-reality/compatible-state.json"
    ))
    .unwrap();
    let (_, legacy) = tests::reality_server_and_profile(24443);
    let profiles = vec![
        state.profiles[0].clone(),
        xhttp.profiles[0].clone(),
        legacy.clone(),
        state.profiles[0].clone(),
        legacy,
        xhttp.profiles[0].clone(),
    ];
    let mixed = ManagedState {
        profiles,
        ..Default::default()
    };
    let value = serde_json::to_value(&mixed).unwrap();
    assert_eq!(value["profiles"].as_array().unwrap().len(), 2);
    let decoded: ManagedState = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        serde_json::to_vec(&mixed.profiles).unwrap(),
        serde_json::to_vec(&decoded.profiles).unwrap()
    );
    for position in [0, 99] {
        let mut invalid = value.clone();
        invalid["sudoku_profiles"][1]["position"] = position.into();
        assert!(serde_json::from_value::<ManagedState>(invalid).is_err());
    }
    let mut invalid = value.clone();
    invalid["sudoku_profiles"][0]["profile"] = value["profiles"][0].clone();
    assert!(serde_json::from_value::<ManagedState>(invalid).is_err());
    let mut invalid = value;
    invalid["sudoku_profiles"][0]["position"] = 1.into();
    assert!(
        serde_json::from_value::<ManagedState>(invalid).is_err(),
        "cross-extension duplicate"
    );
}

#[test]
fn vless_sudoku_rejects_encryption_invalid_padding_and_mismatched_runtime() {
    let (server, profile) = sample();
    for field in ["decryption", "vision", "user_id"] {
        let mut value = serde_json::to_value(&server).unwrap();
        value["protocol"]["protocol"][field] = match field {
            "vision" => true.into(),
            "user_id" => Uuid::nil().to_string().into(),
            _ => "must-not-encrypt".into(),
        };
        let invalid = serde_json::from_value(value).unwrap();
        assert!(ensure_servers_match_state(&[invalid], std::slice::from_ref(&profile)).is_err());
    }
    let mut request = tests::request(profile.protocol(), "unused.yaml".into());
    for options in [
        GenerationOptions {
            vless_enc_vision: true,
            ..Default::default()
        },
        GenerationOptions {
            vless_enc_mode: VlessEncMode::Random,
            ..Default::default()
        },
        GenerationOptions {
            vless_enc_auth: VlessEncAuth::Mlkem768,
            ..Default::default()
        },
        GenerationOptions {
            sudoku: Some(SudokuConfig {
                padding_min: 20,
                padding_max: 10,
                ..SudokuConfig::generated()
            }),
            ..Default::default()
        },
    ] {
        request.options = options;
        assert!(validate_request(&request).is_err());
    }
    request.options = Default::default();
    let generated = presets::generate(&request, Path::new("."), Uuid::nil()).unwrap();
    let Credentials::VlessSudoku { sudoku, .. } = generated.credentials else {
        panic!()
    };
    assert_eq!(sudoku.password.len(), 24);
    assert_eq!(sudoku.ascii, SudokuAscii::PreferEntropy);
    assert_eq!((sudoku.padding_min, sudoku.padding_max), (0, 0));
    for protocol in ["vless-enc", "reality", "socks5"] {
        for extra in [
            vec!["--sudoku-password", "test"],
            vec!["--sudoku-ascii", "prefer-entropy"],
            vec!["--sudoku-padding-min", "0"],
            vec!["--sudoku-padding-max", "0"],
        ] {
            let cli =
                Cli::try_parse_from(["prs", "add", protocol].into_iter().chain(extra)).unwrap();
            let Some(Command::Add(args)) = cli.command else {
                panic!()
            };
            assert!(args.vless_enc.sudoku.validate_for(args.protocol).is_err());
        }
    }
}
