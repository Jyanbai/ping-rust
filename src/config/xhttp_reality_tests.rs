use super::*;
use crate::client::{self, ClientFormat};

fn sample(path: Option<&str>) -> (ServerConfig, ManagedProfile) {
    let mut request = tests::request(Protocol::VlessXhttpReality, "unused.yaml".into());
    request.server_name = "example.com".into();
    request.options.xhttp_path = path.map(str::to_owned);
    validate_request(&request).unwrap();
    let generated = presets::generate(&request, Path::new("."), Uuid::nil()).unwrap();
    let profile = ManagedProfile {
        id: Uuid::nil(),
        name: "xhttp-test".into(),
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
fn xhttp_reality_yaml_nests_xhttp_inside_reality_without_vision() {
    let (server, profile) = sample(Some("/test-path_~.012345"));
    let yaml = crate::yaml::to_value(&server).unwrap();
    let target = &yaml["protocol"]["reality_targets"]["example.com"];
    assert_eq!(yaml["protocol"]["type"], "tls");
    assert_eq!(target["vision"], false);
    assert_eq!(target["dest"], "example.com:443");
    assert_eq!(target["max_time_diff"], 60000);
    assert_eq!(target["protocol"]["type"], "xhttp");
    assert_eq!(target["protocol"]["path"], "/test-path_~.012345");
    assert_eq!(target["protocol"]["mode"], "auto");
    assert_eq!(target["protocol"]["protocol"]["type"], "vless");
    assert!(target["protocol"].get("limits").is_none());
    let mut normalized = yaml.clone();
    let target = &mut normalized["protocol"]["reality_targets"]["example.com"];
    target["private_key"] = "PRIVATE_KEY".into();
    target["short_ids"] = serde_json::json!(["SHORT_ID"]);
    target["protocol"]["protocol"]["user_id"] = "USER_ID".into();
    let golden: serde_json::Value = crate::yaml::from_str(include_str!(
        "../../tests/fixtures/yaml/vless-xhttp-reality/server.yaml"
    ))
    .unwrap();
    assert_eq!(normalized, golden);
    assert!(profile.certificate_path.is_none());
    assert!(!profile.h2mux_eligible());
    assert!(ensure_servers_match_state(&[server], &[profile]).is_ok());
    assert_eq!(
        Protocol::from_menu_number(15),
        Some(Protocol::VlessXhttpReality)
    );
    assert!(commit::is_managed_profile_file_name(
        "VLESS-XHTTP-REALITY-443.yaml"
    ));
}

#[test]
fn xhttp_reality_random_path_and_validation() {
    let mut paths = std::collections::BTreeSet::new();
    for _ in 0..32 {
        let (_, profile) = sample(None);
        let Credentials::VlessXhttpReality { xhttp, .. } = profile.credentials else {
            panic!("wrong credentials");
        };
        assert_eq!(xhttp.path.len(), 17);
        assert!(xhttp.path.starts_with('/'));
        assert!(xhttp.path[1..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert!(paths.insert(xhttp.path));
    }
    for path in ["/", "/a/b-_.~0123"] {
        assert!(validate_xhttp_path(path).is_ok(), "{path}");
    }
    for path in [
        "", "no-slash", "/a b", "/a?b", "/a#b", "/a%b", "/a\\b", "/中文", "/a\nb",
    ] {
        assert!(validate_xhttp_path(path).is_err(), "{path:?}");
        let mut request = tests::request(Protocol::VlessXhttpReality, "unused.yaml".into());
        request.options.xhttp_path = Some(path.into());
        assert!(validate_request(&request).is_err());
    }
    let mut request = tests::request(Protocol::Reality, "unused.yaml".into());
    request.options.xhttp_path = Some("/valid".into());
    assert!(validate_request(&request).is_err());
    request.protocol = Protocol::VlessXhttpReality;
    request.options.vless_enc_vision = true;
    assert!(validate_request(&request).is_err());
}

#[test]
fn xhttp_reality_link_exports_and_info_are_consistent_and_hide_private_key() {
    let (_, profile) = sample(Some("/a/b_~.-"));
    let link = client::stored_share_uri(&profile, None).unwrap();
    assert!(link.contains("path=%2Fa%2Fb_%7E.-"));
    let url = url::Url::parse(&link).unwrap();
    let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    for (key, value) in [
        ("encryption", "none"),
        ("security", "reality"),
        ("sni", "example.com"),
        ("fp", "chrome"),
        ("type", "xhttp"),
        ("path", "/a/b_~.-"),
        ("mode", "auto"),
    ] {
        assert_eq!(query[key], value);
    }
    assert!(!query.contains_key("flow"));
    let Credentials::VlessXhttpReality {
        public_key,
        private_key,
        short_id,
        ..
    } = &profile.credentials
    else {
        panic!("wrong credentials");
    };
    assert_eq!(&query["pbk"], public_key);
    assert_eq!(&query["sid"], short_id);
    assert!(!link.contains(private_key));
    for format in [
        ClientFormat::ClashMeta,
        ClientFormat::SingBox,
        ClientFormat::Nekobox,
    ] {
        assert_eq!(
            client::render(&profile, format, "203.0.113.10")
                .unwrap_err()
                .to_string(),
            "该客户端不支持 XHTTP，请用分享链接导入 v2rayN 或 Xray"
        );
    }
    let info = crate::cli::profile_details_text(&profile, Some(&link));
    assert!(info.contains("传输：XHTTP（path /a/b_~.-，mode auto）"));
    assert!(!info.contains(private_key));
    assert!(!info.contains("xtls-rprx-vision"));
}

#[test]
fn xhttp_reality_changes_keep_runtime_and_state_in_sync() {
    let (mut server, mut profile) = sample(Some("/original"));
    let before = (
        serde_json::to_vec(&server).unwrap(),
        serde_json::to_vec(&profile).unwrap(),
    );
    assert!(apply_profile_change(
        &mut server,
        &mut profile,
        ProfileChange::XhttpPath("/bad?path".into())
    )
    .is_err());
    assert_eq!(
        before,
        (
            serde_json::to_vec(&server).unwrap(),
            serde_json::to_vec(&profile).unwrap()
        )
    );
    for change in [
        ProfileChange::XhttpPath("/changed".into()),
        ProfileChange::Port(24443),
        ProfileChange::RealityServerName("new.example.com".into()),
        ProfileChange::RegenerateCredentials,
    ] {
        apply_profile_change(&mut server, &mut profile, change).unwrap();
        assert!(ensure_servers_match_state(&[server.clone()], &[profile.clone()]).is_ok());
    }
    let yaml = crate::yaml::to_value(&server).unwrap();
    let target = &yaml["protocol"]["reality_targets"]["new.example.com"];
    assert_eq!(target["dest"], "new.example.com:443");
    assert_eq!(target["vision"], false);
    assert_eq!(target["protocol"]["path"], "/changed");
    let mut broken = server.clone();
    let ServerProtocol::Tls {
        reality_targets, ..
    } = &mut broken.protocol
    else {
        unreachable!()
    };
    reality_targets.values_mut().next().unwrap().vision = true;
    assert!(ensure_servers_match_state(&[broken], &[profile.clone()]).is_err());
    let mut broken = profile.clone();
    let Credentials::VlessXhttpReality { xhttp, .. } = &mut broken.credentials else {
        unreachable!()
    };
    xhttp.path = "/different".into();
    assert!(ensure_servers_match_state(&[server], &[broken]).is_err());
}

#[test]
fn xhttp_reality_state_roundtrips_and_old_state_bytes_stay_unchanged() {
    let fixture = include_str!("../../tests/fixtures/yaml/vless-xhttp-reality/state.json");
    let state: ManagedState = serde_json::from_str(fixture).unwrap();
    assert_eq!(
        serde_json::to_string_pretty(&state).unwrap() + "\n",
        fixture
    );
    assert_eq!(state.profiles[0].protocol(), Protocol::VlessXhttpReality);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.json");
    save_state_to(&path, &state).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), fixture.trim_end());
    let loaded = load_state_from(&path).unwrap();
    assert_eq!(
        serde_json::to_vec(&loaded).unwrap(),
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
    ] {
        let state: ManagedState = serde_json::from_str(old).unwrap();
        let written = serde_json::to_string_pretty(&state).unwrap() + "\n";
        assert_eq!(written, old);
        assert!(!written.contains("VlessXhttpReality"));
        assert!(!written.contains("xhttp"));
    }
}

#[tokio::test]
async fn xhttp_reality_generated_yaml_passes_shoes_dry_run() {
    let Some(binary) = crate::shoes_e2e::shoes_binary(
        "config::xhttp_reality_tests::xhttp_reality_generated_yaml_passes_shoes_dry_run",
        &[
            crate::shoes_e2e::TEST_SHOES,
            crate::shoes_e2e::SHOES_E2E_BIN,
        ],
    ) else {
        return;
    };
    let (server, _) = sample(None);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("xhttp.yaml");
    utils::atomic_write(
        &path,
        crate::yaml::to_string(&vec![server]).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    validate_with_binary(&binary, &path).await.unwrap();
}
