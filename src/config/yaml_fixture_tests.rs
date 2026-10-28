//! YAML golden and compatibility fixtures.
//!
//! The fixtures under `tests/fixtures/yaml` were written by the serde_yaml 0.9
//! based release (main @ 7f80a37) with fixed test credentials. Every `*.json`
//! companion file is the parser-independent `serde_json::Value` of the YAML
//! next to it, so these tests compare semantics, not text formatting.

use std::{collections::BTreeMap, fs, path::PathBuf};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value as Json;

use super::*;
use crate::{
    chain_proxy::{
        parse_share_uri, ChainDefinition, ChainHop, ChainPool, RouteTarget, RoutingRule,
    },
    client::{self, ClientFormat},
};

const EXPORT_SERVER: &str = "203.0.113.10";
const FORMATS: [(ClientFormat, &str); 3] = [
    (ClientFormat::ClashMeta, "clash-meta"),
    (ClientFormat::SingBox, "sing-box"),
    (ClientFormat::Nekobox, "nekobox"),
];

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/yaml")
}

fn read_fixture(relative: &str) -> String {
    let path = fixture_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn read_json(relative: &str) -> Json {
    serde_json::from_str(&read_fixture(relative)).unwrap()
}

// The only three YAML library touch points of this module.
fn yaml_to_json(yaml: &str) -> Json {
    crate::yaml::from_str(yaml).expect("YAML parses into serde_json::Value")
}

fn to_yaml<T: Serialize + ?Sized>(value: &T) -> String {
    crate::yaml::to_string(value).expect("YAML serializes")
}

fn from_yaml<T: DeserializeOwned>(yaml: &str) -> T {
    crate::yaml::from_str(yaml).expect("YAML deserializes")
}

fn profile_fixture_documents() -> BTreeMap<String, Vec<u8>> {
    let mut documents = BTreeMap::new();
    for entry in fs::read_dir(fixture_root().join("compat/profiles")).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if name.ends_with(".yaml") {
            documents.insert(name, fs::read(entry.path()).unwrap());
        }
    }
    documents
}

fn client_export_value(format: ClientFormat, text: &str) -> Json {
    match format {
        ClientFormat::ClashMeta => yaml_to_json(text),
        ClientFormat::SingBox => serde_json::from_str(text).unwrap(),
        ClientFormat::Nekobox => Json::String(text.to_owned()),
    }
}

#[test]
fn yaml_fixtures_parse_to_their_recorded_values() {
    for relative in [
        "compat/config.yaml",
        "chain-v2/config.yaml",
        "chain-v036/config.yaml",
    ] {
        let companion = relative.replace(".yaml", ".json");
        assert_eq!(
            yaml_to_json(&read_fixture(relative)),
            read_json(&companion),
            "{relative}"
        );
    }
    let profiles = read_json("compat/profiles.json");
    let documents = profile_fixture_documents();
    assert_eq!(documents.len(), profiles.as_object().unwrap().len());
    for (name, contents) in &documents {
        assert_eq!(
            yaml_to_json(std::str::from_utf8(contents).unwrap()),
            profiles[name.as_str()],
            "{name}"
        );
    }
    let clients = read_json("golden/clients.json");
    for (key, expected) in clients.as_object().unwrap() {
        if let Some(name) = key.strip_suffix(".clash-meta") {
            let yaml = read_fixture(&format!("golden/clients/{name}.clash-meta.yaml"));
            assert_eq!(&yaml_to_json(&yaml), expected, "{key}");
        }
    }
}

#[test]
fn legacy_config_yaml_reads_back_and_reserializes_identically() {
    let path = fixture_root().join("compat/config.yaml");
    let servers = load_servers(&path).unwrap();
    let expected = read_json("compat/config.json");
    assert_eq!(servers.len(), expected.as_array().unwrap().len());
    let state = load_state_from(&fixture_root().join("compat/state.json")).unwrap();
    ensure_servers_match_state(&servers, &state.profiles).unwrap();
    ensure_chain_proxy_matches_state(&servers, &state).unwrap();
    let yaml = to_yaml(&servers);
    validate_yaml(&yaml).unwrap();
    assert_eq!(yaml_to_json(&yaml), expected);
}

#[test]
fn legacy_profile_documents_read_back_identically() {
    let state = load_state_from(&fixture_root().join("compat/state.json")).unwrap();
    let documents = profile_fixture_documents();
    let aggregate = aggregate_profile_documents(&documents, &state.profiles).unwrap();
    assert_eq!(yaml_to_json(&aggregate), read_json("compat/config.json"));

    let servers: Vec<ServerConfig> = from_yaml(&aggregate);
    let regenerated = profile_documents(&servers, &state.profiles).unwrap();
    let profiles = read_json("compat/profiles.json");
    assert_eq!(
        regenerated.keys().collect::<Vec<_>>(),
        documents.keys().collect::<Vec<_>>()
    );
    for (name, contents) in &regenerated {
        assert_eq!(
            yaml_to_json(std::str::from_utf8(contents).unwrap()),
            profiles[name.as_str()],
            "{name}"
        );
        let typed: ServerConfig = from_yaml(std::str::from_utf8(contents).unwrap());
        assert_eq!(yaml_to_json(&to_yaml(&typed)), profiles[name.as_str()]);
    }
}

#[test]
fn golden_preset_outputs_are_semantically_unchanged() {
    // Every protocol preset, rendered from the recorded state through the
    // production per-node serializer.
    let state = load_state_from(&fixture_root().join("compat/state.json")).unwrap();
    let mut protocols = state
        .profiles
        .iter()
        .map(ManagedProfile::protocol)
        .collect::<Vec<_>>();
    protocols.sort_by_key(|protocol| protocol.slug());
    protocols.dedup();
    let mut all = Protocol::all().collect::<Vec<_>>();
    all.sort_by_key(|protocol| protocol.slug());
    assert_eq!(protocols, all, "fixtures must cover every protocol preset");

    let servers = load_servers(&fixture_root().join("compat/config.yaml")).unwrap();
    let expected = read_json("compat/config.json");
    for (index, server) in servers.iter().enumerate() {
        assert_eq!(
            yaml_to_json(&to_yaml(server)),
            expected[index],
            "{}",
            state.profiles[index].name
        );
    }
}

#[test]
fn golden_client_exports_are_semantically_unchanged() {
    let state = load_state_from(&fixture_root().join("compat/state.json")).unwrap();
    let golden = read_json("golden/clients.json");
    let mut seen = 0;
    for profile in &state.profiles {
        for (format, label) in FORMATS {
            let key = format!("{}.{label}", profile.name);
            match client::render(profile, format, EXPORT_SERVER) {
                Ok(text) => {
                    assert_eq!(client_export_value(format, &text), golden[&key], "{key}");
                    seen += 1;
                }
                Err(_) => assert!(golden.get(&key).is_none(), "{key} used to render"),
            }
        }
    }
    assert_eq!(seen, golden.as_object().unwrap().len());
    assert!(golden
        .as_object()
        .unwrap()
        .keys()
        .any(|key| key.ends_with(".clash-meta")));
    assert!(golden
        .as_object()
        .unwrap()
        .keys()
        .any(|key| key.ends_with(".sing-box")));
}

#[test]
fn golden_chain_v2_config_is_semantically_unchanged() {
    let state = load_state_from(&fixture_root().join("chain-v2/state.json")).unwrap();
    assert!(state.chain_proxy.enabled);
    let expected_legacy = read_json("chain-v2/config.json");

    // Old file read back: rules parsed from YAML equal freshly rendered rules.
    let legacy = load_servers(&fixture_root().join("chain-v2/config.yaml")).unwrap();
    ensure_servers_match_state(&legacy, &state.profiles).unwrap();
    assert_eq!(yaml_to_json(&to_yaml(&legacy)), expected_legacy);

    // Fresh render from the old state must use the v0.3.6 typed rule shape.
    let mut servers = legacy.clone();
    for server in &mut servers {
        server.rules = direct_rules();
    }
    apply_chain_proxy_rules(&mut servers, &state);
    ensure_chain_proxy_matches_state(&servers, &state).unwrap();
    let rendered = yaml_to_json(&to_yaml(&servers));
    let wildcard_rules = rendered
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|server| server["rules"].as_array().unwrap())
        .filter(|rule| rule["masks"].get("domain_pattern").is_some())
        .count();
    assert_eq!(wildcard_rules, 4);
}

#[test]
fn old_chain_v2_state_regenerates_v036_domain_pattern_rules() {
    let state = load_state_from(&fixture_root().join("chain-v2/state.json")).unwrap();
    let mut servers = load_servers(&fixture_root().join("chain-v2/config.yaml")).unwrap();
    ensure_servers_match_state(&servers, &state.profiles).unwrap();
    apply_chain_proxy_rules(&mut servers, &state);
    let rendered = to_yaml(&servers);
    assert!(rendered.contains("domain_pattern:"));
    assert!(!rendered.contains("masks: '*.example.com'"));
}

#[test]
fn old_chain_v2_config_is_rejected_by_v036_dry_run() {
    let Some(binary) = std::env::var_os("PING_RUST_SHOES_E2E_BIN") else {
        return;
    };
    let binary = PathBuf::from(binary);
    if !binary.is_file() {
        return;
    }
    let output = std::process::Command::new(&binary)
        .arg("--dry-run")
        .arg(fixture_root().join("chain-v2/config.yaml"))
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "v0.3.6 unexpectedly accepted the legacy chain-v2 fixture"
    );
}

const SPECIAL_STRINGS: &[&str] = &[
    "no",
    "on",
    "yes",
    "off",
    "null",
    "~",
    "0x1F",
    "007",
    "0123",
    "a:b",
    "a: b",
    "#lead",
    "pass#word",
    "a #b",
    "true",
    "1e3",
];

fn special_string_servers(directory: &Path, value: &str) -> Vec<(ServerConfig, ManagedProfile)> {
    let mut socks = tests::request(Protocol::Socks5, directory.join("unused.yaml"));
    socks.port = 18_401;
    socks.options.socks5_username = Some(value.to_owned());
    socks.options.socks5_password = Some(value.to_owned());
    let mut anytls = tests::request(Protocol::AnyTls, directory.join("unused.yaml"));
    anytls.port = 18_402;
    anytls.options.anytls_users = vec![AnyTlsUser {
        name: value.to_owned(),
        password: value.to_owned(),
    }];
    let mut naive = tests::request(Protocol::NaiveProxy, directory.join("unused.yaml"));
    naive.port = 18_403;
    naive.options.naive_self_signed = true;
    naive.options.naive_username = Some(value.to_owned());
    naive.options.naive_password = Some(value.to_owned());
    [socks, anytls, naive]
        .into_iter()
        .enumerate()
        .map(|(index, request)| {
            let profile_id = Uuid::from_u128(0x5000 + index as u128);
            let generated = presets::generate(&request, directory, profile_id).unwrap();
            let server = generated.server;
            let profile = ManagedProfile {
                h2mux: Default::default(),
                id: profile_id,
                name: value.to_owned(),
                port: request.port,
                server_address: None,
                credentials: generated.credentials,
                certificate_path: generated.certificate_path,
                certificate_key_path: generated.certificate_key_path,
                self_signed_certificate: request
                    .protocol
                    .requires_certificate(request.options.anytls_mode),
                naive_certificate_validity: None,
            };
            (server, profile)
        })
        .collect()
}

fn collect_strings(value: &Json, out: &mut Vec<String>) {
    match value {
        Json::String(text) => out.push(text.clone()),
        Json::Array(items) => items.iter().for_each(|item| collect_strings(item, out)),
        Json::Object(map) => map.values().for_each(|item| collect_strings(item, out)),
        _ => {}
    }
}

#[test]
fn yaml_special_strings_round_trip_as_exact_strings() {
    let directory = tempfile::tempdir().unwrap();
    for value in SPECIAL_STRINGS {
        let pairs = special_string_servers(directory.path(), value);
        let servers = pairs
            .iter()
            .map(|(server, _)| server.clone())
            .collect::<Vec<_>>();
        let yaml = to_yaml(&servers);
        validate_yaml(&yaml).unwrap();
        let parsed = yaml_to_json(&yaml);
        assert_eq!(
            parsed,
            serde_json::to_value(&servers).unwrap(),
            "{value:?}\n{yaml}"
        );
        let mut strings = Vec::new();
        collect_strings(&parsed, &mut strings);
        // socks, anytls and naive: each username/name + password
        assert!(
            strings
                .iter()
                .filter(|text| text.as_str() == *value)
                .count()
                >= 6,
            "{value:?} did not survive as a string:\n{yaml}"
        );
        let typed: Vec<ServerConfig> = from_yaml(&yaml);
        assert_eq!(serde_json::to_value(&typed).unwrap(), parsed, "{value:?}");
        for (server, profile) in &pairs {
            let documents =
                profile_documents(std::slice::from_ref(server), std::slice::from_ref(profile))
                    .unwrap();
            let aggregate =
                aggregate_profile_documents(&documents, std::slice::from_ref(profile)).unwrap();
            assert_eq!(
                yaml_to_json(&aggregate),
                serde_json::to_value([server]).unwrap()
            );
            if let Ok(clash) = client::render(profile, ClientFormat::ClashMeta, EXPORT_SERVER) {
                let mut exported = Vec::new();
                collect_strings(&yaml_to_json(&clash), &mut exported);
                assert!(
                    exported.iter().any(|text| text == value),
                    "{value:?} lost in Clash Meta export:\n{clash}"
                );
            }
        }

        let Some(binary) = std::env::var_os("PING_RUST_SHOES_E2E_BIN") else {
            continue;
        };
        let path = directory.path().join("special.yaml");
        fs::write(&path, &yaml).unwrap();
        let output = std::process::Command::new(&binary)
            .arg("--dry-run")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "shoes rejected {value:?}: {}\n{yaml}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Writes raw (unscrubbed) fixtures to `$PING_RUST_YAML_FIXTURE_OUT`.
/// Credentials are then replaced by fixed test values with
/// `scripts/dev/scrub-yaml-fixtures.py` (see tests/fixtures/yaml/README.md).
#[test]
#[ignore]
fn regenerate_yaml_fixtures() {
    let Some(out) = std::env::var_os("PING_RUST_YAML_FIXTURE_OUT") else {
        return;
    };
    let out = PathBuf::from(out);
    let parent = PathBuf::from("/etc/shoes/fixtures");
    let certificates = tempfile::tempdir().unwrap();
    let mut requests = Vec::new();
    for protocol in Protocol::all() {
        let mut request = tests::request(protocol, parent.join("unused.yaml"));
        match protocol {
            Protocol::AnyTls => {
                request.options.anytls_users = vec![
                    AnyTlsUser {
                        name: "alice".to_owned(),
                        password: "placeholder".to_owned(),
                    },
                    AnyTlsUser {
                        name: "bob".to_owned(),
                        password: "placeholder".to_owned(),
                    },
                ];
            }
            Protocol::NaiveProxy => request.options.naive_self_signed = true,
            _ => {}
        }
        requests.push((protocol.slug().to_owned(), request));
    }
    let mut extra = tests::request(Protocol::Shadowsocks, parent.join("unused.yaml"));
    extra.options.shadowsocks_mode = ShadowsocksMode::ShadowTlsV3;
    requests.push(("shadowsocks-shadowtls".to_owned(), extra));
    let mut extra = tests::request(Protocol::AnyTls, parent.join("unused.yaml"));
    extra.options.anytls_mode = AnyTlsMode::Reality;
    extra.options.anytls_users = vec![generated_anytls_user("default")];
    requests.push(("anytls-reality".to_owned(), extra));
    let mut extra = tests::request(Protocol::Socks5, parent.join("unused.yaml"));
    extra.options.socks5_no_auth = true;
    requests.push(("socks5-no-auth".to_owned(), extra));

    let mut servers = Vec::new();
    let mut profiles = Vec::new();
    for (index, (label, mut request)) in requests.into_iter().enumerate() {
        request.port = 20_000 + index as u16;
        let profile_id = Uuid::from_u128(0x1000 + index as u128);
        let generated = presets::generate(&request, certificates.path(), profile_id).unwrap();
        servers.push(generated.server);
        profiles.push(ManagedProfile {
            h2mux: Default::default(),
            id: profile_id,
            name: format!("golden-{label}"),
            port: request.port,
            server_address: None,
            credentials: generated.credentials,
            certificate_path: generated.certificate_path,
            certificate_key_path: generated.certificate_key_path,
            self_signed_certificate: request
                .protocol
                .requires_certificate(request.options.anytls_mode),
            naive_certificate_validity: generated.naive_certificate_validity,
        });
    }
    let certificate_dir = certificates.path().display().to_string();
    let state = ManagedState {
        schema_version: 2,
        profiles: profiles.clone(),
        chain_proxy: ChainProxyState::default(),
    };
    // Typical Chain 2.0 topology: two chains, a pool, CIDR / hostname /
    // block / round-robin rules and a chained default route.
    let mut nodes = [
        "socks5://chain-user:chain-pass@198.51.100.1:1080#first",
        "trojan://chain-trojan@198.51.100.2:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com&sni=example.com#second",
        "vless://00000000-0000-4000-8000-0000000000c3@198.51.100.3:443?security=reality&type=tcp&sni=www.cloudflare.com&pbk=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc&sid=0123456789abcdef&flow=xtls-rprx-vision#third",
    ]
    .map(|uri| parse_share_uri(uri).unwrap());
    for (index, node) in nodes.iter_mut().enumerate() {
        node.id = Uuid::from_u128(0xc000 + index as u128);
    }
    let [first, second, third] = nodes;
    let pool = ChainPool {
        id: Uuid::from_u128(0xd001),
        name: "exit pool".to_owned(),
        members: vec![second.id, third.id],
    };
    let chain_a = ChainDefinition {
        id: Uuid::from_u128(0xe001),
        name: "two hop".to_owned(),
        hops: vec![ChainHop::Node(first.id), ChainHop::Pool(pool.id)],
    };
    let chain_b = ChainDefinition {
        id: Uuid::from_u128(0xe002),
        name: "single hop".to_owned(),
        hops: vec![ChainHop::Node(third.id)],
    };
    let mut chain = ChainProxyState {
        nodes: vec![first, second, third],
        pools: vec![pool],
        chains: vec![chain_a.clone(), chain_b.clone()],
        ..ChainProxyState::default()
    };
    let rule = |n: u128, name: &str, masks: &[&str], target: RouteTarget| RoutingRule {
        id: Uuid::from_u128(0xf000 + n),
        name: name.to_owned(),
        enabled: true,
        masks: masks.iter().map(|mask| (*mask).to_owned()).collect(),
        target,
    };
    chain.rules = vec![
        rule(
            1,
            "private",
            &["192.168.0.0/16", "10.0.0.0/8"],
            RouteTarget::Direct,
        ),
        rule(2, "blocked", &["blocked.test"], RouteTarget::Block),
        rule(
            3,
            "hostname",
            &["*.example.com"],
            RouteTarget::Chain(chain_a.id),
        ),
        rule(
            4,
            "round robin",
            &["2001:db8::/32"],
            RouteTarget::RoundRobin(vec![chain_a.id, chain_b.id]),
        ),
    ];
    chain.default_route = RouteTarget::Chain(chain_a.id);
    chain.enabled = true;
    chain.validate().unwrap();
    let chained = profiles
        .iter()
        .zip(&servers)
        .filter(|(profile, _)| {
            matches!(
                profile.protocol(),
                Protocol::Reality | Protocol::Shadowsocks | Protocol::TrojanTls
            )
        })
        .map(|(profile, server)| (profile.clone(), server.clone()))
        .collect::<Vec<_>>();
    let chain_state = ManagedState {
        schema_version: 2,
        profiles: chained.iter().map(|(profile, _)| profile.clone()).collect(),
        chain_proxy: chain,
    };
    let raw = |relative: &str, contents: String| {
        let path = out.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            contents.replace(&certificate_dir, "/etc/shoes/fixtures"),
        )
        .unwrap();
    };
    raw(
        "compat/state.json",
        serde_json::to_string_pretty(&state).unwrap() + "\n",
    );
    raw("compat/config.yaml", to_yaml(&servers));
    raw(
        "chain-v2/state.json",
        serde_json::to_string_pretty(&chain_state).unwrap() + "\n",
    );
}

/// Rebuilds every derived fixture from the (scrubbed) inputs
/// `compat/state.json`, `compat/config.yaml` and `chain-v2/state.json` in
/// `$PING_RUST_YAML_FIXTURE_OUT`, using the production code paths.
#[test]
#[ignore]
fn derive_yaml_fixtures() {
    let Some(out) = std::env::var_os("PING_RUST_YAML_FIXTURE_OUT") else {
        return;
    };
    let out = PathBuf::from(out);
    let write = |relative: &str, contents: &str| {
        let path = out.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    };
    let write_json = |relative: &str, value: &Json| {
        write(
            relative,
            &(serde_json::to_string_pretty(value).unwrap() + "\n"),
        );
    };
    let state = load_state_from(&out.join("compat/state.json")).unwrap();
    let servers = load_servers(&out.join("compat/config.yaml")).unwrap();
    ensure_servers_match_state(&servers, &state.profiles).unwrap();
    let config = to_yaml(&servers);
    write("compat/config.yaml", &config);
    write_json("compat/config.json", &yaml_to_json(&config));
    let documents = profile_documents(&servers, &state.profiles).unwrap();
    let _ = fs::remove_dir_all(out.join("compat/profiles"));
    let mut profile_values = serde_json::Map::new();
    for (name, contents) in &documents {
        let text = std::str::from_utf8(contents).unwrap();
        write(&format!("compat/profiles/{name}"), text);
        profile_values.insert(name.clone(), yaml_to_json(text));
    }
    write_json("compat/profiles.json", &Json::Object(profile_values));

    let _ = fs::remove_dir_all(out.join("golden/clients"));
    let mut clients = serde_json::Map::new();
    for profile in &state.profiles {
        for (format, label) in FORMATS {
            if let Ok(text) = client::render(profile, format, EXPORT_SERVER) {
                if matches!(format, ClientFormat::ClashMeta) {
                    write(
                        &format!("golden/clients/{}.{label}.yaml", profile.name),
                        &text,
                    );
                }
                clients.insert(
                    format!("{}.{label}", profile.name),
                    client_export_value(format, &text),
                );
            }
        }
    }
    write_json("golden/clients.json", &Json::Object(clients));

    let chain_state = load_state_from(&out.join("chain-v2/state.json")).unwrap();
    let mut chain_servers = chain_state
        .profiles
        .iter()
        .map(|chained| {
            let index = state
                .profiles
                .iter()
                .position(|profile| profile.id == chained.id)
                .unwrap();
            servers[index].clone()
        })
        .collect::<Vec<_>>();
    apply_chain_proxy_rules(&mut chain_servers, &chain_state);
    let chain_yaml = to_yaml(&chain_servers);
    write("chain-v2/config.yaml", &chain_yaml);
    write_json("chain-v2/config.json", &yaml_to_json(&chain_yaml));
}
