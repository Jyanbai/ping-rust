use std::collections::BTreeMap;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;

const MARKER: &str = "fixture-value-must-not-appear-in-errors";

fn socks5_request(directory: &Path, port: u16) -> GenerationRequest {
    let mut request = tests::request(Protocol::Socks5, directory.join("config.yaml"));
    request.port = port;
    request.options.socks5_no_auth = true;
    request.options.udp_enabled = false;
    request
}

pub(super) async fn write_fixture(directory: &Path) -> (ManagedState, Vec<Value>) {
    let (vless, vless_profile) = vless_encryption_tests::sample(false);
    let mut socks = generate_inner(socks5_request(directory, 1080), false)
        .await
        .unwrap();
    let mut servers = vec![
        crate::yaml::to_value(vless).unwrap(),
        read_entries(directory).remove(0),
    ];
    let last = generate_inner(socks5_request(directory, 2080), false)
        .await
        .unwrap();
    servers.push(read_entries(directory).remove(0));
    servers[0]["protocol"]["encryption_limits"] = json!({"test_limit": MARKER});
    servers[1]["address"] = json!("0.0.0.0:1080");
    let Credentials::Socks5 { listen, .. } = &mut socks.profile.credentials else {
        unreachable!();
    };
    *listen = None;
    socks.profile.server_address = Some("proxy.example.com".to_owned());
    let state = ManagedState {
        profiles: vec![vless_profile, socks.profile, last.profile],
        ..Default::default()
    };
    fs::create_dir(directory.join("profiles")).unwrap();
    for (profile, server) in state.profiles.iter().zip(&servers) {
        write_yaml(&profile_file(directory, profile), server);
    }
    write_yaml(&directory.join("config.yaml"), &servers);
    save_state_to(&directory.join("ping-rust-state.json"), &state).unwrap();
    (state, servers)
}

fn write_yaml(path: &Path, value: &impl Serialize) {
    fs::write(path, crate::yaml::to_string(value).unwrap()).unwrap();
}

fn read_yaml<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    crate::yaml::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn read_entries(directory: &Path) -> Vec<Value> {
    read_yaml(&directory.join("config.yaml"))
}

fn profile_file(directory: &Path, profile: &ManagedProfile) -> PathBuf {
    directory.join("profiles").join(profile.config_file_name())
}

pub(super) fn hashes(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(directory: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(&path, output);
            } else {
                output.insert(
                    path.clone(),
                    Sha256::digest(fs::read(path).unwrap()).to_vec(),
                );
            }
        }
    }
    let mut output = BTreeMap::new();
    collect(directory, &mut output);
    output
}

pub(super) fn assert_refused_without_writes(
    error: anyhow::Error,
    directory: &Path,
    before: &BTreeMap<PathBuf, Vec<u8>>,
) {
    let error = format!("{error:#}");
    assert!(
        error.contains("该操作暂不支持保留手工添加的字段"),
        "{error}"
    );
    assert!(!error.contains(MARKER));
    assert_eq!(&hashes(directory), before);
}

#[tokio::test]
async fn aggregating_profiles_keeps_their_unmodeled_fields() {
    let directory = tempfile::tempdir().unwrap();
    let (_, servers) = write_fixture(directory.path()).await;
    let state = load_state_from(&directory.path().join("ping-rust-state.json")).unwrap();
    let documents = ProfileDirectorySnapshot::capture(&directory.path().join("profiles"))
        .unwrap()
        .files;
    let aggregate = aggregate_profile_documents(&documents, &state.profiles).unwrap();
    let actual: Vec<Value> = crate::yaml::from_str(&aggregate).unwrap();
    assert!(actual == servers, "聚合配置必须保留完整的节点 YAML Value");
}

#[tokio::test]
async fn managed_restore_preparation_refuses_unmodeled_fields() {
    let directory = tempfile::tempdir().unwrap();
    write_fixture(directory.path()).await;
    let before = hashes(directory.path());
    let error = prepare_managed_snapshot(directory.path()).unwrap_err();
    assert_refused_without_writes(error, directory.path(), &before);
}

#[tokio::test]
async fn managed_add_edit_and_delete_preserve_other_nodes_and_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let (state, mut expected) = write_fixture(path).await;
    let preserved = serde_json::to_value(&state.profiles[0]).unwrap();
    expected[1]["protocol"]["hand_added"] = json!({"nested": MARKER});
    write_yaml(&path.join("config.yaml"), &expected);
    write_yaml(&profile_file(path, &state.profiles[1]), &expected[1]);
    let missing = profile_file(path, &state.profiles[2]);
    fs::remove_file(&missing).unwrap();

    let added = generate_inner_with_lock(socks5_request(path, 3080), false, Some(lock(path)), path)
        .await
        .unwrap();
    let added_id = added.profile_id;
    drop(added);
    let after_add = read_entries(path);
    assert!(after_add[..3] == expected);
    assert_eq!(after_add[3]["address"], "127.0.0.1:3080");
    assert!(read_yaml::<Value>(&missing) == expected[2]);
    assert!(read_yaml::<Value>(&profile_file(path, &state.profiles[0])) == expected[0]);
    expected.push(after_add[3].clone());

    let target = state.profiles[1].id;
    let edited = update_profile_at(path, target, ProfileChange::Port(1081), lock(path), false)
        .await
        .unwrap();
    assert!(edited.runtime_config_changed);
    assert_eq!(edited.profile_id, target);
    assert!(!profile_file(path, &state.profiles[1]).exists());
    expected[1]["address"] = json!("0.0.0.0:1081");
    assert!(read_entries(path) == expected);
    assert!(read_yaml::<Value>(&profile_file(path, &edited.profile)) == expected[1]);
    assert!(read_yaml::<Value>(&profile_file(path, &state.profiles[0])) == expected[0]);
    drop(edited);

    let deleted = delete_profile_at(path, target, lock(path), false)
        .await
        .unwrap();
    assert_eq!(deleted.profile.id, target);
    assert!(!profile_file(path, &deleted.profile).exists());
    expected.remove(1);
    assert!(read_entries(path) == expected);
    let saved = load_state_from(&path.join("ping-rust-state.json")).unwrap();
    assert_eq!(
        saved
            .profiles
            .iter()
            .map(|profile| profile.id)
            .collect::<Vec<_>>(),
        vec![state.profiles[0].id, state.profiles[2].id, added_id]
    );
    assert!(serde_json::to_value(&saved.profiles[0]).unwrap() == preserved);
    for (profile, entry) in saved.profiles.iter().zip(expected) {
        assert!(read_yaml::<Value>(&profile_file(path, profile)) == entry);
    }
}

#[tokio::test]
async fn conflicting_profile_copies_are_refused_without_exposing_values() {
    for change_aggregate in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let (state, mut servers) = write_fixture(path).await;
        servers[0]["protocol"]
            .as_object_mut()
            .unwrap()
            .remove("encryption_limits");
        let profile = &state.profiles[0];
        if change_aggregate {
            write_yaml(&path.join("config.yaml"), &servers);
        } else {
            write_yaml(&profile_file(path, profile), &servers[0]);
        }
        let lock = lock(path);
        let before = hashes(path);
        let result = update_profile_at(
            path,
            state.profiles[1].id,
            ProfileChange::Port(1081),
            lock,
            false,
        )
        .await;
        let error = format!("{:#}", result.err().unwrap());
        assert!(error.contains("config.yaml"));
        assert!(error.contains(&profile.config_file_name()));
        assert!(error.contains("第 1 项"));
        assert!(error.contains("protocol.encryption_limits"));
        assert!(!error.contains(MARKER));
        assert_eq!(hashes(path), before);
    }
}

#[tokio::test]
async fn legacy_singular_client_chain_can_be_migrated() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let (mut server, profile) = tests::reality_server_and_profile(53453);
    let node = crate::chain_proxy::parse_share_uri("socks5://proxy.example.com:1080#old").unwrap();
    server.rules = chain_rules(&node.client);
    let expected = crate::yaml::to_value(&server).unwrap();
    let mut legacy = expected.clone();
    let rule = legacy["rules"][0].as_object_mut().unwrap();
    let client = rule.remove("client_chains").unwrap();
    rule.insert("client_chain".to_owned(), client);
    fs::create_dir(path.join("profiles")).unwrap();
    let profile_path = profile_file(path, &profile);
    write_yaml(&profile_path, &legacy);
    write_yaml(&path.join("config.yaml"), &[&legacy]);
    let state_path = path.join("ping-rust-state.json");
    fs::write(
        &state_path,
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "profiles": [profile],
            "chain_proxy": {"enabled": true, "active_node": node.id, "nodes": [node]}
        }))
        .unwrap(),
    )
    .unwrap();

    let before = hashes(path);
    assert!(!ensure_profile_files_at(path).await.unwrap());
    assert_eq!(hashes(path), before);

    let (servers, state, _, complete) = ManagedYaml::load(path).unwrap().into_legacy(true).unwrap();
    assert!(complete);
    assert!(state.chain_proxy.legacy_layout);
    assert!(crate::yaml::to_value(&servers[0]).unwrap() == expected);

    #[cfg(unix)]
    {
        let binary = path.join("mock-shoes");
        utils::atomic_write(
            &binary,
            b"#!/bin/sh\ntest \"$1\" = --dry-run && grep -q 'client_chains:' \"$2\" && ! grep -q 'client_chain:' \"$2\"\n",
            0o700,
        )
        .unwrap();
        migrate_managed_config_at(path, &binary)
            .await
            .unwrap()
            .finish();
        assert!(read_entries(path) == [expected.clone()]);
        assert!(read_yaml::<Value>(&profile_path) == expected);
        assert!(
            load_state_from(&state_path)
                .unwrap()
                .chain_proxy
                .legacy_layout
        );
    }

    legacy["rules"][0]["hand_added"] = json!({"nested": MARKER});
    write_yaml(&profile_path, &legacy);
    write_yaml(&path.join("config.yaml"), &[&legacy]);
    let before = hashes(path);
    let result = ManagedYaml::load(path).unwrap().into_legacy(true);
    assert_refused_without_writes(result.err().unwrap(), path, &before);
}

#[tokio::test]
async fn managed_add_migrates_legacy_wildcard_rules_for_every_node() {
    use crate::chain_proxy::{RouteTarget, RoutingRule};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let (mut state, mut entries) = write_fixture(path).await;
    state.chain_proxy.enabled = true;
    state.chain_proxy.rules.push(RoutingRule {
        id: Uuid::new_v4(),
        name: "wildcard".to_owned(),
        enabled: true,
        masks: vec!["*.example.com".to_owned()],
        target: RouteTarget::Direct,
    });
    let legacy = crate::yaml::to_value(render_legacy_rules(&state.chain_proxy)).unwrap();
    assert_eq!(legacy[0]["masks"], "*.example.com");
    for (entry, profile) in entries.iter_mut().zip(&state.profiles) {
        entry["rules"] = legacy.clone();
        write_yaml(&profile_file(path, profile), entry);
    }
    write_yaml(&path.join("config.yaml"), &entries);
    save_state_to(&path.join("ping-rust-state.json"), &state).unwrap();

    let added = generate_inner_with_lock(socks5_request(path, 3080), false, Some(lock(path)), path)
        .await
        .unwrap();
    let actual = read_entries(path);
    assert_eq!(actual.len(), entries.len() + 1);
    let expected_rules = crate::yaml::to_value(render_rules(&state.chain_proxy)).unwrap();
    assert_eq!(
        expected_rules[0]["masks"]["domain_pattern"],
        json!(["*.example.com"])
    );
    for (entry, profile) in actual
        .iter()
        .zip(state.profiles.iter().chain([&added.profile]))
    {
        assert_eq!(entry["rules"], expected_rules);
        assert!(read_yaml::<Value>(&profile_file(path, profile)) == *entry);
    }
    for (mut original, migrated) in entries.into_iter().zip(actual) {
        original["rules"] = expected_rules.clone();
        assert!(original == migrated);
    }
}

#[tokio::test]
async fn current_profile_copies_with_unmodeled_fields_need_no_writes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let (_, entries) = write_fixture(path).await;
    assert!(entries[0]["protocol"].get("encryption_limits").is_some());
    let state_path = path.join("ping-rust-state.json");
    save_state_to(&state_path, &load_state_from(&state_path).unwrap()).unwrap();
    assert!(!socks5::listen_migration_pending(&state_path).unwrap());

    let before = hashes(path);
    let timestamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(946_684_800);
    for file in before.keys() {
        fs::OpenOptions::new()
            .write(true)
            .open(file)
            .unwrap()
            .set_modified(timestamp)
            .unwrap();
    }
    assert!(!ensure_profile_files_at(path).await.unwrap());
    assert_eq!(hashes(path), before);
    for file in before.keys() {
        assert_eq!(fs::metadata(file).unwrap().modified().unwrap(), timestamp);
    }
}

#[tokio::test]
async fn legacy_chain_and_profile_migration_refuse_unmodeled_fields() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    write_fixture(path).await;
    let lock = lock(path);
    let before = hashes(path);
    let result = update_chain_proxy_at(path, ChainProxyChange::SetRules(Vec::new()), lock).await;
    assert_refused_without_writes(result.err().unwrap(), path, &before);
    assert!(socks5::listen_migration_pending(&path.join("ping-rust-state.json")).unwrap());
    let error = ensure_profile_files_at(path).await.unwrap_err();
    assert_refused_without_writes(error, path, &before);
    let migration = ManagedYaml::load(path).unwrap().into_legacy(true);
    assert_refused_without_writes(migration.err().unwrap(), path, &before);
}

fn lock(directory: &Path) -> utils::ExclusiveLock {
    utils::exclusive_lock(&directory.join("lock")).unwrap()
}
