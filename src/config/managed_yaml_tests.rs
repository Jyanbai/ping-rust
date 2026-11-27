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
async fn managed_restore_rebuilds_profile_with_unmodeled_fields() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let (state, entries) = write_fixture(path).await;
    let missing = profile_file(path, &state.profiles[0]);
    fs::remove_file(&missing).unwrap();
    assert!(prepare_managed_snapshot(path).unwrap());
    validate_managed_snapshot(
        &path.join("config.yaml"),
        &path.join("ping-rust-state.json"),
    )
    .unwrap();
    assert!(read_entries(path) == entries);
    assert!(read_yaml::<Value>(&missing) == entries[0]);
    assert!(!prepare_managed_snapshot(path).unwrap());
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
        let held = lock(path);
        let before = hashes(path);
        let edit = update_profile_at(
            path,
            state.profiles[1].id,
            ProfileChange::Port(1081),
            held,
            false,
        )
        .await
        .err()
        .unwrap();
        let chain =
            update_chain_proxy_at(path, ChainProxyChange::SetEnabled(true), lock(path), false)
                .await
                .err()
                .unwrap();
        let ensure = ensure_profile_files_at(path, false).await.unwrap_err();
        let restore = prepare_managed_snapshot(path).unwrap_err();
        let upgrade = migrate_managed_config_at(path, &path.join("no-shoes"))
            .await
            .err()
            .unwrap();
        for error in [edit, chain, ensure, restore, upgrade] {
            let error = format!("{error:#}");
            assert!(error.contains("config.yaml"));
            assert!(error.contains(&profile.config_file_name()));
            assert!(error.contains("第 1 项"));
            assert!(error.contains("protocol.encryption_limits"));
            assert!(!error.contains(MARKER));
        }
        assert_eq!(hashes(path), before);
    }
}

#[tokio::test]
async fn restoring_legacy_singular_client_chain_allows_adding_a_node() {
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
    assert!(!ensure_profile_files_at(path, true).await.unwrap());
    assert_eq!(hashes(path), before);

    fs::remove_file(&profile_path).unwrap();
    let original_state = fs::read(&state_path).unwrap();
    assert!(prepare_managed_snapshot(path).unwrap());
    validate_managed_snapshot(&path.join("config.yaml"), &state_path).unwrap();
    assert_eq!(fs::read(&state_path).unwrap(), original_state);
    assert!(
        load_state_from(&state_path)
            .unwrap()
            .chain_proxy
            .legacy_layout
    );
    assert!(read_yaml::<Value>(&profile_path) == read_entries(path)[0]);
    assert!(read_entries(path) == [expected]);
    write_yaml(&profile_path, &legacy);
    assert!(prepare_managed_snapshot(path).unwrap());
    assert!(read_yaml::<Value>(&profile_path) == read_entries(path)[0]);
    let added = generate_inner_with_lock(socks5_request(path, 3080), false, Some(lock(path)), path)
        .await
        .unwrap();
    assert_eq!(read_entries(path).len(), 2);
    drop(added);
}

#[tokio::test]
#[cfg(unix)]
async fn shoes_migration_changes_only_legacy_aliases_and_wildcard_masks() {
    use crate::chain_proxy::{RouteTarget, RoutingRule};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let (mut state, mut entries) = write_fixture(path).await;
    state.chain_proxy.enabled = true;
    state.chain_proxy.rules.push(RoutingRule {
        id: Uuid::new_v4(),
        name: "wildcard".to_owned(),
        enabled: true,
        masks: vec!["*.example.com".to_owned(), "203.0.113.0/24".to_owned()],
        target: RouteTarget::Direct,
    });
    let mut rules = crate::yaml::to_value(render_legacy_rules(&state.chain_proxy)).unwrap();
    let rule = rules[0].as_object_mut().unwrap();
    let client = rule.remove("client_chains").unwrap();
    rule.insert("client_chain".to_owned(), client.clone());
    rule.insert("hand_added".to_owned(), json!({"nested": MARKER}));
    for (entry, profile) in entries.iter_mut().zip(&state.profiles) {
        entry["rules"] = rules.clone();
        write_yaml(&profile_file(path, profile), entry);
    }
    write_yaml(&path.join("config.yaml"), &entries);
    let state_path = path.join("ping-rust-state.json");
    save_state_to(&state_path, &state).unwrap();
    let binary = path.join("mock-shoes");
    utils::atomic_write(
        &binary,
        b"#!/bin/sh\ntest \"$1\" = --dry-run && grep -q 'client_chains:' \"$2\" && ! grep -q 'client_chain:' \"$2\" && grep -q 'domain_pattern:' \"$2\" && grep -q 'encryption_limits:' \"$2\"\n",
        0o700,
    )
    .unwrap();
    migrate_managed_config_at(path, &binary)
        .await
        .unwrap()
        .finish();

    let rule = rules[0].as_object_mut().unwrap();
    rule.remove("client_chain");
    rule.insert("client_chains".to_owned(), client);
    rules[0]["masks"][0] = json!({"domain_pattern": ["*.example.com"]});
    for (entry, profile) in entries.iter_mut().zip(&state.profiles) {
        entry["rules"] = rules.clone();
        assert!(read_yaml::<Value>(&profile_file(path, profile)) == *entry);
    }
    assert!(read_entries(path) == entries);
    validate_managed_snapshot(&path.join("config.yaml"), &state_path).unwrap();
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
    assert!(!ensure_profile_files_at(path, true).await.unwrap());
    assert_eq!(hashes(path), before);
    for file in before.keys() {
        assert_eq!(fs::metadata(file).unwrap().modified().unwrap(), timestamp);
    }
}

#[tokio::test]
async fn chain_update_changes_only_rules_and_keeps_unmodeled_fields() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let (state, mut entries) = write_fixture(path).await;
    let result = update_chain_proxy_at(path, ChainProxyChange::SetEnabled(true), lock(path), false)
        .await
        .unwrap();
    assert!(result.configuration_changed);
    let rules = crate::yaml::to_value(render_rules(&result.state.chain_proxy)).unwrap();
    for (entry, profile) in entries.iter_mut().zip(&state.profiles) {
        assert_ne!(entry["rules"], rules);
        entry["rules"] = rules.clone();
        assert!(read_yaml::<Value>(&profile_file(path, profile)) == *entry);
    }
    assert!(read_entries(path) == entries);
}

#[tokio::test]
async fn chain_update_preserves_unique_rules_and_rejects_ambiguous_ones() {
    use crate::chain_proxy::{RouteTarget, RoutingRule};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let (mut state, mut entries) = write_fixture(path).await;
    let pinned = RoutingRule {
        id: Uuid::new_v4(),
        name: "annotated".to_owned(),
        enabled: true,
        masks: vec!["203.0.113.0/24".to_owned()],
        target: RouteTarget::Direct,
    };
    let second = RoutingRule {
        id: Uuid::new_v4(),
        name: "another".to_owned(),
        masks: vec!["example.com".to_owned()],
        ..pinned.clone()
    };
    state.chain_proxy.enabled = true;
    state.chain_proxy.rules = vec![pinned.clone(), second.clone()];
    let mut rules = crate::yaml::to_value(render_rules(&state.chain_proxy)).unwrap();
    rules[0]["hand_added"] = json!(MARKER);
    for (entry, profile) in entries.iter_mut().zip(&state.profiles) {
        entry["rules"] = rules.clone();
        write_yaml(&profile_file(path, profile), entry);
    }
    write_yaml(&path.join("config.yaml"), &entries);
    save_state_to(&path.join("ping-rust-state.json"), &state).unwrap();
    let result = update_chain_proxy_at(
        path,
        ChainProxyChange::SetRules(vec![second.clone(), pinned.clone()]),
        lock(path),
        false,
    )
    .await
    .unwrap();
    assert!(result.configuration_changed);
    drop(result);
    rules.as_array_mut().unwrap().swap(0, 1);
    for (entry, profile) in read_entries(path).iter().zip(&state.profiles) {
        assert!(entry["rules"] == rules);
        assert!(read_yaml::<Value>(&profile_file(path, profile)) == *entry);
    }

    let held = lock(path);
    let before = hashes(path);
    let duplicate = RoutingRule {
        id: Uuid::new_v4(),
        name: "duplicate".to_owned(),
        ..pinned.clone()
    };
    let error = update_chain_proxy_at(
        path,
        ChainProxyChange::SetRules(vec![second, pinned, duplicate]),
        held,
        false,
    )
    .await
    .err()
    .unwrap();
    let error = format!("{error:#}");
    assert!(
        error.contains("config.yaml 第 1 项（字段路径：$.rules[1]）"),
        "{error}"
    );
    assert!(!error.contains(MARKER));
    assert_eq!(hashes(path), before);
}

#[tokio::test]
async fn ensure_profiles_rebuilds_missing_copy_with_unmodeled_fields() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let (state, entries) = write_fixture(path).await;
    let missing = profile_file(path, &state.profiles[0]);
    fs::remove_file(&missing).unwrap();
    let original = fs::read(path.join("config.yaml")).unwrap();
    let state_path = path.join("ping-rust-state.json");
    assert!(socks5::listen_migration_pending(&state_path).unwrap());
    assert!(ensure_profile_files_at(path, false).await.unwrap());
    assert!(!socks5::listen_migration_pending(&state_path).unwrap());
    assert_eq!(fs::read(path.join("config.yaml")).unwrap(), original);
    assert!(read_yaml::<Value>(&missing) == entries[0]);
}

fn lock(directory: &Path) -> utils::ExclusiveLock {
    utils::exclusive_lock(&directory.join("lock")).unwrap()
}
