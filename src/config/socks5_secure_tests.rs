use super::schema::TlsTarget;
use super::socks5_secure::{SecureMode, SecurePlan};
use super::*;

fn legacy(directory: &Path) -> ManagedProfile {
    legacy_at(directory, 443)
}

fn legacy_at(directory: &Path, port: u16) -> ManagedProfile {
    legacy_bound_to(directory, port, "0.0.0.0")
}

fn legacy_bound_to(directory: &Path, port: u16, host: &str) -> ManagedProfile {
    let mut request = tests::request(Protocol::Socks5, directory.join("config.yaml"));
    request.options.socks5_no_auth = true;
    request.port = port;
    let generated = presets::generate(&request, directory, Uuid::nil()).unwrap();
    let mut server = generated.server;
    server.address = format!("{host}:{port}");
    let mut profile = ManagedProfile {
        id: Uuid::nil(),
        name: "legacy-socks".into(),
        port,
        server_address: None,
        credentials: generated.credentials,
        certificate_path: None,
        certificate_key_path: None,
        self_signed_certificate: false,
        naive_certificate_validity: None,
        h2mux: Default::default(),
    };
    profile.server_address = Some("203.0.113.8".into());
    let mut json = serde_json::to_value(ManagedState {
        profiles: vec![profile.clone()],
        ..Default::default()
    })
    .unwrap();
    json["profiles"][0]["credentials"]["Socks5"]
        .as_object_mut()
        .unwrap()
        .remove("listen");
    fs::write(
        directory.join("config.yaml"),
        crate::yaml::to_string(&vec![server]).unwrap(),
    )
    .unwrap();
    fs::write(
        directory.join("ping-rust-state.json"),
        serde_json::to_vec(&json).unwrap(),
    )
    .unwrap();
    profile
}

#[test]
fn socks5_secure_preview_hides_original_public_ipv4_and_ipv6() {
    for (host, loopback) in [("203.0.113.8", "127.0.0.1"), ("[2001:db8::8]", "[::1]")] {
        let directory = tempfile::tempdir().unwrap();
        let profile = legacy_bound_to(directory.path(), 443, host);
        for mode in [SecureMode::Auth, SecureMode::Local] {
            let diff = SecurePlan::prepare(directory.path(), profile.id, mode)
                .unwrap()
                .unwrap()
                .diff()
                .unwrap();
            let (profile_diff, aggregate_diff) = diff.split_once("--- config.yaml").unwrap();
            for section in [profile_diff, aggregate_diff] {
                assert!(!section.contains(host.trim_matches(['[', ']'])));
                assert!(section.contains("[REDACTED]:443"));
                if mode == SecureMode::Local {
                    assert!(section.contains(&format!("{loopback}:443")));
                }
            }
        }
    }
}

#[test]
fn socks5_secure_dry_run_redacts_both_diffs_and_never_writes() {
    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let warning = load_state_from(&directory.path().join("ping-rust-state.json"))
        .unwrap()
        .profiles[0]
        .socks5_risk_warning()
        .unwrap();
    assert!(warning.contains("prs socks5 secure"));
    let config = fs::read(directory.path().join("config.yaml")).unwrap();
    let state = fs::read(directory.path().join("ping-rust-state.json")).unwrap();
    let plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Auth)
        .unwrap()
        .unwrap();
    let diff = plan.diff().unwrap();
    let Credentials::Socks5 {
        username: Some(user),
        password: Some(pass),
        ..
    } = &plan.profile.credentials
    else {
        panic!()
    };
    assert!(diff.contains("profile"));
    assert!(diff.contains("config.yaml"));
    assert!(diff.contains("[REDACTED]"));
    assert!(!diff.contains(user));
    assert!(!diff.contains(pass));
    assert_eq!(
        fs::read(directory.path().join("config.yaml")).unwrap(),
        config
    );
    assert_eq!(
        fs::read(directory.path().join("ping-rust-state.json")).unwrap(),
        state
    );
    assert!(!directory.path().join("profiles").exists());
}

#[test]
fn socks5_secure_aggregate_preview_serializes_redacted_authentication() {
    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Auth)
        .unwrap()
        .unwrap();
    let diff = plan.diff().unwrap();
    let (_, aggregate_diff) = diff.split_once("+++ config.yaml\n").unwrap();
    let added_yaml = aggregate_diff
        .lines()
        .filter_map(|line| line.strip_prefix('+'))
        .collect::<Vec<_>>()
        .join("\n");
    let preview: Vec<serde_json::Value> = crate::yaml::from_str(&added_yaml).unwrap();

    assert_eq!(preview.len(), 1);
    assert_eq!(preview[0]["protocol"]["username"], "[REDACTED]");
    assert_eq!(preview[0]["protocol"]["password"], "[REDACTED]");
}

#[test]
fn socks5_secure_rejects_safe_state_with_unsafe_aggregate() {
    for mode in [SecureMode::Auth, SecureMode::Local] {
        let directory = tempfile::tempdir().unwrap();
        let profile = legacy(directory.path());
        let config_path = directory.path().join("config.yaml");
        let unsafe_config = fs::read(&config_path).unwrap();
        let mut plan = SecurePlan::prepare(directory.path(), profile.id, mode)
            .unwrap()
            .unwrap();
        plan.commit_files().unwrap();
        plan.publish_state().unwrap();
        fs::write(&config_path, &unsafe_config).unwrap();

        assert!(SecurePlan::already_secure(directory.path(), profile.id).is_err());
        assert!(SecurePlan::prepare(directory.path(), profile.id, mode).is_err());
        assert_eq!(fs::read(&config_path).unwrap(), unsafe_config);
    }
}

#[tokio::test]
async fn socks5_secure_already_safe_still_requires_noninteractive_mode() {
    use crate::cli::{Cli, Command, Socks5Command};
    use clap::Parser;

    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let mut plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Local)
        .unwrap()
        .unwrap();
    plan.commit_files().unwrap();
    plan.publish_state().unwrap();

    let lock = directory.path().join("ping-rust.lock");
    for (tty, dry_run, option, success) in [
        (true, false, Some("--yes"), false),
        (false, false, None, false),
        (false, true, None, false),
        (false, true, Some("--local"), true),
        (true, true, None, true),
    ] {
        let cli = Cli::try_parse_from(
            ["prs", "socks5", "secure", &profile.name]
                .into_iter()
                .chain(dry_run.then_some("--dry-run"))
                .chain(option),
        )
        .unwrap();
        let Some(Command::Socks5 {
            command: Socks5Command::Secure(args),
        }) = cli.command
        else {
            panic!("需要 SOCKS5 secure 命令");
        };
        let result = args.run_in(directory.path(), &lock, tty).await;
        if success {
            result.unwrap();
        } else {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("--auth 或 --local"));
        }
    }
    assert!(!lock.exists());
}

#[tokio::test]
async fn socks5_secure_checks_running_listener_when_legacy_disk_config_is_local() {
    use crate::cli::{Cli, Command, Socks5Command};
    use clap::Parser;

    let directory = tempfile::tempdir().unwrap();
    let profile = legacy_bound_to(directory.path(), 1080, "127.0.0.1");
    let state_path = directory.path().join("ping-rust-state.json");
    let config_path = directory.path().join("config.yaml");
    let original_state = fs::read(&state_path).unwrap();
    let original_config = fs::read(&config_path).unwrap();
    let state: serde_json::Value = serde_json::from_slice(&original_state).unwrap();
    assert!(state["profiles"][0]["credentials"]["Socks5"]
        .get("listen")
        .is_none());

    for (running, safe) in [("0.0.0.0:1080", false), ("127.0.0.1:1080", true)] {
        let cli =
            Cli::try_parse_from(["prs", "socks5", "secure", &profile.name, "--local"]).unwrap();
        let Some(Command::Socks5 {
            command: Socks5Command::Secure(args),
        }) = cli.command
        else {
            panic!("需要 SOCKS5 secure 命令");
        };
        let verified = std::cell::Cell::new(false);
        let result = args
            .run_in_with_verifier(
                directory.path(),
                &directory.path().join("ping-rust.lock"),
                false,
                || Ok(()),
                async |profile: &ManagedProfile| {
                    verified.set(true);
                    let expected = profile.listen_address()?.parse()?;
                    assert_eq!(expected, "127.0.0.1:1080".parse::<std::net::SocketAddr>()?);
                    let sockets =
                        format!("LISTEN 0 128 {running} *:* users:((\"shoes\",pid=42,fd=7))");
                    crate::socks5_secure::check_listeners(&sockets, expected, 42)
                },
            )
            .await;
        assert!(verified.get());
        assert_eq!(result.is_ok(), safe);
        if let Err(error) = result {
            assert!(format!("{error:#}").contains("实际监听地址不符合预期"));
        }
        assert_eq!(fs::read(&state_path).unwrap(), original_state);
        assert_eq!(fs::read(&config_path).unwrap(), original_config);
        assert!(!directory.path().join("profiles").exists());
    }
}

#[test]
fn socks5_secure_dry_run_hides_other_listeners_chain_exits_and_tls_targets() {
    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let config_path = directory.path().join("config.yaml");
    let state_path = directory.path().join("ping-rust-state.json");
    let mut state = load_state_from(&state_path).unwrap();
    let mut servers = load_servers(&config_path).unwrap();
    let (mut reality, reality_profile) = tests::reality_server_and_profile(53459);
    let ServerProtocol::Tls {
        reality_targets,
        tls_targets,
        ..
    } = &mut reality.protocol
    else {
        panic!("需要 TLS 节点");
    };
    let (_, mut target) = reality_targets.pop_first().unwrap();
    target.dest = "backend.example.com:35443".into();
    reality_targets.insert("sni.example.com".into(), target);
    tls_targets.insert(
        "tls.example.com".into(),
        TlsTarget {
            cert: "example.crt".into(),
            key: "example.key".into(),
            alpn_protocols: vec![],
            vision: false,
            protocol: InnerProtocol::Trojan {
                password: "fixture-password".into(),
            },
        },
    );
    let mut request = tests::request(Protocol::Shadowsocks, config_path.clone());
    request.port = 53460;
    request.server_name = "shadow-sni.example.com".into();
    request.options.shadowsocks_mode = ShadowsocksMode::ShadowTlsV3;
    request.options.shadowtls_handshake = Some("handshake.example.com:36443".into());
    let generated = presets::generate(&request, directory.path(), Uuid::new_v4()).unwrap();
    let mut shadow = reality_profile.clone();
    shadow.id = Uuid::new_v4();
    shadow.port = request.port;
    shadow.credentials = generated.credentials;
    state.profiles.extend([reality_profile, shadow]);
    servers.extend([reality, generated.server]);

    let exit =
        crate::chain_proxy::parse_share_uri("socks5://alice:secret@exit.example.com:39080#exit")
            .unwrap();
    let exit_id = exit.id;
    state
        .chain_proxy
        .apply(ChainProxyChange::Add(exit))
        .unwrap();
    state
        .chain_proxy
        .apply(ChainProxyChange::Select(exit_id))
        .unwrap();
    state
        .chain_proxy
        .apply(ChainProxyChange::SetEnabled(true))
        .unwrap();
    apply_chain_proxy_rules(&mut servers, &state);
    let config = crate::yaml::to_string(&servers).unwrap();
    fs::write(&config_path, &config).unwrap();
    save_state_to(&state_path, &state).unwrap();

    let diff = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Local)
        .unwrap()
        .unwrap()
        .diff()
        .unwrap();
    assert!(diff.contains("0.0.0.0:443"));
    assert!(diff.contains("127.0.0.1:443"));
    for private in ["53459", "53460", "35443", "36443", "39080", "example.com"] {
        assert!(config.contains(private));
        assert!(!diff.contains(private));
    }
}

#[test]
fn socks5_secure_persists_safety_across_port_edit_and_rebuild() {
    for mode in [SecureMode::Auth, SecureMode::Local] {
        let directory = tempfile::tempdir().unwrap();
        let profile = legacy(directory.path());
        let mut plan = SecurePlan::prepare(directory.path(), profile.id, mode)
            .unwrap()
            .unwrap();
        plan.commit_files().unwrap();
        plan.publish_state().unwrap();
        let path = directory.path().join("ping-rust-state.json");
        let mut state = load_state_from(&path).unwrap();
        let mut servers = load_servers(&directory.path().join("config.yaml")).unwrap();
        let json = serde_json::to_value(&state).unwrap();
        assert!(json["profiles"][0]["credentials"]["Socks5"]["listen"]
            .get("legacy_public_address")
            .is_none());
        apply_profile_change(
            &mut servers[0],
            &mut state.profiles[0],
            ProfileChange::Port(1080),
        )
        .unwrap();
        let documents = profile_documents(&servers, &state.profiles).unwrap();
        let yaml = aggregate_profile_documents(&documents, &state.profiles).unwrap();
        ensure_servers_match_state(
            &crate::yaml::from_str::<Vec<ServerConfig>>(&yaml).unwrap(),
            &state.profiles,
        )
        .unwrap();
        assert!(state.profiles[0].socks5_risk_warning().is_none());
        match mode {
            SecureMode::Auth => {
                assert_eq!(servers[0].address, "0.0.0.0:1080");
                assert!(apply_profile_change(
                    &mut servers[0],
                    &mut state.profiles[0],
                    ProfileChange::Socks5Authentication(false)
                )
                .is_err());
            }
            SecureMode::Local => {
                assert_eq!(servers[0].address, "127.0.0.1:1080");
                assert_eq!(
                    state.profiles[0].server_address.as_deref(),
                    Some("127.0.0.1")
                );
            }
        }
        commit_managed_with_state_writer(
            &directory.path().join("config.yaml"),
            &path,
            &directory.path().join("profiles"),
            &servers,
            &state,
            save_state_to,
        )
        .unwrap();
        let saved = load_state_from(&path).unwrap();
        assert_eq!(saved.profiles[0].port, 1080);
        assert!(saved.profiles[0].socks5_risk_warning().is_none());
        let rebuilt =
            crate::yaml::to_string(&load_servers(&directory.path().join("config.yaml")).unwrap())
                .unwrap();
        assert_eq!(rebuilt, yaml);
        assert!(SecurePlan::prepare(directory.path(), profile.id, mode)
            .unwrap()
            .is_none());
    }
}

#[test]
fn socks5_secure_activation_failure_restores_exact_files() {
    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let original_state = load_state_from(&directory.path().join("ping-rust-state.json")).unwrap();
    let original_servers = load_servers(&directory.path().join("config.yaml")).unwrap();
    let profile_path = directory
        .path()
        .join("profiles")
        .join(original_state.profiles[0].config_file_name());
    write_profile_documents(
        &directory.path().join("profiles"),
        &profile_documents(&original_servers, &original_state.profiles).unwrap(),
    )
    .unwrap();
    let original_profile = fs::read(&profile_path).unwrap();
    let config = fs::read(directory.path().join("config.yaml")).unwrap();
    let state = fs::read(directory.path().join("ping-rust-state.json")).unwrap();
    let mut plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Auth)
        .unwrap()
        .unwrap();
    plan.commit_files().unwrap();
    plan.rollback_files().unwrap();
    plan.finish_pending().unwrap();
    assert_eq!(
        fs::read(directory.path().join("config.yaml")).unwrap(),
        config
    );
    assert_eq!(
        fs::read(directory.path().join("ping-rust-state.json")).unwrap(),
        state
    );
    assert_eq!(fs::read(&profile_path).unwrap(), original_profile);
}

#[cfg(target_os = "linux")]
#[test]
fn socks5_secure_rollback_restores_aggregate_symlink() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let config = directory.path().join("config.yaml");
    let managed = Path::new("managed/aggregate.yaml");
    let target = directory.path().join(managed);
    fs::create_dir(target.parent().unwrap()).unwrap();
    fs::rename(&config, &target).unwrap();
    symlink(managed, &config).unwrap();
    let original = fs::read(&target).unwrap();

    let profiles = directory.path().join("profiles");
    fs::create_dir(&profiles).unwrap();
    let unmanaged = profiles.join("manual.yaml");
    fs::write(&unmanaged, b"# unmanaged file\n").unwrap();
    let mut failed = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Auth)
        .unwrap()
        .unwrap();
    let error = failed.commit_files().unwrap_err();
    assert!(format!("{error:#}").contains("非 ping-rust 文件"));
    assert_eq!(fs::read_link(&config).unwrap(), managed);
    assert_eq!(fs::read(&config).unwrap(), original);
    assert!(!directory
        .path()
        .join(".ping-rust-socks5-secure.pending")
        .exists());
    fs::remove_file(unmanaged).unwrap();

    let mut plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Auth)
        .unwrap()
        .unwrap();
    plan.commit_files().unwrap();
    assert_ne!(fs::read(&config).unwrap(), original);
    assert_eq!(fs::read(&target).unwrap(), original);
    plan.rollback_files().unwrap();
    plan.finish_pending().unwrap();

    assert_eq!(fs::read_link(&config).unwrap(), managed);
    assert_eq!(fs::read(&config).unwrap(), original);
    fs::write(&target, b"# update from the configuration manager\n").unwrap();
    assert_eq!(fs::read(&config).unwrap(), fs::read(&target).unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn socks5_secure_rollback_restores_state_symlink() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let state = directory.path().join("ping-rust-state.json");
    let managed = Path::new("managed/state.json");
    let target = directory.path().join(managed);
    fs::create_dir(target.parent().unwrap()).unwrap();
    fs::rename(&state, &target).unwrap();
    symlink(managed, &state).unwrap();
    let original = fs::read(&target).unwrap();

    let profiles = directory.path().join("profiles");
    fs::create_dir(&profiles).unwrap();
    let unmanaged = profiles.join("manual.yaml");
    fs::write(&unmanaged, b"# unmanaged file\n").unwrap();
    let mut plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Auth)
        .unwrap()
        .unwrap();
    assert!(format!("{:#}", plan.commit_files().unwrap_err()).contains("非 ping-rust 文件"));
    assert_eq!(fs::read_link(&state).unwrap(), managed);
    assert_eq!(fs::read(&state).unwrap(), original);
    fs::remove_file(unmanaged).unwrap();

    plan.commit_files().unwrap();
    assert_eq!(fs::read(&target).unwrap(), original);
    plan.rollback_files().unwrap();
    plan.finish_pending().unwrap();

    assert_eq!(fs::read_link(&state).unwrap(), managed);
    assert_eq!(fs::read(&state).unwrap(), original);
    let mut updated = load_state_from(&state).unwrap();
    updated.profiles[0].name = "updated-legacy-socks".into();
    save_state_to(&target, &updated).unwrap();
    assert_eq!(
        load_state_from(&state).unwrap().profiles[0].name,
        "updated-legacy-socks"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn socks5_secure_preserves_aggregate_owner_group_and_mode_through_rollback() {
    use std::os::unix::fs::MetadataExt;

    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let config = directory.path().join("config.yaml");
    utils::set_mode(&config, 0o640).unwrap();
    let metadata = || {
        let file = fs::metadata(&config).unwrap();
        (file.uid(), file.gid(), file.mode() & 0o7777)
    };
    let original = metadata();
    let mut plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Auth)
        .unwrap()
        .unwrap();
    plan.commit_files().unwrap();
    assert_eq!(metadata(), original);
    plan.rollback_files().unwrap();
    assert_eq!(metadata(), original);
    plan.finish_pending().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn socks5_secure_preserves_aggregate_posix_acl_through_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let config = directory.path().join("config.yaml");
    let assert_acl = delegate_file_read(&config);
    assert_acl();
    let mut plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Auth)
        .unwrap()
        .unwrap();
    plan.commit_files().unwrap();
    assert_acl();
    plan.rollback_files().unwrap();
    assert_acl();
    plan.finish_pending().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn socks5_secure_preserves_profile_directory_and_yaml_access_through_rollback() {
    use std::os::unix::fs::MetadataExt;

    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let profiles = directory.path().join("profiles");
    let state = load_state_from(&directory.path().join("ping-rust-state.json")).unwrap();
    let servers = load_servers(&directory.path().join("config.yaml")).unwrap();
    write_profile_documents(
        &profiles,
        &profile_documents(&servers, &state.profiles).unwrap(),
    )
    .unwrap();
    let yaml = profiles.join(profile.config_file_name());
    let original_yaml = fs::read(&yaml).unwrap();
    let assert_yaml_acl = delegate_file_read(&yaml);
    let assert_directory_access = delegate_access(&profiles, "system.posix_acl_access", 7, 5);
    let assert_directory_default = delegate_access(&profiles, "system.posix_acl_default", 7, 5);
    let access_metadata = |path: &Path| {
        let metadata = fs::metadata(path).unwrap();
        (metadata.uid(), metadata.gid(), metadata.mode())
    };
    let original_directory = access_metadata(&profiles);
    let original_file = access_metadata(&yaml);
    let assert_access = || {
        assert_eq!(access_metadata(&profiles), original_directory);
        assert_eq!(access_metadata(&yaml), original_file);
        assert_directory_access();
        assert_directory_default();
        assert_yaml_acl();
    };

    let mut plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Auth)
        .unwrap()
        .unwrap();
    plan.commit_files().unwrap();
    let candidate_yaml = fs::read(&yaml).unwrap();
    assert!(candidate_yaml != original_yaml);
    plan.rollback_files().unwrap();
    plan.finish_pending().unwrap();
    assert!(fs::read(&yaml).unwrap() == original_yaml);
    assert_access();
}

#[cfg(target_os = "linux")]
fn delegate_file_read(path: &Path) -> impl Fn() + '_ {
    delegate_access(path, "system.posix_acl_access", 6, 4)
}

#[cfg(target_os = "linux")]
fn delegate_access<'a>(
    path: &'a Path,
    attribute: &'static str,
    owner_permissions: u16,
    reader_permissions: u16,
) -> impl Fn() + 'a {
    use rustix::fs::{getxattr, setxattr, XattrFlags};
    use std::os::unix::fs::MetadataExt;

    let owner = fs::metadata(path).unwrap().uid();
    let reader = if owner == 65534 { 65533_u32 } else { 65534_u32 };
    // Linux ACL xattr v2：仅所有者可写，并为指定 UID 增加访问权限。
    let mut acl = 2_u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in [
        (1_u16, owner_permissions, u32::MAX),
        (2, reader_permissions, reader),
        (4, 0, u32::MAX),
        (16, reader_permissions, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        acl.extend(tag.to_le_bytes());
        acl.extend(permissions.to_le_bytes());
        acl.extend(id.to_le_bytes());
    }
    setxattr(path, attribute, &acl, XattrFlags::empty()).unwrap();
    move || {
        let mut current = [0_u8; 44];
        let len = getxattr(path, attribute, current.as_mut_slice()).unwrap();
        assert_eq!(&current[..len], acl.as_slice());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn socks5_secure_preserves_state_posix_acl_through_publish_and_rollback() {
    for rollback in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let profile = legacy(directory.path());
        let state_path = directory.path().join("ping-rust-state.json");
        if !rollback {
            let explicit_listen = load_state_from(&state_path).unwrap();
            save_state_to(&state_path, &explicit_listen).unwrap();
        }
        let original = fs::read(&state_path).unwrap();
        let assert_acl = delegate_file_read(&state_path);
        assert_acl();

        let mut plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Auth)
            .unwrap()
            .unwrap();
        plan.commit_files().unwrap();
        assert_acl();
        if rollback {
            plan.rollback_files().unwrap();
            plan.finish_pending().unwrap();
            assert!(fs::read(&state_path).unwrap() == original);
        } else {
            plan.publish_state().unwrap();
            assert!(SecurePlan::already_secure(directory.path(), profile.id).unwrap());
        }
        assert_acl();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn socks5_secure_commit_requires_unlocked_file_exports_to_release_the_state() {
    use fs2::FileExt;

    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let state = directory.path().join("ping-rust-state.json");
    let config = directory.path().join("config.yaml");
    let original_state = fs::read(&state).unwrap();
    let original_config = fs::read(&config).unwrap();
    for mode in [SecureMode::Auth, SecureMode::Local] {
        let mut plan = SecurePlan::prepare(directory.path(), profile.id, mode)
            .unwrap()
            .unwrap();
        let guard = fs::File::open(&state).unwrap();
        FileExt::lock_shared(&guard).unwrap();
        let error = plan.commit_files().unwrap_err();
        assert!(format!("{error:#}").contains("文件导出"));
        assert!(fs::read(&state).unwrap() == original_state);
        assert!(fs::read(&config).unwrap() == original_config);
        assert!(!directory
            .path()
            .join(".ping-rust-socks5-secure.pending")
            .exists());
        drop(guard);

        plan.commit_files().unwrap();
        plan.rollback_files().unwrap();
        plan.finish_pending().unwrap();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn socks5_secure_unlocked_read_rejects_concurrent_file_replacement() {
    use super::socks5_secure::read_unlocked_snapshot;

    let directory = tempfile::tempdir().unwrap();
    legacy(directory.path());
    let state_path = directory.path().join("ping-rust-state.json");
    for name in ["ping-rust-state.json", "config.yaml"] {
        let replaced = directory.path().join(name);
        let error = read_unlocked_snapshot(&state_path, || {
            let snapshot = load_state_from(&state_path)?;
            utils::atomic_write(&replaced, &fs::read(&replaced)?, 0o600)?;
            Ok(snapshot)
        })
        .err()
        .expect("文件已替换，必须丢弃本次快照");
        assert!(format!("{error:#}").contains("读取期间受管配置已变更"));
    }
}

#[tokio::test]
async fn socks5_secure_refuses_inactive_disabled_custom_unit() {
    for mode in [SecureMode::Auth, SecureMode::Local] {
        let directory = tempfile::tempdir().unwrap();
        let profile = legacy(directory.path());
        let unit = directory.path().join("shoes.service");
        let custom = b"[Service]\nUser=proxy\nExecStart=/opt/shoes /etc/shoes/config.yaml\n";
        fs::write(&unit, custom).unwrap();
        let unit_enablement = directory
            .path()
            .join("multi-user.target.wants/shoes.service");
        let config = directory.path().join("config.yaml");
        let state = directory.path().join("ping-rust-state.json");
        let original = [fs::read(&config).unwrap(), fs::read(&state).unwrap()];
        let error = crate::socks5_secure::run(
            directory.path(),
            profile.id,
            Some(mode),
            || Ok(false),
            async |_| panic!("停止的服务不应进入运行态验证"),
        )
        .await
        .unwrap_err();

        assert!(format!("{error:#}").contains("未处于 active"));
        assert_eq!(fs::read(&unit).unwrap(), custom);
        assert!(!unit_enablement.exists());
        assert!(!directory.path().join("profiles").exists());
        assert_eq!(
            [fs::read(config).unwrap(), fs::read(state).unwrap()],
            original
        );
    }
}

#[tokio::test]
async fn socks5_secure_restart_and_late_failures_restore_config_firewall_and_service() {
    use crate::socks5_secure::Runtime;
    use clap::Parser;
    struct Fake {
        fail_at: usize,
        fail_firewall_restore: bool,
        fail_service_stop: bool,
        step: usize,
        events: Vec<&'static str>,
        directory: PathBuf,
        original: Vec<u8>,
    }
    impl Fake {
        fn step(&mut self, event: &'static str) -> Result<()> {
            self.events.push(event);
            self.step += 1;
            if self.step == self.fail_at {
                bail!("模拟失败：{event}");
            }
            Ok(())
        }
    }
    impl Runtime for Fake {
        async fn preflight(
            &mut self,
            _: &SecurePlan,
            _: &crate::socks5_secure::InterruptGuard<'_>,
        ) -> Result<()> {
            Ok(())
        }

        async fn activate(&mut self) -> Result<()> {
            self.step("restart")
        }
        async fn verify(&mut self, _: &ManagedProfile) -> Result<()> {
            self.step("verify")
        }
        async fn close_firewall(&mut self) -> Result<()> {
            self.step("close-firewall")
        }
        async fn restore_firewall(&mut self) -> Result<()> {
            self.events.push("restore-firewall");
            if self.fail_firewall_restore {
                bail!("模拟防火墙回滚失败");
            }
            Ok(())
        }
        async fn stop_service(&mut self) -> Result<()> {
            assert_eq!(
                load_servers(&self.directory.join("config.yaml")).unwrap()[0].address,
                "127.0.0.1:443"
            );
            self.events.push("stop-with-candidate-config");
            if self.fail_service_stop {
                bail!("模拟停止服务失败");
            }
            Ok(())
        }
        async fn restore_service(&mut self, _: &ManagedProfile) -> Result<()> {
            assert_eq!(
                fs::read(self.directory.join("config.yaml")).unwrap(),
                self.original
            );
            self.events.push("restore-service-and-verify");
            Ok(())
        }
    }
    for (fail_at, fail_firewall_restore, fail_service_stop) in [
        (1, false, false),
        (2, false, false),
        (3, false, false),
        (4, false, false),
        (3, true, false),
        (3, true, true),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let profile = legacy(directory.path());
        let config = fs::read(directory.path().join("config.yaml")).unwrap();
        let state = fs::read(directory.path().join("ping-rust-state.json")).unwrap();
        let mut plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Local)
            .unwrap()
            .unwrap();
        let mut fake = Fake {
            fail_at,
            fail_firewall_restore,
            fail_service_stop,
            step: 0,
            events: vec![],
            directory: directory.path().into(),
            original: config.clone(),
        };
        let interrupt = crate::socks5_secure::Interrupt::default();
        let lock_path = directory.path().join("ping-rust.lock");
        let lock = utils::exclusive_lock(&lock_path).unwrap();
        let error = crate::socks5_secure::apply(&mut plan, &mut fake, &interrupt)
            .await
            .unwrap_err();
        drop(lock);
        let final_event = if fail_firewall_restore {
            assert!(error.to_string().contains("回滚不完整"));
            assert!(!fake.events.contains(&"restore-service-and-verify"));
            "stop-with-candidate-config"
        } else {
            assert!(error.to_string().contains("已恢复并再次验证"));
            "restore-service-and-verify"
        };
        assert_eq!(
            &fake.events[fake.events.len() - 2..],
            ["restore-firewall", final_event]
        );
        if fail_service_stop {
            assert!(error.to_string().contains("暂保留加固配置"));
            assert_eq!(
                load_servers(&directory.path().join("config.yaml")).unwrap()[0].address,
                "127.0.0.1:443"
            );
            let profile_path = directory
                .path()
                .join("profiles")
                .join(profile.config_file_name());
            let stored: ServerConfig =
                crate::yaml::from_slice(&fs::read(profile_path).unwrap()).unwrap();
            assert_eq!(stored.address, "127.0.0.1:443");
            let state_path = directory.path().join("ping-rust-state.json");
            let saved = load_state_from(&state_path).unwrap();
            assert_eq!(saved.profiles[0].listen_address().unwrap(), "127.0.0.1:443");
            assert!(SecurePlan::already_secure(directory.path(), profile.id).unwrap());

            let id = profile.id.to_string();
            let output_path = directory.path().join("client.json");
            for args in [
                vec!["prs", "url", &id, "--server-address", "example.com"],
                vec!["prs", "qr", &id, "--server-address", "example.com"],
                vec![
                    "prs",
                    "export",
                    "sing-box",
                    "--profile",
                    &id,
                    "--server",
                    "example.com",
                    "--output",
                    output_path.to_str().unwrap(),
                ],
            ] {
                let cli = crate::cli::Cli::try_parse_from(args).unwrap();
                let error = crate::cli::run_with_export_paths(cli, &state_path, &lock_path)
                    .await
                    .unwrap_err();
                assert!(format!("{error:#}").contains("仅监听本机"));
            }
            assert!(!output_path.exists());
            continue;
        }
        assert_eq!(
            fs::read(directory.path().join("config.yaml")).unwrap(),
            config
        );
        assert_eq!(
            fs::read(directory.path().join("ping-rust-state.json")).unwrap(),
            state
        );
        assert!(!directory.path().join("profiles").exists());
    }
}

#[tokio::test]
async fn socks5_secure_publishes_safety_only_after_runtime_verification() {
    struct Observer<'a> {
        directory: &'a Path,
        id: Uuid,
        fail_final_verification: bool,
        verifications: usize,
        restored: bool,
    }

    impl Observer<'_> {
        fn assert_unpublished(&self) {
            let bytes = fs::read(self.directory.join("ping-rust-state.json")).unwrap();
            let disk_state: ManagedState = serde_json::from_slice(&bytes).unwrap();
            let Credentials::Socks5 { username, .. } = &disk_state.profiles[0].credentials else {
                panic!("需要 SOCKS5 节点");
            };
            assert!(username.is_none());
            // 无锁读者从旧版状态和聚合配置推断，仍不能报告节点安全。
            assert!(!matches!(
                SecurePlan::already_secure(self.directory, self.id),
                Ok(true)
            ));
        }
    }

    impl crate::socks5_secure::Runtime for Observer<'_> {
        async fn preflight(
            &mut self,
            _: &SecurePlan,
            _: &crate::socks5_secure::InterruptGuard<'_>,
        ) -> Result<()> {
            Ok(())
        }

        async fn activate(&mut self) -> Result<()> {
            self.assert_unpublished();
            Ok(())
        }

        async fn verify(&mut self, _: &ManagedProfile) -> Result<()> {
            self.assert_unpublished();
            self.verifications += 1;
            if self.verifications == 2 && self.fail_final_verification {
                bail!("模拟最终验证失败");
            }
            Ok(())
        }

        async fn close_firewall(&mut self) -> Result<()> {
            self.assert_unpublished();
            Ok(())
        }

        async fn restore_firewall(&mut self) -> Result<()> {
            self.assert_unpublished();
            Ok(())
        }

        async fn restore_service(&mut self, _: &ManagedProfile) -> Result<()> {
            self.assert_unpublished();
            self.restored = true;
            Ok(())
        }

        async fn stop_service(&mut self) -> Result<()> {
            panic!("防火墙成功恢复后应恢复服务")
        }
    }

    for mode in [SecureMode::Auth, SecureMode::Local] {
        for fail_final_verification in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let id = legacy(directory.path()).id;
            let mut plan = SecurePlan::prepare(directory.path(), id, mode)
                .unwrap()
                .unwrap();
            let state_path = directory.path().join("ping-rust-state.json");
            let original = fs::read(&state_path).unwrap();
            let mut runtime = Observer {
                directory: directory.path(),
                id,
                fail_final_verification,
                verifications: 0,
                restored: false,
            };
            let lock_path = directory.path().join("ping-rust.lock");
            let lock = utils::exclusive_lock(&lock_path).unwrap();
            let reader_directory = directory.path().to_owned();
            let reader = std::thread::spawn(move || {
                utils::read_with_existing_lock(&lock_path, || {
                    SecurePlan::already_secure(&reader_directory, id)
                })
            });
            let interrupt = crate::socks5_secure::Interrupt::default();
            let result = crate::socks5_secure::apply(&mut plan, &mut runtime, &interrupt).await;
            drop(lock);
            assert_eq!(runtime.verifications, 2);
            assert_eq!(runtime.restored, fail_final_verification);
            assert_eq!(result.is_err(), fail_final_verification);
            assert_eq!(reader.join().unwrap().unwrap(), !fail_final_verification);
            assert_eq!(
                SecurePlan::already_secure(directory.path(), id).unwrap(),
                !fail_final_verification
            );
            if fail_final_verification {
                assert_eq!(fs::read(&state_path).unwrap(), original);
            }
        }
    }
}

#[test]
fn socks5_secure_info_url_qr_and_file_export_wait_for_publish_or_rollback() {
    use clap::Parser;
    use std::{sync::mpsc, thread, time::Duration};

    for (mode, rollback) in [
        (SecureMode::Local, false),
        (SecureMode::Local, true),
        (SecureMode::Auth, false),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let profile = legacy(directory.path());
        let state_path = directory.path().join("ping-rust-state.json");
        let lock_path = directory.path().join("ping-rust.lock");
        let output_path = directory.path().join("client.json");
        let id = profile.id.to_string();
        let mut plan = SecurePlan::prepare(directory.path(), profile.id, mode)
            .unwrap()
            .unwrap();
        let lock = utils::exclusive_lock(&lock_path).unwrap();
        plan.commit_files().unwrap();
        assert_eq!(
            load_servers(&directory.path().join("config.yaml")).unwrap()[0].address,
            if mode == SecureMode::Local {
                "127.0.0.1:443"
            } else {
                "0.0.0.0:443"
            }
        );

        let mut readers = Vec::new();
        for command in ["url", "qr", "export", "info"] {
            let args = if command == "export" {
                vec![
                    "prs",
                    command,
                    "sing-box",
                    "--profile",
                    &id,
                    "--server",
                    "example.com",
                    "--output",
                    output_path.to_str().unwrap(),
                ]
            } else if command == "info" {
                vec!["prs", command, &id]
            } else {
                vec!["prs", command, &id, "--server-address", "example.com"]
            };
            let cli = crate::cli::Cli::try_parse_from(args).unwrap();
            let (ready, started) = mpsc::channel();
            let (finished, result) = mpsc::channel();
            let (state_path, lock_path) = (state_path.clone(), lock_path.clone());
            let reader = thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                if command == "info" {
                    // 即使未安装 shoes，也要让此读者执行带输出管道的 Tokio 子进程。
                    let output = runtime.block_on(async {
                        tokio::process::Command::new(std::env::current_exe().unwrap())
                            .arg("--help")
                            .output()
                            .await
                            .unwrap()
                    });
                    assert!(output.status.success());
                    assert!(!output.stdout.is_empty());
                }
                ready.send(()).unwrap();
                let outcome = runtime.block_on(crate::cli::run_with_export_paths(
                    cli,
                    &state_path,
                    &lock_path,
                ));
                finished.send(outcome).unwrap();
            });
            started.recv_timeout(Duration::from_secs(5)).unwrap();
            readers.push((command, reader, result));
        }

        for (command, _, result) in &readers {
            assert!(
                matches!(
                    result.recv_timeout(Duration::from_millis(100)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ),
                "{command} 导出必须等待加固写锁释放"
            );
        }
        assert!(!output_path.exists());
        if rollback {
            plan.rollback_files().unwrap();
            plan.finish_pending().unwrap();
        } else {
            plan.publish_state().unwrap();
        }
        drop(lock);

        let public_export = rollback || mode == SecureMode::Auth;
        for (command, reader, result) in readers {
            let result = result.recv_timeout(Duration::from_secs(5)).unwrap();
            reader.join().unwrap();
            if public_export || command == "info" {
                assert!(result.is_ok(), "{command} 应读取事务完成后的状态");
            } else {
                assert!(format!("{:#}", result.unwrap_err()).contains("仅监听本机"));
            }
        }
        assert_eq!(output_path.exists(), public_export);
        if public_export {
            let contents: serde_json::Value =
                serde_json::from_slice(&fs::read(output_path).unwrap()).unwrap();
            let outbound = contents["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|outbound| outbound["type"] == "socks")
                .unwrap();
            if rollback {
                assert!(outbound["username"].is_null());
                assert!(outbound["password"].is_null());
            } else {
                let Credentials::Socks5 {
                    username, password, ..
                } = &plan.profile.credentials
                else {
                    panic!("需要 SOCKS5 节点");
                };
                assert!(outbound["username"].as_str() == username.as_deref());
                assert!(outbound["password"].as_str() == password.as_deref());
                assert!(username.is_some() && password.is_some());
            }
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn socks5_secure_sigkill_after_commit_refuses_retry_and_stale_exports() {
    use crate::service::ShoesServiceHook;
    use clap::Parser;
    use std::{
        io::Read,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    const CHILD_DIR: &str = "PING_RUST_TEST_SOCKS5_SIGKILL_DIR";
    if let Some(directory) = std::env::var_os(CHILD_DIR) {
        let directory = PathBuf::from(directory);
        let _lock = utils::exclusive_lock(&directory.join("ping-rust.lock")).unwrap();
        let id = load_state_from(&directory.join("ping-rust-state.json"))
            .unwrap()
            .profiles[0]
            .id;
        let mut plan = SecurePlan::prepare(&directory, id, SecureMode::Auth)
            .unwrap()
            .unwrap();
        plan.commit_files().unwrap();
        fs::write(directory.join("committed"), b"").unwrap();
        let _ = std::io::stdin().read_exact(&mut [0]);
        return;
    }

    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "config::socks5_secure_tests::socks5_secure_sigkill_after_commit_refuses_retry_and_stale_exports",
        ])
        .env(CHILD_DIR, directory.path())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !directory.path().join("committed").exists() {
        assert!(child.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline, "子进程未写入候选配置");
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());

    let lock_path = directory.path().join("ping-rust.lock");
    let state_path = directory.path().join("ping-rust-state.json");
    let config_path = directory.path().join("config.yaml");
    let output_path = directory.path().join("client.json");
    let config = fs::read(&config_path).unwrap();
    let state = fs::read(&state_path).unwrap();
    let ServerProtocol::Socks {
        username, password, ..
    } = &load_servers(&config_path).unwrap()[0].protocol
    else {
        panic!("需要 SOCKS5 配置");
    };
    assert!(username.is_some() && password.is_some());
    let stored: ManagedState = serde_json::from_slice(&state).unwrap();
    assert!(stored.profiles[0].socks5_risk_warning().is_some());
    let id = stored.profiles[0].id.to_string();

    let retry = crate::cli::Cli::try_parse_from([
        "prs",
        "socks5",
        "secure",
        &profile.name,
        "--auth",
        "--yes",
    ])
    .unwrap();
    let Some(crate::cli::Command::Socks5 {
        command: crate::cli::Socks5Command::Secure(retry),
    }) = retry.command
    else {
        panic!("需要 SOCKS5 加固命令");
    };
    let error = retry
        .run_in(directory.path(), &lock_path, false)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("上次 SOCKS5 加固未完成"));

    for hook in [ShoesServiceHook::Start, ShoesServiceHook::Stop] {
        let error = super::socks5_secure::read_export_state(&state_path, Some(hook))
            .err()
            .expect("systemd 钩子也必须拒绝已失去写者的事务");
        assert!(format!("{error:#}").contains("上次 SOCKS5 加固未完成"));
    }

    for args in [
        vec!["prs", "url", &profile.name],
        vec!["prs", "qr", &profile.name],
        vec!["prs", "info", &profile.name],
        vec![
            "prs",
            "export",
            "sing-box",
            "--profile",
            &id,
            "--server",
            "example.com",
            "--output",
            output_path.to_str().unwrap(),
        ],
    ] {
        let cli = crate::cli::Cli::try_parse_from(args).unwrap();
        let error = crate::cli::run_with_export_paths(cli, &state_path, &lock_path)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("上次 SOCKS5 加固未完成"));
    }
    assert!(!output_path.exists());
    assert!(fs::read(config_path).unwrap() == config);
    assert!(fs::read(state_path).unwrap() == state);
}

#[test]
fn socks5_secure_view_menu_renders_selected_uuid_after_hardening() {
    for mode in [SecureMode::Auth, SecureMode::Local] {
        let directory = tempfile::tempdir().unwrap();
        let id = legacy(directory.path()).id;
        let state_path = directory.path().join("ping-rust-state.json");
        let lock_path = directory.path().join("ping-rust.lock");
        let mut state = load_state_from(&state_path).unwrap();
        let mut other = state.profiles[0].clone();
        other.id = Uuid::new_v4();
        other.name = "other-socks".into();
        other.port = 444;
        let config_path = directory.path().join("config.yaml");
        let mut servers = load_servers(&config_path).unwrap();
        let mut other_server = servers[0].clone();
        other_server.address = other.listen_address().unwrap();
        servers.push(other_server);
        fs::write(&config_path, crate::yaml::to_string(&servers).unwrap()).unwrap();
        state.profiles.push(other);
        save_state_to(&state_path, &state).unwrap();

        let rendered = crate::menu::view_config_with(
            &state_path,
            &lock_path,
            |profiles| {
                assert_eq!(profiles.len(), 2);
                assert_eq!(profiles[0].id, id);
                assert!(profiles[0].socks5_risk_warning().is_some());
                let lock = utils::exclusive_lock(&lock_path)?;
                let mut plan = SecurePlan::prepare(directory.path(), id, mode)?.unwrap();
                plan.commit_files()?;
                plan.publish_state()?;
                let mut updated = load_state_from(&state_path)?;
                updated.profiles.swap(0, 1);
                let mut servers = load_servers(&config_path)?;
                servers.swap(0, 1);
                fs::write(&config_path, crate::yaml::to_string(&servers)?)?;
                save_state_to(&state_path, &updated)?;
                drop(lock);
                Ok(Some(0))
            },
            |profile, uri, warning| {
                assert_eq!(profile.id, id);
                assert!(warning.is_none());
                let uri = uri.unwrap();
                match mode {
                    SecureMode::Auth => {
                        assert!(uri.contains("@203.0.113.8:443"));
                        assert!(!uri.contains("socks5://203.0.113.8:443"));
                    }
                    SecureMode::Local => {
                        assert!(uri.starts_with("socks5://127.0.0.1:443"));
                        assert!(!uri.contains("203.0.113.8"));
                    }
                }
                let text = crate::cli::profile_details_with_qr_text(profile, Some(uri))?;
                assert!(text.contains(uri));
                assert!(text.contains("二维码 (QR)"));
                Ok(())
            },
        )
        .unwrap();
        assert!(rendered);
    }
}

#[test]
fn socks5_secure_tools_menu_exports_the_state_after_input() {
    use crate::client::ClientFormat;
    use std::{sync::mpsc, thread, time::Duration};

    for (format, wait_for_writer) in [
        (ClientFormat::ClashMeta, false),
        (ClientFormat::SingBox, true),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let id = legacy(directory.path()).id;
        let state_path = directory.path().join("ping-rust-state.json");
        let lock_path = directory.path().join("ping-rust.lock");
        let (selected, selection_ready) = mpsc::channel();
        let (answer, input_ready) = mpsc::channel();
        let (finished, result) = mpsc::channel();
        let reader = {
            let (state_path, lock_path) = (state_path.clone(), lock_path.clone());
            thread::spawn(move || {
                let output = crate::menu::export_menu_with(
                    &state_path,
                    &lock_path,
                    |profiles| {
                        assert_eq!(profiles[0].id, id);
                        assert!(profiles[0].socks5_loopback().is_none());
                        Ok(Some(0))
                    },
                    || {
                        selected.send(()).unwrap();
                        input_ready.recv_timeout(Duration::from_secs(5)).unwrap();
                        Ok(Some((format, "example.com".to_owned())))
                    },
                    |_| panic!("加固后不能输出公网配置"),
                );
                finished.send(output).unwrap();
            })
        };
        selection_ready
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        let lock = utils::exclusive_lock(&lock_path).unwrap();
        let mut plan = SecurePlan::prepare(directory.path(), id, SecureMode::Local)
            .unwrap()
            .unwrap();
        plan.commit_files().unwrap();
        if wait_for_writer {
            answer.send(()).unwrap();
            assert!(matches!(
                result.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
        }
        plan.publish_state().unwrap();
        drop(lock);
        if !wait_for_writer {
            answer.send(()).unwrap();
        }

        let error = result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap_err();
        assert!(format!("{error:#}").contains("仅监听本机"));
        reader.join().unwrap();
    }
}

struct InterruptedRuntime<'a> {
    interrupt: &'a crate::socks5_secure::Interrupt,
    directory: &'a Path,
    has_ss: bool,
    stop_at: &'static str,
    events: Vec<&'static str>,
    service_active: bool,
}

impl crate::socks5_secure::Runtime for InterruptedRuntime<'_> {
    async fn preflight(
        &mut self,
        _: &SecurePlan,
        _: &crate::socks5_secure::InterruptGuard<'_>,
    ) -> Result<()> {
        assert!(!self.directory.join("profiles").exists());
        crate::socks5_secure::require_tools(|tool| self.has_ss || tool != "ss")
    }

    async fn activate(&mut self) -> Result<()> {
        #[cfg(unix)]
        if self.stop_at == "sigterm" {
            self.events.push("activate");
            assert!(self.directory.join("profiles").is_dir());
            let status = std::process::Command::new("sh")
                .args([
                    "-c",
                    "kill -TERM \"$1\"",
                    "sh",
                    &std::process::id().to_string(),
                ])
                .status()?;
            assert!(status.success());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while self.interrupt.pending_signal().is_none() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "等待 SIGTERM 处理超时"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            std::future::pending::<()>().await;
        }
        self.record("activate");
        if self.stop_at == "hung-activate" {
            assert!(self
                .interrupt
                .defer_signal(crate::socks5_secure::ShutdownSignal::Interrupt));
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn verify(&mut self, _: &ManagedProfile) -> Result<()> {
        if self.events.contains(&"close-firewall") {
            self.record("final-verify");
        } else {
            self.record("verify");
        }
        Ok(())
    }

    async fn close_firewall(&mut self) -> Result<()> {
        self.record("close-firewall");
        Ok(())
    }

    async fn restore_firewall(&mut self) -> Result<()> {
        self.events.push("restore-firewall");
        // 回滚途中再次收到 SIGINT 也不能触发全局直接退出。
        assert!(self
            .interrupt
            .defer_signal(crate::socks5_secure::ShutdownSignal::Interrupt));
        Ok(())
    }

    async fn restore_service(&mut self, _: &ManagedProfile) -> Result<()> {
        self.service_active = false;
        assert!(self
            .interrupt
            .defer_signal(crate::socks5_secure::ShutdownSignal::Interrupt));
        self.service_active = true;
        self.events.push("restore-service");
        Ok(())
    }

    async fn stop_service(&mut self) -> Result<()> {
        panic!("防火墙成功恢复后应恢复服务")
    }
}

impl InterruptedRuntime<'_> {
    fn record(&mut self, event: &'static str) {
        self.events.push(event);
        if self.stop_at == event {
            assert!(self.directory.join("profiles").is_dir());
            assert!(self
                .interrupt
                .defer_signal(crate::socks5_secure::ShutdownSignal::Interrupt));
        }
    }
}

#[tokio::test]
async fn socks5_secure_sigint_after_commit_rolls_back_before_exit() {
    for (stop_at, expected) in [
        (
            "activate",
            &["activate", "restore-firewall", "restore-service"][..],
        ),
        (
            "verify",
            &["activate", "verify", "restore-firewall", "restore-service"],
        ),
        (
            "close-firewall",
            &[
                "activate",
                "verify",
                "close-firewall",
                "restore-firewall",
                "restore-service",
            ],
        ),
        (
            "final-verify",
            &[
                "activate",
                "verify",
                "close-firewall",
                "final-verify",
                "restore-firewall",
                "restore-service",
            ],
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let profile = legacy(directory.path());
        let config = fs::read(directory.path().join("config.yaml")).unwrap();
        let state = fs::read(directory.path().join("ping-rust-state.json")).unwrap();
        let mut plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Local)
            .unwrap()
            .unwrap();
        let interrupt = crate::socks5_secure::Interrupt::default();
        let mut runtime = InterruptedRuntime {
            interrupt: &interrupt,
            directory: directory.path(),
            has_ss: true,
            stop_at,
            events: vec![],
            service_active: true,
        };
        let error = crate::socks5_secure::apply(&mut plan, &mut runtime, &interrupt)
            .await
            .unwrap_err();
        assert!(crate::is_interrupted(&error));
        assert!(error.to_string().contains("已恢复并再次验证"));
        assert_eq!(runtime.events, expected);
        assert!(runtime.service_active);
        assert_eq!(
            fs::read(directory.path().join("config.yaml")).unwrap(),
            config
        );
        assert_eq!(
            fs::read(directory.path().join("ping-rust-state.json")).unwrap(),
            state
        );
        assert!(!directory.path().join("profiles").exists());
        assert!(!interrupt.defer_signal(crate::socks5_secure::ShutdownSignal::Interrupt));
    }
}

#[tokio::test]
async fn socks5_secure_sigint_interrupts_a_restart_that_never_finishes() {
    let directory = tempfile::tempdir().unwrap();
    let id = legacy(directory.path()).id;
    let config_path = directory.path().join("config.yaml");
    let state_path = directory.path().join("ping-rust-state.json");
    let config = fs::read(&config_path).unwrap();
    let state = fs::read(&state_path).unwrap();
    let mut plan = SecurePlan::prepare(directory.path(), id, SecureMode::Local)
        .unwrap()
        .unwrap();
    let interrupt = crate::socks5_secure::Interrupt::default();
    let mut runtime = InterruptedRuntime {
        interrupt: &interrupt,
        directory: directory.path(),
        has_ss: true,
        stop_at: "hung-activate",
        events: vec![],
        service_active: true,
    };
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::socks5_secure::apply(&mut plan, &mut runtime, &interrupt),
    )
    .await
    .expect("重启一直未返回时仍须完成取消与回滚")
    .unwrap_err();
    assert_eq!(crate::interrupted_exit_code(&error), 130);
    assert!(format!("{error:#}").contains("SIGINT"));
    assert!(error.to_string().contains("已恢复并再次验证"));
    assert_eq!(
        runtime.events,
        ["activate", "restore-firewall", "restore-service"]
    );
    assert!(runtime.service_active);
    assert_eq!(fs::read(&config_path).unwrap(), config);
    assert_eq!(fs::read(&state_path).unwrap(), state);
    assert!(!directory.path().join("profiles").exists());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn socks5_secure_sigterm_during_restart_rolls_back_before_exit() {
    const CHILD: &str = "PING_RUST_TEST_SOCKS5_SIGTERM_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "config::socks5_secure_tests::socks5_secure_sigterm_during_restart_rolls_back_before_exit",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "子进程退出：{}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }

    crate::listen_for_interrupts().await.unwrap();
    crate::listen_for_termination().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let id = legacy(directory.path()).id;
    let config_path = directory.path().join("config.yaml");
    let state_path = directory.path().join("ping-rust-state.json");
    let config = fs::read(&config_path).unwrap();
    let state = fs::read(&state_path).unwrap();
    let mut plan = SecurePlan::prepare(directory.path(), id, SecureMode::Local)
        .unwrap()
        .unwrap();
    let interrupt = &crate::socks5_secure::INTERRUPT;
    let mut runtime = InterruptedRuntime {
        interrupt,
        directory: directory.path(),
        has_ss: true,
        stop_at: "sigterm",
        events: vec![],
        service_active: true,
    };
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::socks5_secure::apply(&mut plan, &mut runtime, interrupt),
    )
    .await
    .expect("SIGTERM 必须中断一直未返回的重启并回滚")
    .unwrap_err();
    assert!(crate::is_interrupted(&error));
    assert_eq!(crate::interrupted_exit_code(&error), 143);
    assert!(format!("{error:#}").contains("SIGTERM"));
    assert_eq!(
        runtime.events,
        ["activate", "restore-firewall", "restore-service"]
    );
    assert!(runtime.service_active);
    assert_eq!(fs::read(&config_path).unwrap(), config);
    assert_eq!(fs::read(&state_path).unwrap(), state);
    assert!(!directory.path().join("profiles").exists());
}

#[tokio::test]
async fn socks5_secure_signal_observing_idle_prevents_transaction_from_writing() {
    use crate::socks5_secure::{Interrupt, ShutdownSignal};

    let directory = tempfile::tempdir().unwrap();
    let id = legacy(directory.path()).id;
    let config_path = directory.path().join("config.yaml");
    let state_path = directory.path().join("ping-rust-state.json");
    let config = fs::read(&config_path).unwrap();
    let state = fs::read(&state_path).unwrap();
    let mut plan = SecurePlan::prepare(directory.path(), id, SecureMode::Local)
        .unwrap()
        .unwrap();
    let interrupt = Interrupt::default();
    let mut runtime = InterruptedRuntime {
        interrupt: &interrupt,
        directory: directory.path(),
        has_ss: true,
        stop_at: "",
        events: vec![],
        service_active: true,
    };
    // 模拟信号线程决定退出后，主线程在退出动作之前尝试进入事务。
    assert!(!interrupt.defer_signal(ShutdownSignal::Interrupt));
    let error = crate::socks5_secure::apply(&mut plan, &mut runtime, &interrupt)
        .await
        .unwrap_err();
    assert!(crate::is_interrupted(&error));
    assert!(runtime.events.is_empty());
    assert_eq!(fs::read(&config_path).unwrap(), config);
    assert_eq!(fs::read(&state_path).unwrap(), state);
    assert!(!directory.path().join("profiles").exists());
}

#[tokio::test]
async fn socks5_secure_missing_ss_leaves_files_and_service_untouched() {
    let directory = tempfile::tempdir().unwrap();
    let profile = legacy(directory.path());
    let config = fs::read(directory.path().join("config.yaml")).unwrap();
    let state = fs::read(directory.path().join("ping-rust-state.json")).unwrap();
    let mut plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Local)
        .unwrap()
        .unwrap();
    let interrupt = crate::socks5_secure::Interrupt::default();
    let mut runtime = InterruptedRuntime {
        interrupt: &interrupt,
        directory: directory.path(),
        has_ss: false,
        stop_at: "",
        events: vec![],
        service_active: true,
    };
    let error = crate::socks5_secure::apply(&mut plan, &mut runtime, &interrupt)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("ss"));
    assert!(runtime.events.is_empty());
    assert_eq!(
        fs::read(directory.path().join("config.yaml")).unwrap(),
        config
    );
    assert_eq!(
        fs::read(directory.path().join("ping-rust-state.json")).unwrap(),
        state
    );
    assert!(!directory.path().join("profiles").exists());
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn socks5_secure_real_auth_and_local_isolation() {
    use std::{net::Ipv4Addr, process::Stdio, time::Duration};
    use tokio::net::{TcpListener, TcpStream};
    let Some(binary) = crate::shoes_e2e::shoes_binary(
        "socks5_secure_real_auth_and_local_isolation",
        &[
            crate::shoes_e2e::TEST_SHOES,
            crate::shoes_e2e::SHOES_E2E_BIN,
        ],
    ) else {
        return;
    };
    let routes = fs::read_to_string("/proc/net/fib_trie").unwrap();
    let lines = routes.lines().collect::<Vec<_>>();
    let interface = lines
        .windows(2)
        .filter(|pair| pair[1].contains("/32 host LOCAL"))
        .filter_map(|pair| pair[0].split_whitespace().last()?.parse::<Ipv4Addr>().ok())
        .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .expect("CI 需要非回环网卡");
    for mode in [SecureMode::Auth, SecureMode::Local] {
        let directory = tempfile::tempdir().unwrap();
        let reservation = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let profile = legacy_at(directory.path(), port);
        let mut plan = SecurePlan::prepare(directory.path(), profile.id, mode)
            .unwrap()
            .unwrap();
        plan.commit_files().unwrap();
        validate_with_binary(&binary, &directory.path().join("config.yaml"))
            .await
            .unwrap();
        let mut child = Command::new(&binary)
            .arg(directory.path().join("config.yaml"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                assert!(child.try_wait().unwrap().is_none());
                if TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        let target = if mode == SecureMode::Local {
            Ipv4Addr::LOCALHOST
        } else {
            interface
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            crate::socks5_secure::probe(&plan.profile, (target, port).into()),
        )
        .await
        .unwrap()
        .unwrap();
        if mode == SecureMode::Local {
            let error = tokio::time::timeout(
                Duration::from_secs(2),
                TcpStream::connect((interface, port)),
            )
            .await
            .unwrap()
            .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        }
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }
}
