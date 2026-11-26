use super::*;

async fn legacy(directory: &Path, port: u16, address: &str) -> ManagedProfile {
    let mut request =
        crate::config::tests::request(Protocol::Socks5, directory.join("config.yaml"));
    request.port = port;
    request.server_address = Some("proxy.example.com".to_owned());
    request.options.socks5_no_auth = true;
    request.options.udp_enabled = false;
    let result = generate_inner(request, false).await.unwrap();
    let mut server = load_servers(&result.config_path).unwrap().remove(0);
    server.address = socks5_address(address, port);
    let mut profile = result.profile;
    profile.server_address = Some("proxy.example.com".to_owned());
    let mut state = serde_json::to_value(ManagedState {
        profiles: vec![profile.clone()],
        ..Default::default()
    })
    .unwrap();
    state["profiles"][0]["credentials"]["Socks5"]
        .as_object_mut()
        .unwrap()
        .remove("listen");
    fs::write(
        directory.join("ping-rust-state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    fs::write(
        &result.config_path,
        crate::yaml::to_string(&vec![&server]).unwrap(),
    )
    .unwrap();
    fs::create_dir(directory.join("profiles")).unwrap();
    fs::write(
        profile_path(directory, &profile),
        crate::yaml::to_string(&server).unwrap(),
    )
    .unwrap();
    profile
}

fn prepare(directory: &Path, profile: &ManagedProfile, mode: SecureMode) -> SecurePlan {
    SecurePlan::load(directory, &profile.id.to_string(), || Ok(Some(mode)))
        .unwrap()
        .expect("应生成加固计划")
}

#[tokio::test]
async fn dry_run_redacts_diff_and_preserves_all_file_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let profile = legacy(path, 1080, "0.0.0.0").await;
    let files = [
        path.join("config.yaml"),
        path.join("ping-rust-state.json"),
        profile_path(path, &profile),
    ];
    let before = files.each_ref().map(|file| fs::read(file).unwrap());
    let plan = prepare(path, &profile, SecureMode::Auth);
    let diff = plan.diff(path);
    assert!(diff.contains("profiles/SOCKS5-1080.yaml"));
    assert!(diff.contains("config.yaml"));
    assert_eq!(diff.matches("+    username: <已脱敏>").count(), 2);
    assert_eq!(diff.matches("+    password: <已脱敏>").count(), 2);
    assert!(!diff.contains("proxy.example.com"));
    let Credentials::Socks5 {
        username: Some(username),
        password: Some(password),
        ..
    } = &plan.profile().credentials
    else {
        panic!("应生成凭据")
    };
    assert!(!diff.contains(username));
    assert!(!diff.contains(password));
    assert_eq!(files.each_ref().map(|file| fs::read(file).unwrap()), before);
    assert_eq!(fs::read_dir(path).unwrap().count(), 3);
    assert_eq!(fs::read_dir(path.join("profiles")).unwrap().count(), 1);
    let diff = prepare(path, &profile, SecureMode::Local).diff(path);
    assert_eq!(diff.matches("- address: 0.0.0.0:1080").count(), 2);
    assert_eq!(diff.matches("+ address: 127.0.0.1:1080").count(), 2);
    assert_eq!(files.each_ref().map(|file| fs::read(file).unwrap()), before);
}

#[tokio::test]
async fn restart_failure_restores_exact_files_before_restarting_original_service() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let profile = legacy(path, 1080, "0.0.0.0").await;
    let unrelated = path.join("profiles/other.conf");
    fs::write(&unrelated, b"leave intact").unwrap();
    let files = [
        path.join("config.yaml"),
        path.join("ping-rust-state.json"),
        profile_path(path, &profile),
        unrelated,
    ];
    let snapshot = || files.each_ref().map(|file| fs::read(file).unwrap());
    let before = snapshot();
    let mut restarts = Vec::new();
    let error = prepare(path, &profile, SecureMode::Local)
        .commit(path, |profile| {
            let address = profile.listen_address()?;
            restarts.push(address.clone());
            if address == "127.0.0.1:1080" {
                let after = snapshot();
                for (updated, original) in after[..3].iter().zip(&before[..3]) {
                    assert_ne!(updated, original);
                }
                assert_eq!(after[3], before[3]);
                bail!("模拟服务重启失败");
            }
            assert_eq!(snapshot(), before, "恢复服务前必须先还原文件");
            Ok(())
        })
        .err()
        .unwrap();
    assert_eq!(restarts, ["127.0.0.1:1080", "0.0.0.0:1080"]);
    assert_eq!(snapshot(), before);
    assert!(format!("{error:#}").contains("模拟服务重启失败"));
    assert!(format!("{error:#}").contains("原配置已恢复"));
}

#[tokio::test]
async fn repaired_socks5_stays_safe_after_port_edit_and_profile_rebuild() {
    for (mode, binding, expected) in [
        (SecureMode::Auth, "0.0.0.0", "0.0.0.0:2080"),
        (SecureMode::Local, "0.0.0.0", "127.0.0.1:2080"),
        (SecureMode::Local, "::", "[::1]:2080"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let original = legacy(path, 1080, binding).await;
        prepare(path, &original, mode)
            .commit(path, |_| Ok(()))
            .unwrap();

        let config = path.join("config.yaml");
        let saved_state = path.join("ping-rust-state.json");
        let mut state = load_state_from(&saved_state).unwrap();
        let mut servers = load_servers(&config).unwrap();
        assert!(
            SecurePlan::load(path, &original.name, || panic!("安全节点无需选择"))
                .unwrap()
                .is_none()
        );

        let profile = &mut state.profiles[0];
        assert_eq!(profile.id, original.id);
        assert!(profile.socks5_risk_warning().is_none());
        if mode == SecureMode::Auth {
            assert!(apply_profile_change(
                &mut servers[0],
                profile,
                ProfileChange::Socks5Authentication(false)
            )
            .is_err());
            assert!(crate::client::stored_share_uri(profile, None)
                .unwrap()
                .contains("@proxy.example.com:1080"));
        } else {
            assert_eq!(profile.server_address.as_deref(), profile.socks5_loopback());
        }
        apply_profile_change(&mut servers[0], profile, ProfileChange::Port(2080)).unwrap();
        let documents = profile_documents(&servers, &state.profiles).unwrap();
        assert_eq!(documents.len(), 1);
        let rebuilt = aggregate_profile_documents(&documents, &state.profiles).unwrap();
        assert_eq!(
            crate::yaml::from_str::<Vec<ServerConfig>>(&rebuilt).unwrap()[0].address,
            expected
        );
        let profiles = path.join("profiles");
        commit::commit_managed_with_state_writer(
            &config,
            &saved_state,
            &profiles,
            &servers,
            &state,
            save_state_to,
        )
        .unwrap();
        fs::remove_file(profile_path(path, &state.profiles[0])).unwrap();
        assert!(prepare_managed_snapshot(path).unwrap());
        validate_managed_snapshot(&config, &saved_state).unwrap();
        let state = load_state_from(&saved_state).unwrap();
        assert!(state.profiles[0].socks5_risk_warning().is_none());
        let json = serde_json::to_value(&state).unwrap();
        assert!(json["profiles"][0]["credentials"]["Socks5"]["listen"]
            .get("legacy_public_address")
            .is_none());
    }
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn repaired_socks5_authenticates_and_loopback_rejects_remote_connections() {
    use std::{
        net::{Ipv4Addr, TcpListener},
        process::Stdio,
    };
    use tokio::process::Command;

    let Some(binary) = crate::shoes_e2e::shoes_binary(
        "repaired_socks5_authenticates_and_loopback_rejects_remote_connections",
        &[
            crate::shoes_e2e::TEST_SHOES,
            crate::shoes_e2e::SHOES_E2E_BIN,
        ],
    ) else {
        return;
    };
    let routes = fs::read_to_string("/proc/net/fib_trie").unwrap();
    let lines: Vec<_> = routes.lines().collect();
    let remote = lines
        .windows(2)
        .filter(|pair| pair[1].contains("/32 host LOCAL"))
        .filter_map(|pair| pair[0].split_whitespace().last()?.parse::<Ipv4Addr>().ok())
        .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .expect("CI 必须提供非回环 IPv4 网卡");
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    for mode in [SecureMode::Auth, SecureMode::Local] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let reservation = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        let original = legacy(path, port, "0.0.0.0").await;
        drop(reservation);

        let plan = prepare(path, &original, mode);
        validate_candidate_with_binary(&plan.runtime, path, &binary)
            .await
            .unwrap();
        let repaired = plan.commit(path, |_| Ok(())).unwrap();
        let mut child = Command::new(&binary)
            .arg(path.join("config.yaml"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let remote = SocketAddr::from((remote, port));
        wait_for_listener(socket_address(&repaired).unwrap(), child.id().unwrap()).unwrap();
        let target = match mode {
            SecureMode::Local => {
                let error = TcpStream::connect_timeout(&remote, PROBE_TIMEOUT).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
                SocketAddr::from((Ipv4Addr::LOCALHOST, port))
            }
            SecureMode::Auth => remote,
        };

        let mut stream = verify_socks5_handshake(target, &repaired).unwrap();
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&origin.local_addr().unwrap().port().to_be_bytes());
        stream.write_all(&request).unwrap();
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..3], &[5, 0, 0], "SOCKS5 CONNECT 必须成功");
        child.kill().await.unwrap();
    }
}
