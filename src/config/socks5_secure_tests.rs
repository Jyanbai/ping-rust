use super::socks5_secure::{SecureMode, SecurePlan};
use super::*;

fn legacy(directory: &Path) -> ManagedProfile {
    legacy_at(directory, 443)
}

fn legacy_at(directory: &Path, port: u16) -> ManagedProfile {
    let mut request = tests::request(Protocol::Socks5, directory.join("config.yaml"));
    request.options.socks5_no_auth = true;
    request.port = port;
    let generated = presets::generate(&request, directory, Uuid::nil()).unwrap();
    let mut server = generated.server;
    server.address = format!("0.0.0.0:{port}");
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
fn socks5_secure_persists_safety_across_port_edit_and_rebuild() {
    for mode in [SecureMode::Auth, SecureMode::Local] {
        let directory = tempfile::tempdir().unwrap();
        let profile = legacy(directory.path());
        let mut plan = SecurePlan::prepare(directory.path(), profile.id, mode)
            .unwrap()
            .unwrap();
        plan.commit_files().unwrap();
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
    plan.rollback().unwrap();
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

#[tokio::test]
async fn socks5_secure_restart_and_late_failures_restore_config_firewall_and_service() {
    use crate::socks5_secure::Runtime;
    struct Fake {
        fail_at: usize,
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
    for fail_at in 1..=4 {
        let directory = tempfile::tempdir().unwrap();
        let profile = legacy(directory.path());
        let config = fs::read(directory.path().join("config.yaml")).unwrap();
        let state = fs::read(directory.path().join("ping-rust-state.json")).unwrap();
        let mut plan = SecurePlan::prepare(directory.path(), profile.id, SecureMode::Local)
            .unwrap()
            .unwrap();
        let mut fake = Fake {
            fail_at,
            step: 0,
            events: vec![],
            directory: directory.path().into(),
            original: config.clone(),
        };
        let error = crate::socks5_secure::apply(&mut plan, &mut fake)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("已恢复并再次验证"));
        assert_eq!(
            &fake.events[fake.events.len() - 2..],
            ["restore-firewall", "restore-service-and-verify"]
        );
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
