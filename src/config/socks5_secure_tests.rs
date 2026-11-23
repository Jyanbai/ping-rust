use super::schema::TlsTarget;
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
        fs::write(&config_path, &unsafe_config).unwrap();

        assert!(SecurePlan::already_secure(directory.path(), profile.id).is_err());
        assert!(SecurePlan::prepare(directory.path(), profile.id, mode).is_err());
        assert_eq!(fs::read(&config_path).unwrap(), unsafe_config);
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
        async fn preflight(&mut self, _: &SecurePlan) -> Result<()> {
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
        let interrupt = crate::socks5_secure::Interrupt::default();
        let error = crate::socks5_secure::apply(&mut plan, &mut fake, &interrupt)
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

struct InterruptedRuntime<'a> {
    interrupt: &'a crate::socks5_secure::Interrupt,
    directory: &'a Path,
    has_ss: bool,
    stop_at: &'static str,
    events: Vec<&'static str>,
}

impl crate::socks5_secure::Runtime for InterruptedRuntime<'_> {
    async fn preflight(&mut self, _: &SecurePlan) -> Result<()> {
        assert!(!self.directory.join("profiles").exists());
        crate::socks5_secure::require_tools(|tool| self.has_ss || tool != "ss")
    }

    async fn activate(&mut self) -> Result<()> {
        self.record("activate");
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
        assert!(self.interrupt.defer_signal());
        Ok(())
    }

    async fn restore_service(&mut self, _: &ManagedProfile) -> Result<()> {
        self.events.push("restore-service");
        Ok(())
    }
}

impl InterruptedRuntime<'_> {
    fn record(&mut self, event: &'static str) {
        self.events.push(event);
        if self.stop_at == event {
            assert!(self.directory.join("profiles").is_dir());
            assert!(self.interrupt.defer_signal());
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
        };
        let error = crate::socks5_secure::apply(&mut plan, &mut runtime, &interrupt)
            .await
            .unwrap_err();
        assert!(crate::is_interrupted(&error));
        assert!(error.to_string().contains("已恢复并再次验证"));
        assert_eq!(runtime.events, expected);
        assert_eq!(
            fs::read(directory.path().join("config.yaml")).unwrap(),
            config
        );
        assert_eq!(
            fs::read(directory.path().join("ping-rust-state.json")).unwrap(),
            state
        );
        assert!(!directory.path().join("profiles").exists());
        assert!(!interrupt.defer_signal());
    }
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
