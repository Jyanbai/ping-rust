use super::*;

async fn anonymous(directory: &Path) -> GenerationResult {
    let mut request = tests::request(Protocol::Socks5, directory.join("config.yaml"));
    request.options.socks5_no_auth = true;
    generate_inner(request, false).await.unwrap()
}

#[tokio::test]
async fn socks5_generation_persists_rollback_compatible_client_address() {
    for (server_address, loopback) in [
        (Some("203.0.113.8"), "127.0.0.1"),
        (None, "127.0.0.1"),
        (Some("example.com"), "127.0.0.1"),
        (Some("2001:db8::8"), "::1"),
        (Some("[2001:db8::8]"), "::1"),
    ] {
        for no_auth in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let mut request =
                tests::request(Protocol::Socks5, directory.path().join("config.yaml"));
            request.options.socks5_no_auth = no_auth;
            request.server_address = server_address.map(str::to_owned);
            let result = generate_inner(request, false).await.unwrap();
            let expected = if no_auth {
                Some(loopback)
            } else {
                server_address
            };
            let servers = load_servers(&result.config_path).unwrap();
            assert_eq!(
                servers[0].address,
                socks5_address(if no_auth { loopback } else { "0.0.0.0" }, 443)
            );
            let state_path = directory.path().join("ping-rust-state.json");
            save_state_to(
                &state_path,
                &ManagedState {
                    profiles: vec![result.profile],
                    ..Default::default()
                },
            )
            .unwrap();
            let json: serde_json::Value =
                serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
            // v0.2.1 ignores `listen` and uses this field for URL, QR and info.
            assert_eq!(json["profiles"][0]["server_address"].as_str(), expected);
            let restored = load_state_from(&state_path).unwrap();
            assert_eq!(restored.profiles[0].server_address.as_deref(), expected);
        }
    }
}

#[tokio::test]
async fn socks5_loopback_survives_edit_rebuild_and_upgrade() {
    for server_address in ["203.0.113.8", "2001:db8::8"] {
        let directory = tempfile::tempdir().unwrap();
        let mut request = tests::request(Protocol::Socks5, directory.path().join("config.yaml"));
        request.options.socks5_no_auth = true;
        request.server_address = Some(server_address.to_owned());
        let result = generate_inner(request, false).await.unwrap();
        let mut servers = load_servers(&result.config_path).unwrap();
        let mut state = ManagedState {
            profiles: vec![result.profile],
            ..Default::default()
        };
        let host = if server_address.contains(':') {
            "::1"
        } else {
            "127.0.0.1"
        };
        assert_eq!(servers[0].address, socks5_address(host, 443));
        apply_profile_change(
            &mut servers[0],
            &mut state.profiles[0],
            ProfileChange::Port(1080),
        )
        .unwrap();
        for _ in 0..2 {
            let documents = profile_documents(&servers, &state.profiles).unwrap();
            let yaml = aggregate_profile_documents(&documents, &state.profiles).unwrap();
            assert!(yaml.contains(&socks5_address(host, 1080)));
            fs::write(&result.config_path, yaml).unwrap();
            let state_path = directory.path().join("ping-rust-state.json");
            save_state_to(&state_path, &state).unwrap();
            state = load_state_from(&state_path).unwrap();
            servers = load_servers(&result.config_path).unwrap();
            assert!(state.profiles[0].socks5_risk_warning().is_none());
        }
    }
}

#[tokio::test]
async fn socks5_legacy_public_migration_preserves_binding_and_warns() {
    for host in ["0.0.0.0", "::", "[::]", "2001:0db8::8", "203.0.113.8"] {
        let directory = tempfile::tempdir().unwrap();
        let result = anonymous(directory.path()).await;
        let mut servers = load_servers(&result.config_path).unwrap();
        servers[0].address = socks5_address(host, result.profile.port);
        fs::write(
            &result.config_path,
            crate::yaml::to_string(&servers).unwrap(),
        )
        .unwrap();
        let mut json = serde_json::to_value(ManagedState {
            profiles: vec![result.profile],
            ..Default::default()
        })
        .unwrap();
        json["profiles"][0]["credentials"]["Socks5"]
            .as_object_mut()
            .unwrap()
            .remove("listen");
        let state_path = directory.path().join("ping-rust-state.json");
        fs::write(&state_path, serde_json::to_vec(&json).unwrap()).unwrap();
        let mut state = load_state_from(&state_path).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&state_path).unwrap()).unwrap(),
            json,
            "只读加载不得改写旧状态"
        );
        assert!(socks5::listen_migration_pending(&state_path).unwrap());
        let runtime_before = fs::read(&result.config_path).unwrap();
        let profiles_path = directory.path().join("profiles");
        commit_managed_with_state_writer(
            &result.config_path,
            &state_path,
            &profiles_path,
            &servers,
            &state,
            save_state_to,
        )
        .unwrap();
        assert!(!socks5::listen_migration_pending(&state_path).unwrap());
        assert_eq!(fs::read(&result.config_path).unwrap(), runtime_before);
        state = load_state_from(&state_path).unwrap();
        apply_profile_change(
            &mut servers[0],
            &mut state.profiles[0],
            ProfileChange::Port(1080),
        )
        .unwrap();
        let documents = profile_documents(&servers, &state.profiles).unwrap();
        let yaml = aggregate_profile_documents(&documents, &state.profiles).unwrap();
        let rebuilt: Vec<ServerConfig> = crate::yaml::from_str(&yaml).unwrap();
        assert_eq!(rebuilt[0].address, socks5_address(host, 1080));
        let warning = state.profiles[0].socks5_risk_warning().unwrap();
        assert!(warning.contains("1080"));
        assert!(warning.contains(&state.profiles[0].name));
        assert!(warning.contains("`sudo prs menu`"));
        assert!(warning.contains("更改认证模式"));
        assert!(warning.contains("启用用户名 + 密码认证"));
        assert!(!warning.contains(host));
        save_state_to(&state_path, &state).unwrap();
        let restored = load_state_from(&state_path).unwrap();
        assert!(restored.profiles[0].socks5_risk_warning().is_some());
        ensure_servers_match_state(&rebuilt, &restored.profiles).unwrap();
        let mut changed = restored.profiles[0].clone();
        let Credentials::Socks5 {
            listen: Some(listen),
            ..
        } = &mut changed.credentials
        else {
            unreachable!()
        };
        listen.address = "203.0.113.99".to_owned();
        assert!(
            changed.validate_socks5_listen().is_err(),
            "旧节点例外不能许可另一个地址"
        );
    }
}

#[tokio::test]
async fn socks5_profile_and_aggregate_reject_public_and_missing_listen() {
    let directory = tempfile::tempdir().unwrap();
    let result = anonymous(directory.path()).await;
    let original = load_servers(&result.config_path).unwrap();
    for host in ["0.0.0.0", "::", "[::]", "", "example.com", "203.0.113.9"] {
        let mut profile = result.profile.clone();
        let Credentials::Socks5 { listen, .. } = &mut profile.credentials else {
            unreachable!()
        };
        *listen = Some(Socks5Listen::new(host));
        assert!(profile.validate_socks5_listen().is_err(), "{host}");
        let mut servers = original.clone();
        servers[0].address = socks5_address(host, profile.port);
        assert!(
            profile_documents(&servers, &[profile.clone()]).is_err(),
            "{host}"
        );
        let documents = BTreeMap::from([(
            profile.config_file_name(),
            crate::yaml::to_string(&servers[0]).unwrap().into_bytes(),
        )]);
        assert!(
            aggregate_profile_documents(&documents, &[profile]).is_err(),
            "{host}"
        );
    }
    let mut profile = result.profile;
    let Credentials::Socks5 { listen, .. } = &mut profile.credentials else {
        unreachable!()
    };
    *listen = None;
    assert!(profile.validate_socks5_listen().is_err());
    assert!(profile_documents(&original, &[profile]).is_err());
}

#[tokio::test]
async fn socks5_loopback_exports_cannot_advertise_public_address() {
    let directory = tempfile::tempdir().unwrap();
    let profile = anonymous(directory.path()).await.profile;
    assert!(crate::client::share_uri(&profile, "203.0.113.8").is_err());
    for format in [
        crate::client::ClientFormat::ClashMeta,
        crate::client::ClientFormat::SingBox,
    ] {
        assert!(crate::client::render(&profile, format, "203.0.113.8").is_err());
        assert!(crate::client::render(&profile, format, "127.0.0.1").is_ok());
    }
    assert!(crate::client::stored_share_uri(&profile, None)
        .unwrap()
        .contains("127.0.0.1"));
    assert!(crate::client::share_uri(&profile, "127.0.0.1").is_ok());
    assert!(crate::client::share_uri(&profile, "::1").is_err());
}

#[tokio::test]
async fn socks5_legacy_snapshot_persists_listen_even_when_profiles_are_current() {
    let directory = tempfile::tempdir().unwrap();
    let result = anonymous(directory.path()).await;
    let servers = load_servers(&result.config_path).unwrap();
    let state = ManagedState {
        profiles: vec![result.profile],
        ..Default::default()
    };
    let documents = profile_documents(&servers, &state.profiles).unwrap();
    write_profile_documents(&directory.path().join("profiles"), &documents).unwrap();
    let mut json = serde_json::to_value(state).unwrap();
    json["profiles"][0]["credentials"]["Socks5"]
        .as_object_mut()
        .unwrap()
        .remove("listen");
    let state_path = directory.path().join("ping-rust-state.json");
    fs::write(&state_path, serde_json::to_vec(&json).unwrap()).unwrap();
    assert!(prepare_managed_snapshot(directory.path()).unwrap());
    assert!(!socks5::listen_migration_pending(&state_path).unwrap());
    assert!(!prepare_managed_snapshot(directory.path()).unwrap());
    validate_managed_snapshot(&result.config_path, &state_path).unwrap();
    assert!(load_state_from(&state_path).unwrap().profiles[0]
        .socks5_risk_warning()
        .is_none());
}

#[tokio::test]
async fn socks5_render_rejects_runtime_authentication_and_address_mismatches() {
    let directory = tempfile::tempdir().unwrap();
    let request = tests::request(Protocol::Socks5, directory.path().join("config.yaml"));
    let result = generate_inner(request, false).await.unwrap();
    let mut servers = load_servers(&result.config_path).unwrap();
    let before = serde_json::to_value(&result.profile).unwrap();
    let mut profile = result.profile;
    assert!(apply_profile_change(
        &mut servers[0],
        &mut profile,
        ProfileChange::Socks5Authentication(false)
    )
    .is_err());
    assert_eq!(serde_json::to_value(&profile).unwrap(), before);
    let ServerProtocol::Socks {
        username, password, ..
    } = &mut servers[0].protocol
    else {
        unreachable!()
    };
    *username = None;
    *password = None;
    assert!(profile_documents(&servers, &[profile]).is_err());

    let result = anonymous(directory.path()).await;
    let mut servers = load_servers(&result.config_path).unwrap();
    servers[0].address = format!("0.0.0.0:{}", result.profile.port);
    assert!(profile_documents(&servers, &[result.profile]).is_err());
}

#[test]
fn socks5_ipv6_generation_and_loopback_classification() {
    for host in ["127.0.0.1", "127.2.3.4", "::1", "[::1]"] {
        assert!(socks5_is_loopback(host));
    }
    for host in [
        "0.0.0.0",
        "::",
        "[::]",
        "",
        "localhost",
        "::ffff:127.0.0.1",
        "[127.0.0.1]",
    ] {
        assert!(!socks5_is_loopback(host));
    }
    let mut request = tests::request(Protocol::Socks5, PathBuf::from("unused.yaml"));
    request.server_address = Some("2001:db8::1".to_owned());
    request.options.socks5_no_auth = true;
    let generated = presets::generate(&request, Path::new("."), Uuid::nil()).unwrap();
    assert_eq!(generated.server.address, "[::1]:443");
}

#[tokio::test]
async fn socks5_fixed_shoes_requires_explicit_address() {
    let Some(binary) = crate::shoes_e2e::shoes_binary(
        "socks5_fixed_shoes_requires_explicit_address",
        &[
            crate::shoes_e2e::TEST_SHOES,
            crate::shoes_e2e::SHOES_E2E_BIN,
        ],
    ) else {
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    // shoes uses `address`, not a separate `listen` field. Missing or empty
    // address must fail instead of silently falling back to a public bind.
    for address in ["", "  address: ''\n"] {
        let yaml =
            format!("-\n{address}  protocol:\n    type: socks\n  rules:\n    - allow-all-direct\n");
        assert!(
            validate_candidate_with_binary(&yaml, directory.path(), &binary)
                .await
                .is_err()
        );
    }
    let result = anonymous(directory.path()).await;
    validate_with_binary(&binary, &result.config_path)
        .await
        .unwrap();
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn socks5_real_tcp_loopback_isolation_and_authentication() {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        process::Stdio,
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let Some(binary) = crate::shoes_e2e::shoes_binary(
        "socks5_real_tcp_loopback_isolation_and_authentication",
        &[
            crate::shoes_e2e::TEST_SHOES,
            crate::shoes_e2e::SHOES_E2E_BIN,
        ],
    ) else {
        return;
    };
    // Query an actual interface address without relying on external routing.
    let routes = fs::read_to_string("/proc/net/fib_trie").unwrap();
    let lines = routes.lines().collect::<Vec<_>>();
    let non_loopback = lines
        .windows(2)
        .filter(|pair| pair[1].contains("/32 host LOCAL"))
        .filter_map(|pair| pair[0].split_whitespace().last()?.parse::<Ipv4Addr>().ok())
        .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .expect("CI 必须提供非回环 IPv4 网卡，以验证监听隔离");
    let directory = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    for authenticated in [false, true] {
        let reservation = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let mut request = tests::request(Protocol::Socks5, directory.path().join("config.yaml"));
        request.port = port;
        request.options.socks5_no_auth = !authenticated;
        request.options.udp_enabled = false;
        let result = generate_inner(request, false).await.unwrap();
        validate_with_binary(&binary, &result.config_path)
            .await
            .unwrap();
        let mut child = Command::new(&binary)
            .arg(&result.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                assert!(child.try_wait().unwrap().is_none(), "shoes 提前退出");
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
        if !authenticated {
            let error = tokio::time::timeout(
                Duration::from_secs(2),
                TcpStream::connect((non_loopback, port)),
            )
            .await
            .unwrap()
            .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        }
        let Credentials::Socks5 {
            username, password, ..
        } = result.credentials
        else {
            unreachable!()
        };
        let target = if authenticated {
            IpAddr::V4(non_loopback)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        for wrong_password in if authenticated {
            vec![true, false]
        } else {
            vec![false]
        } {
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut stream = TcpStream::connect(SocketAddr::new(target, port))
                    .await
                    .unwrap();
                stream
                    .write_all(&[5, 1, if authenticated { 2 } else { 0 }])
                    .await
                    .unwrap();
                let mut reply = [0; 2];
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply, [5, if authenticated { 2 } else { 0 }]);
                if authenticated {
                    let user = username.as_ref().unwrap().as_bytes();
                    let pass = if wrong_password {
                        "wrong-password"
                    } else {
                        password.as_ref().unwrap()
                    }
                    .as_bytes();
                    let mut auth = vec![1, user.len() as u8];
                    auth.extend_from_slice(user);
                    auth.push(pass.len() as u8);
                    auth.extend_from_slice(pass);
                    stream.write_all(&auth).await.unwrap();
                    let response = stream.read_exact(&mut reply).await;
                    if wrong_password {
                        match response {
                            Ok(_) => assert_ne!(reply[1], 0, "错误凭据不能通过认证"),
                            Err(error) => assert!(
                                matches!(
                                    error.kind(),
                                    std::io::ErrorKind::UnexpectedEof
                                        | std::io::ErrorKind::ConnectionReset
                                ),
                                "错误凭据必须被明确拒绝或断开连接"
                            ),
                        }
                        return;
                    }
                    response.unwrap();
                    assert_eq!(reply, [1, 0]);
                }
                let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
                connect.extend_from_slice(&origin_address.port().to_be_bytes());
                stream.write_all(&connect).await.unwrap();
                let mut header = [0; 4];
                stream.read_exact(&mut header).await.unwrap();
                assert_eq!(&header[..3], &[5, 0, 0]);
                let length = match header[3] {
                    1 => 6,
                    4 => 18,
                    other => panic!("unexpected ATYP {other}"),
                };
                stream.read_exact(&mut vec![0; length]).await.unwrap();
                let (mut accepted, _) = origin.accept().await.unwrap();
                accepted.write_all(b"socks5-ok").await.unwrap();
                let mut body = [0; 9];
                stream.read_exact(&mut body).await.unwrap();
                assert_eq!(&body, b"socks5-ok");
            })
            .await
            .unwrap();
        }
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }
}
