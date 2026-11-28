use super::*;

fn prepare_locked(
    directory: &Path,
    selector: &str,
    lock_path: &Path,
    dry_run: bool,
    choose: impl FnOnce() -> Result<Option<SecureMode>>,
) -> Result<Option<(SecurePlan, Option<utils::ExclusiveLock>)>> {
    super::prepare_locked(directory, selector, lock_path, dry_run, choose, |_| {
        panic!("没有待同步的状态，无需验证服务")
    })
}

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
    prepare_locked(
        directory,
        &profile.id.to_string(),
        &directory.join("lock"),
        true,
        || Ok(Some(mode)),
    )
    .unwrap()
    .expect("应生成加固计划")
    .0
}

#[tokio::test]
async fn choosing_socks5_mode_does_not_hold_config_lock() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let profile = legacy(path, 1080, "0.0.0.0").await;
    let lock_path = path.join("lock");
    let _ = utils::try_exclusive_lock(&lock_path, true).unwrap();
    let prepared = prepare_locked(path, &profile.name, &lock_path, false, || {
        let _other = utils::try_exclusive_lock(&lock_path, false)?.unwrap();
        Ok(Some(SecureMode::Local))
    })
    .unwrap();
    assert!(prepared.is_some());
    assert!(utils::try_exclusive_lock(&lock_path, true).is_err());
}

#[tokio::test]
async fn secure_preserves_unmodeled_fields_from_the_latest_snapshot() {
    use crate::config::managed_yaml_tests::write_fixture;
    use serde_json::{json, Value};

    for mode in [SecureMode::Auth, SecureMode::Local] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let (state, mut entries) = write_fixture(path).await;
        let lock_path = path.join("lock");
        let config = path.join("config.yaml");
        let other = profile_path(path, &state.profiles[0]);
        let target = profile_path(path, &state.profiles[1]);
        entries[1]["protocol"]["hand_added"] = json!({"preserve": true});
        fs::write(&config, crate::yaml::to_string(&entries).unwrap()).unwrap();
        fs::write(&target, crate::yaml::to_string(&entries[1]).unwrap()).unwrap();
        let (plan, _lock) =
            prepare_locked(path, &state.profiles[1].name, &lock_path, false, || {
                let _other_lock = utils::exclusive_lock(&lock_path)?;
                entries[0]["protocol"]["encryption_limits"]["updated"] = json!(true);
                fs::write(&config, crate::yaml::to_string(&entries)?)?;
                fs::write(&other, crate::yaml::to_string(&entries[0])?)?;
                Ok(Some(mode))
            })
            .unwrap()
            .unwrap();
        let previous = fs::read(&other).unwrap();
        let state_path = path.join("ping-rust-state.json");
        let previous_state = fs::read(&state_path).unwrap();
        let hardened = plan
            .commit(path, |_| {
                assert_eq!(fs::read(&state_path).unwrap(), previous_state);
                Ok(())
            })
            .unwrap();
        assert!(hardened.socks5_risk_warning().is_none());
        let actual: Vec<Value> = crate::yaml::from_slice(&fs::read(&config).unwrap()).unwrap();
        assert!(actual[0] == entries[0] && actual[2] == entries[2]);
        assert_eq!(fs::read(&other).unwrap(), previous);
        let target_copy: Value = crate::yaml::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert!(target_copy == actual[1]);
        match mode {
            SecureMode::Auth => {
                assert!(actual[1]["protocol"]["username"].is_string());
                assert!(actual[1]["protocol"]["password"].is_string());
                entries[1]["protocol"]["username"] = actual[1]["protocol"]["username"].clone();
                entries[1]["protocol"]["password"] = actual[1]["protocol"]["password"].clone();
            }
            SecureMode::Local => entries[1]["address"] = json!("127.0.0.1:1080"),
        }
        assert!(actual[1] == entries[1]);
        validate_managed_snapshot(&config, &state_path).unwrap();
    }
}

#[tokio::test]
async fn secure_refuses_a_conflicting_copy_or_a_stale_plan() {
    use crate::config::managed_yaml_tests::{hashes, write_fixture};
    use serde_json::json;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let (state, mut entries) = write_fixture(path).await;
    let profile = &state.profiles[1];
    let plan = prepare(path, profile, SecureMode::Local);
    let config = path.join("config.yaml");
    let copy = profile_path(path, &state.profiles[0]);
    entries[0]["protocol"]["encryption_limits"]["updated"] = json!(true);
    fs::write(&config, crate::yaml::to_string(&entries).unwrap()).unwrap();
    let before = hashes(path);
    let error = SecureTarget::load(path, &profile.name).err().unwrap();
    let error = format!("{error:#}");
    assert!(error.contains("config.yaml 第 1 项"));
    assert!(error.contains("protocol.encryption_limits.<字段>"));
    assert!(!error.contains("updated"));
    assert_eq!(hashes(path), before);

    fs::write(&copy, crate::yaml::to_string(&entries[0]).unwrap()).unwrap();
    let before = hashes(path);
    let error = plan
        .commit(path, |_| panic!("旧候选配置不能激活"))
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("受管配置在校验期间已变更"));
    assert_eq!(hashes(path), before);
}

#[tokio::test]
async fn already_safe_socks5_still_requires_config_lock() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let profile = legacy(path, 1080, "0.0.0.0").await;
    let plan = prepare(path, &profile, SecureMode::Local);
    let lock_path = path.join("lock");
    let held = utils::try_exclusive_lock(&lock_path, true)
        .unwrap()
        .unwrap();
    plan.commit(path, |_| Ok(())).unwrap();
    for dry_run in [false, true] {
        let result = prepare_locked(path, &profile.name, &lock_path, dry_run, || {
            panic!("安全节点无需选择")
        });
        assert!(format!("{:#}", result.err().unwrap()).contains("无法取得 ping-rust 配置锁"));
    }
    drop(held);
    assert!(prepare_locked(path, &profile.name, &lock_path, false, || {
        panic!("安全节点无需选择")
    })
    .unwrap()
    .is_none());
}

#[tokio::test]
async fn rejects_socks5_state_changed_during_prompt() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let profile = legacy(path, 1080, "0.0.0.0").await;
    let state_path = path.join("ping-rust-state.json");
    let result = prepare_locked(path, &profile.name, &path.join("lock"), false, || {
        let mut state = load_state_from(&state_path)?;
        state.profiles[0].server_address = Some("other.example.com".to_owned());
        save_state_to(&state_path, &state)?;
        Ok(Some(SecureMode::Local))
    });
    assert!(format!("{:#}", result.err().unwrap()).contains("所选 SOCKS5 节点已变更"));
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
async fn dry_run_redacts_specific_ipv4_and_ipv6_bindings() {
    for (binding, loopback) in [
        ("203.0.113.8", "127.0.0.1:1080"),
        ("2001:db8::8", "[::1]:1080"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let original = legacy(path, 1080, binding).await;
        for mode in [SecureMode::Auth, SecureMode::Local] {
            let diff = prepare(path, &original, mode).diff(path);
            assert!(!diff.contains(binding));
            assert_eq!(diff.matches("address: <已脱敏>:1080").count(), 2);
            if mode == SecureMode::Local {
                assert_eq!(diff.matches(&format!("+ address: {loopback}")).count(), 2);
            }
        }
    }
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn signals_remove_socks5_preflight_candidate() {
    use sha2::{Digest, Sha256};
    use std::{os::unix::fs::PermissionsExt, process::Command};

    const CHILD: &str = "PING_RUST_TEST_SOCKS5_PREFLIGHT_DIR";
    const SIGNAL: &str = "PING_RUST_TEST_SOCKS5_PREFLIGHT_SIGNAL";
    if let Some(path) = std::env::var_os(CHILD) {
        let path = PathBuf::from(path);
        let state = load_state_from(&path.join("ping-rust-state.json")).unwrap();
        let plan = prepare(&path, &state.profiles[0], SecureMode::Auth);
        let mut interrupt = signal(SignalKind::interrupt()).unwrap();
        tokio::spawn(async move {
            while interrupt.recv().await.is_some() {
                if let Ok(_guard) = crate::INTERRUPT_EXIT.try_lock() {
                    crate::restore_cursor_and_exit();
                }
            }
        });
        commit_with_signal_protection(
            async {
                validate_secure_candidate(&plan.yaml.aggregate, &path, &path.join("shoes")).await
            },
            |()| panic!("预检收到信号后不应提交"),
        )
        .await
        .unwrap();
        panic!("预检收到信号后不应继续执行");
    }

    for (signal, code) in [("HUP", 129), ("INT", 130), ("TERM", 143)] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let profile = legacy(path, 1080, "0.0.0.0").await;
        let files = [
            path.join("config.yaml"),
            path.join("ping-rust-state.json"),
            profile_path(path, &profile),
        ];
        let snapshot = || {
            files
                .each_ref()
                .map(|file| Sha256::digest(fs::read(file).unwrap()))
        };
        let before = snapshot();
        let shoes = path.join("shoes");
        fs::write(
            &shoes,
            r#"#!/bin/sh
test "$1" = --dry-run && test -s "$2" || exit 2
stat -c '%a' -- "$2" > "${2%/*}/candidate-mode" || exit 3
kill -s "$PING_RUST_TEST_SOCKS5_PREFLIGHT_SIGNAL" "$PPID" || exit 4
exec sleep 10
"#,
        )
        .unwrap();
        fs::set_permissions(&shoes, fs::Permissions::from_mode(0o700)).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "config::socks5::secure::tests::signals_remove_socks5_preflight_candidate",
            ])
            .env(CHILD, path)
            .env(SIGNAL, signal)
            .output()
            .unwrap();
        assert_eq!(
            fs::read_to_string(path.join("candidate-mode")).unwrap(),
            "600\n"
        );
        assert_eq!(snapshot(), before, "SIG{signal} 改写了受管文件");
        assert!(
            !path.read_dir().unwrap().any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".ping-rust-candidate-")),
            "SIG{signal} 遗留了候选配置"
        );
        assert_eq!(output.status.code(), Some(code), "SIG{signal}");
    }
}

#[tokio::test(flavor = "current_thread")]
#[cfg(target_os = "linux")]
async fn signals_at_socks5_preflight_completion_prevent_commit() {
    use sha2::{Digest, Sha256};
    use std::{ffi::c_int, process::Command};

    const CHILD: &str = "PING_RUST_TEST_SOCKS5_HANDOFF_DIR";
    const SIGNAL: &str = "PING_RUST_TEST_SOCKS5_HANDOFF_SIGNAL";
    extern "C" {
        fn raise(signal: c_int) -> c_int;
    }

    if let Some(path) = std::env::var_os(CHILD) {
        let path = PathBuf::from(path);
        let state = load_state_from(&path.join("ping-rust-state.json")).unwrap();
        let plan = prepare(&path, &state.profiles[0], SecureMode::Auth);
        let kind = match std::env::var(SIGNAL).unwrap().as_str() {
            "HUP" => SignalKind::hangup(),
            "INT" => SignalKind::interrupt(),
            "TERM" => SignalKind::terminate(),
            name => panic!("意外的测试信号：{name}"),
        };
        let commit_path = path.clone();
        commit_with_signal_protection(
            async {
                let mut candidate = SecureCandidate(Some(create_candidate(&path).unwrap()));
                write_candidate(candidate.0.as_mut().unwrap(), &plan.yaml.aggregate).unwrap();
                assert_eq!(unsafe { raise(kind.as_raw_value()) }, 0);
                Ok(plan)
            },
            move |plan| {
                fs::write(commit_path.join("commit-started"), b"").unwrap();
                plan.commit(&commit_path, |_| Ok(()))
            },
        )
        .await
        .unwrap();
        panic!("预检结束时收到信号后不应继续执行");
    }

    for (signal, code) in [("HUP", 129), ("INT", 130), ("TERM", 143)] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let profile = legacy(path, 1080, "0.0.0.0").await;
        let files = [
            path.join("config.yaml"),
            path.join("ping-rust-state.json"),
            profile_path(path, &profile),
        ];
        let snapshot = || {
            files
                .each_ref()
                .map(|file| Sha256::digest(fs::read(file).unwrap()))
        };
        let before = snapshot();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "config::socks5::secure::tests::signals_at_socks5_preflight_completion_prevent_commit",
            ])
            .env(CHILD, path)
            .env(SIGNAL, signal)
            .output()
            .unwrap();
        assert!(
            !path.join("commit-started").exists(),
            "SIG{signal} 启动了提交"
        );
        assert_eq!(snapshot(), before, "SIG{signal} 改写了受管文件");
        assert!(
            !path.read_dir().unwrap().any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".ping-rust-candidate-")),
            "SIG{signal} 遗留了候选配置"
        );
        assert_eq!(output.status.code(), Some(code), "SIG{signal}");
    }
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn signals_do_not_interrupt_socks5_rollback() {
    use std::{
        io::BufRead,
        process::{Command, Stdio},
        sync::mpsc,
    };

    const CHILD: &str = "PING_RUST_TEST_SOCKS5_SIGNAL_DIR";
    const SIGNAL: &str = "PING_RUST_TEST_SOCKS5_SIGNAL";
    fn signal_and_wait() {
        assert!(Command::new("/bin/sh")
            .args(["-c", "kill -s \"$1\" \"$2\"", "sh"])
            .arg(std::env::var(SIGNAL).unwrap())
            .arg(std::process::id().to_string())
            .status()
            .unwrap()
            .success());
        io::stdin().read_line(&mut String::new()).unwrap();
    }
    if let Some(path) = std::env::var_os(CHILD) {
        let path = PathBuf::from(path);
        let profile = load_state_from(&path.join("ping-rust-state.json"))
            .unwrap()
            .profiles
            .remove(0);
        let plan = prepare(&path, &profile, SecureMode::Local);
        let result = commit_with_signal_protection(std::future::ready(Ok(())), move |()| {
            let terminate = std::env::var(SIGNAL).unwrap() == "TERM";
            if !terminate {
                commit::AFTER_PROFILE_REPLACE.set(Some(signal_and_wait));
            }
            plan.commit(&path, |profile| {
                if profile.socks5_loopback().is_some() {
                    if terminate {
                        signal_and_wait();
                    }
                    bail!("模拟收到信号后的服务启动失败");
                }
                Ok(())
            })
        })
        .await;
        assert!(result.is_err());
        return;
    }

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let profile = legacy(path, 1080, "0.0.0.0").await;
    let files = [
        path.join("config.yaml"),
        path.join("ping-rust-state.json"),
        profile_path(path, &profile),
    ];
    let snapshot = || files.each_ref().map(|file| fs::read(file).unwrap());
    let before = snapshot();
    for (signal, code) in [("HUP", 129), ("INT", 130), ("TERM", 143)] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "config::socks5::secure::tests::signals_do_not_interrupt_socks5_rollback",
                "--nocapture",
            ])
            .env(CHILD, path)
            .env(SIGNAL, signal)
            .env("PATH", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = io::BufReader::new(child.stderr.take().unwrap());
        let (notify, observed) = mpsc::channel();
        let log = thread::spawn(move || {
            let mut log = String::new();
            stderr.read_line(&mut log).unwrap();
            let _ = notify.send(log.contains(&format!("收到 SIG{signal}")));
            stderr.read_to_string(&mut log).unwrap();
            log
        });
        let signal_received = observed.recv_timeout(Duration::from_secs(10));
        let during = snapshot();
        drop(child.stdin.take());
        let status = child.wait().unwrap();
        let log = log.join().unwrap();
        assert!(
            snapshot() == before,
            "SIG{signal} 导致配置未完整回滚：{log}"
        );
        assert_eq!(signal_received, Ok(true), "SIG{signal}: {log}");
        assert_eq!(status.code(), Some(code));
        assert!(log.contains("原配置已恢复"), "{log}");
        if signal != "TERM" {
            assert!(during[..2] == before[..2] && during[2] != before[2]);
        }
    }
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
                assert_ne!(after[0], before[0]);
                assert_eq!(after[1], before[1], "服务验证前不能写入 state");
                assert_ne!(after[2], before[2]);
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
#[cfg(target_os = "linux")]
async fn interrupted_socks5_commit_recovers_from_hardened_config_and_old_state() {
    use std::process::Command;

    const CHILD: &str = "PING_RUST_TEST_SOCKS5_INTERRUPTED_DIR";
    const MODE: &str = "PING_RUST_TEST_SOCKS5_INTERRUPTED_MODE";
    const INTERRUPTED: i32 = 83;
    if let Some(path) = std::env::var_os(CHILD) {
        let path = PathBuf::from(path);
        let mode = if std::env::var(MODE).unwrap() == "auth" {
            SecureMode::Auth
        } else {
            SecureMode::Local
        };
        let state = load_state_from(&path.join("ping-rust-state.json")).unwrap();
        let plan = prepare(&path, &state.profiles[0], mode);
        let _lock = utils::try_exclusive_lock(&path.join("lock"), true).unwrap();
        plan.commit(&path, |_| std::process::exit(INTERRUPTED))
            .unwrap();
        panic!("应在激活阶段中止提交");
    }

    for (mode, explicit_listen) in [("auth", false), ("local", false), ("local", true)] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let profile = legacy(path, 1080, "0.0.0.0").await;
        let config = path.join("config.yaml");
        let state = path.join("ping-rust-state.json");
        let profile_file = profile_path(path, &profile);
        if explicit_listen {
            let mut explicit = load_state_from(&state).unwrap();
            explicit.profiles[0].server_address = Some("127.0.0.1".to_owned());
            save_state_to(&state, &explicit).unwrap();
        }
        let before = fs::read(&state).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "config::socks5::secure::tests::interrupted_socks5_commit_recovers_from_hardened_config_and_old_state",
            ])
            .env(CHILD, path)
            .env(MODE, mode)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(INTERRUPTED), "{output:?}");
        let servers = load_servers(&config).unwrap();
        let on_disk: ServerConfig =
            crate::yaml::from_slice(&fs::read(&profile_file).unwrap()).unwrap();
        assert!(
            crate::yaml::to_string(&on_disk).unwrap()
                == crate::yaml::to_string(&servers[0]).unwrap()
        );
        if mode == "auth" {
            assert_eq!(servers[0].address, "0.0.0.0:1080");
            assert!(matches!(&servers[0].protocol, ServerProtocol::Socks {
                username: Some(username), password: Some(password), ..
            } if !username.is_empty() && !password.is_empty()));
        } else {
            assert_eq!(servers[0].address, "127.0.0.1:1080");
        }
        assert!(
            fs::read(&state).unwrap() == before,
            "中断时 state 必须仍是旧值"
        );
        let lock = path.join("lock");
        let choose = || panic!("已加固的磁盘配置无需重新选择");
        assert!(prepare_locked(path, &profile.name, &lock, true, choose)
            .unwrap()
            .is_none());
        let result = super::prepare_locked(path, &profile.name, &lock, false, choose, |_| {
            bail!("模拟中断后服务仍在使用旧配置")
        });
        assert!(format!("{:#}", result.err().unwrap()).contains("未能确认服务已加载"));
        assert!(
            fs::read(&state).unwrap() == before,
            "未验证服务时不得改写 state"
        );

        assert!(
            super::prepare_locked(path, &profile.name, &lock, false, choose, |recovered| {
                assert!(utils::try_exclusive_lock(&lock, false).is_err());
                assert!(recovered.socks5_risk_warning().is_none());
                ensure_servers_match_state(&servers, std::slice::from_ref(recovered))
            })
            .unwrap()
            .is_none()
        );
        let recovered = load_state_from(&state).unwrap();
        assert_eq!(recovered.profiles[0].id, profile.id);
        assert!(recovered.profiles[0].socks5_risk_warning().is_none());
        if mode == "local" {
            assert_eq!(
                recovered.profiles[0].server_address.as_deref(),
                Some("127.0.0.1")
            );
        }
        ensure_servers_match_state(&servers, &recovered.profiles).unwrap();
    }
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
            prepare_locked(path, &original.name, &path.join("lock"), true, || panic!(
                "安全节点无需选择"
            ))
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
        validate_candidate_with_binary(&plan.yaml.aggregate, path, &binary)
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
