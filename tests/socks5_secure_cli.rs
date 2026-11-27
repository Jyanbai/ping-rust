use std::process::{Command, Stdio};

#[test]
fn socks5_secure_requires_explicit_mode_without_tty_or_with_yes() {
    for args in [vec![], vec!["--yes"], vec!["--dry-run"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_ping-rust"))
            .args(["socks5", "secure", "legacy"])
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("非交互模式"), "{error}");
        assert!(
            error.contains("--auth") && error.contains("--local"),
            "{error}"
        );
    }
}

#[test]
fn socks5_secure_rejects_conflicting_modes() {
    let output = Command::new(env!("CARGO_BIN_EXE_ping-rust"))
        .args(["socks5", "secure", "legacy", "--auth", "--local"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("--auth") && error.contains("--local"),
        "{error}"
    );
}
