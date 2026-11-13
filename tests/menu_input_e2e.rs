//! 菜单输入终端回归：
//! sudo env PING_RUST_MENU_E2E=1 cargo test --offline --test menu_input_e2e -- --nocapture
//!
//! 需要 Linux、root、expect，以及 /etc/shoes 下至少一份已初始化且节点文件齐全的
//! 当前版本受管配置（使用专用测试机）。本测试不负责部署节点；只有取消/无效输入，
//! 不需要 shoes 运行或 systemd 可用，也不访问网络。若需迁移节点文件则先在测试机
//! 完成迁移（那一步需要 shoes）。测试前后逐字节比较聚合配置、state 和节点文件。
#![cfg(target_os = "linux")]

use std::{collections::BTreeMap, fs, path::Path, process::Command};

fn snapshot(directory: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(directory).expect("读取测试配置目录") {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(snapshot(&path));
        } else {
            files.insert(path.clone(), fs::read(path).expect("读取测试配置文件"));
        }
    }
    files
}

#[test]
fn menu_input_returns_retries_defaults_to_no_and_handles_eof() {
    if std::env::var("PING_RUST_MENU_E2E").as_deref() != Ok("1") {
        eprintln!(
            "跳过 menu_input.exp：未设置 PING_RUST_MENU_E2E=1（需要 Linux/root/预置受管配置）"
        );
        return;
    }
    if !Command::new("expect")
        .arg("-v")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        eprintln!("跳过 menu_input.exp：系统未安装 expect");
        return;
    }
    let uid = Command::new("id").arg("-u").output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&uid.stdout).trim(),
        "0",
        "终端回归需要 root"
    );
    let directory = Path::new("/etc/shoes");
    let before = snapshot(directory);
    let state: serde_json::Value = serde_json::from_slice(
        &fs::read(directory.join("ping-rust-state.json")).expect("请预置当前版本受管配置"),
    )
    .unwrap();
    let profiles = state["profiles"].as_array().expect("受管 profiles");
    assert!(!profiles.is_empty(), "请预置至少一个测试节点");
    let output = Command::new("expect")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/menu_input.exp"))
        .arg(env!("CARGO_BIN_EXE_ping-rust"))
        .arg(profiles[0]["port"].as_u64().expect("节点端口").to_string())
        .arg(profiles.len().to_string())
        .env("NO_COLOR", "1")
        .output()
        .expect("运行 menu_input.exp");
    // 只打印菜单及取消输入，不输出配置快照中的任何凭据。
    eprintln!("{}", String::from_utf8_lossy(&output.stdout));
    eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    let transcript = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for removed in [
        "没有任何加密",
        "旧分享链接",
        "凭据失效",
        "固定 pin",
        "受控重启",
        "TCP splice",
        "64 KiB",
        "UDP/QUIC",
        "上行约",
        "Mihomo 已验证",
        "传输加密",
    ] {
        assert!(!transcript.contains(removed), "冗余提示仍出现：{removed}");
    }
    assert!(!transcript.contains("· menu-e2e"));
    let after = snapshot(directory);
    assert!(before == after, "取消输入、回车保持或默认否操作改动了配置");
    assert!(
        output.status.success(),
        "menu_input.exp 失败：{}",
        output.status
    );
}
