//! 菜单输入终端回归：
//! sudo env PING_RUST_MENU_E2E=1 cargo test --offline --test menu_input_e2e -- --nocapture
//!
//! 需要 Linux、root、expect，以及 /etc/shoes 下至少一份已初始化且节点文件齐全的
//! 当前版本受管配置（使用专用测试机），含一个绑定 IPv4 通配地址的 SOCKS5 节点。
//! 加固回归在 shoes 停止时临时写入旧版无认证格式并恢复。测试只发送取消或无效输入，
//! 无需 systemd，也不访问网络。若需迁移节点文件则先在测试机
//! 完成迁移（那一步需要 shoes）。测试前后逐字节比较聚合配置、state 和节点文件。
#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::{Command, Stdio},
};

use serde_json::Value;

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

struct RestoreSocks5Files<'a>([(&'a Path, &'a [u8]); 3]);

impl Drop for RestoreSocks5Files<'_> {
    fn drop(&mut self) {
        for (path, bytes) in self.0 {
            if let Err(error) = fs::write(path, bytes) {
                eprintln!("恢复 {} 失败：{error}", path.display());
            }
        }
    }
}

fn check_socks5_secure_cancellation(
    directory: &Path,
    original: &BTreeMap<std::path::PathBuf, Vec<u8>>,
) {
    let shoes = Command::new("pgrep")
        .args(["-x", "shoes"])
        .stdout(Stdio::null())
        .status()
        .expect("检查 shoes 进程");
    assert_eq!(shoes.code(), Some(1), "请先停止测试机的 shoes 进程");
    let state_path = directory.join("ping-rust-state.json");
    let config_path = directory.join("config.yaml");
    let mut state: Value = serde_json::from_slice(&original[&state_path]).unwrap();
    let node = state["profiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["credentials"]["Socks5"]["listen"]["address"] == "0.0.0.0")
        .expect("请预置一个监听 0.0.0.0 的 SOCKS5 测试节点");
    let selector = node["id"].as_str().unwrap().to_owned();
    let port = node["port"].as_u64().unwrap();
    let creds = node["credentials"]["Socks5"].as_object_mut().unwrap();
    for key in ["listen", "username", "password"] {
        creds.remove(key);
    }
    let profile_path = directory.join(format!("profiles/SOCKS5-{port}.yaml"));
    let mut servers: Vec<Value> =
        serde_saphyr::from_str(std::str::from_utf8(&original[&config_path]).unwrap()).unwrap();
    let address = format!("0.0.0.0:{port}");
    let server = servers
        .iter_mut()
        .find(|server| server["address"] == address)
        .unwrap();
    let protocol = server["protocol"].as_object_mut().unwrap();
    protocol.remove("username");
    protocol.remove("password");
    let _restore = RestoreSocks5Files([
        (&profile_path, &original[&profile_path]),
        (&config_path, &original[&config_path]),
        (&state_path, &original[&state_path]),
    ]);
    fs::write(&profile_path, serde_json::to_vec(server).unwrap()).unwrap();
    fs::write(&config_path, serde_json::to_vec(&servers).unwrap()).unwrap();
    fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let before = snapshot(directory);
    let output = Command::new("expect")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/menu_input.exp"))
        .arg(env!("CARGO_BIN_EXE_ping-rust"))
        .arg(selector)
        .env("NO_COLOR", "1")
        .output()
        .expect("运行 SOCKS5 加固终端回归");
    assert!(snapshot(directory) == before, "加固取消改动了受管文件");
    assert!(
        output.status.success(),
        "加固终端回归失败：\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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
    check_socks5_secure_cancellation(directory, &before);
    assert!(
        snapshot(directory) == before,
        "旧版 SOCKS5 测试文件未完整恢复"
    );
}
