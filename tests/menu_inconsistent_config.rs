//! 聚合配置与管理状态不一致时菜单仍要可用（回归）：
//! sudo env PING_RUST_MENU_E2E=1 cargo test --offline --test menu_inconsistent_config -- --nocapture
//!
//! 需要 Linux、root，以及 /etc/shoes 下至少一份已初始化的当前版本受管配置（使用专用测试机，
//! 与 menu_input_e2e 相同）。测试把 config.yaml 第一个节点的监听端口改成与 state 不一致，
//! 用管道输入 `0` 运行菜单，然后逐字节恢复 config.yaml（断言失败时也恢复）。
//! 不需要 shoes 运行、systemd 或网络：HTTPS 代理指向本机关闭的端口。
#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CONFIG_DIR: &str = "/etc/shoes";
const CONFIG_FILE: &str = "/etc/shoes/config.yaml";
const STATE_FILE: &str = "/etc/shoes/ping-rust-state.json";
const CLOSED_PROXY: &str = "http://127.0.0.1:9";

fn snapshot(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
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

/// 无论测试成功还是断言失败，都把 config.yaml 写回原内容（写入已有文件，权限不变）。
struct RestoreConfig(Vec<u8>);

impl Drop for RestoreConfig {
    fn drop(&mut self) {
        if let Err(error) = fs::write(CONFIG_FILE, &self.0) {
            eprintln!("恢复 {CONFIG_FILE} 失败：{error}");
        }
    }
}

#[test]
fn inconsistent_config_still_opens_main_menu_without_writing() {
    if std::env::var("PING_RUST_MENU_E2E").as_deref() != Ok("1") {
        eprintln!("跳过：未设置 PING_RUST_MENU_E2E=1（需要 Linux/root/预置受管配置）");
        return;
    }
    let uid = Command::new("id").arg("-u").output().expect("运行 id -u");
    assert_eq!(
        String::from_utf8_lossy(&uid.stdout).trim(),
        "0",
        "本回归需要 root"
    );

    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(STATE_FILE).expect("请预置当前版本受管配置")).unwrap();
    let port = state["profiles"][0]["port"]
        .as_u64()
        .expect("请预置至少一个测试节点");
    let original = fs::read(CONFIG_FILE).expect("读取聚合配置");
    let _restore = RestoreConfig(original.clone());

    // 只改第一个节点的监听端口：state 不变，两者按位置比对时一定不一致。
    let listen = format!("0.0.0.0:{port}");
    let other = if port == 65535 { port - 1 } else { port + 1 };
    let text = String::from_utf8(original).expect("聚合配置是 UTF-8");
    assert!(text.contains(&listen), "聚合配置里找不到监听地址 {listen}");
    fs::write(
        CONFIG_FILE,
        text.replacen(&listen, &format!("0.0.0.0:{other}"), 1),
    )
    .expect("写入不一致的聚合配置");
    let before = snapshot(Path::new(CONFIG_DIR));

    let mut child = Command::new(env!("CARGO_BIN_EXE_ping-rust"))
        .env("NO_COLOR", "1")
        .env("HTTPS_PROXY", CLOSED_PROXY)
        .env("https_proxy", CLOSED_PROXY)
        .env("ALL_PROXY", CLOSED_PROXY)
        .env("all_proxy", CLOSED_PROXY)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("启动 ping-rust 菜单");
    // 主菜单出现后输入 0 退出；随后 stdin 关闭。
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"0\n")
        .expect("写入菜单输入");
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().expect("查询菜单进程").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("菜单 60 秒内没有退出");
        }
        thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().expect("读取菜单输出");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        before == snapshot(Path::new(CONFIG_DIR)),
        "配置不一致时菜单改动了 /etc/shoes"
    );
    assert!(
        output.status.success(),
        "配置不一致时菜单直接退出：{}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert!(
        stderr.contains("检查受管配置失败") && stderr.contains("不一致"),
        "缺少不一致原因\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("9) 工具 → 8) 恢复配置"),
        "缺少恢复入口提示\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("请选择 [0-10]: "),
        "没有进入主菜单\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("已退出。"),
        "主菜单没有处理退出\nstdout:\n{stdout}"
    );
}
