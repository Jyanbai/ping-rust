//! 首次默认部署失败后菜单仍要可用（回归）：
//! cargo test --test menu_bootstrap_failure
//!
//! 只在 Linux、非 root、且本机没有 /etc/shoes 时运行。此时首次默认部署一定会在
//! 写任何系统文件之前失败：HTTPS 代理指向本机关闭的端口，公网地址探测离线并立即失败；
//! 即使探测成功，非 root 也过不了 shoes 安装的权限检查。
#![cfg(target_os = "linux")]

use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CLOSED_PROXY: &str = "http://127.0.0.1:9";

#[test]
fn bootstrap_failure_still_opens_main_menu() {
    let uid = Command::new("id").arg("-u").output().expect("运行 id -u");
    if String::from_utf8_lossy(&uid.stdout).trim() == "0" {
        eprintln!("跳过：root 下首次默认部署可能改动本机，本回归只在非 root 下运行");
        return;
    }
    if Path::new("/etc/shoes").exists() {
        eprintln!("跳过：本机已有 /etc/shoes，不会触发首次默认部署");
        return;
    }

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
        output.status.success(),
        "首次默认部署失败后菜单直接退出：{}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert!(
        stderr.contains("首次默认部署失败"),
        "缺少部署失败提示\nstderr:\n{stderr}"
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
