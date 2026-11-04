//! 终端里首次进入菜单时，自动部署前要先确认，选择跳过后不做任何部署尝试（回归）：
//! cargo test --test menu_bootstrap_confirm
//!
//! 部署失败后 state 不存在，每次启动都会重试默认部署；连不上 GitHub 的机器每次都要
//! 先等几分钟。确认放在任何网络操作之前，输入 n 立即进入主菜单。
//!
//! 只在 Linux、非 root、本机没有 /etc/shoes、且有 util-linux `script`（提供伪终端）时运行。
//! HTTPS 代理指向本机关闭的端口，万一确认没有生效，部署也会离线失败，不会改动本机。
#![cfg(target_os = "linux")]

use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CLOSED_PROXY: &str = "http://127.0.0.1:9";

fn should_skip() -> Option<&'static str> {
    let uid = Command::new("id").arg("-u").output().expect("运行 id -u");
    if String::from_utf8_lossy(&uid.stdout).trim() == "0" {
        return Some("root 下首次默认部署可能改动本机，本回归只在非 root 下运行");
    }
    if Path::new("/etc/shoes").exists() {
        return Some("本机已有 /etc/shoes，不会触发首次默认部署");
    }
    let script = Command::new("script")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !script.is_ok_and(|status| status.success()) {
        return Some("没有 util-linux script，无法提供伪终端");
    }
    None
}

/// 在伪终端里运行菜单，把 `input` 逐行写入，返回退出是否成功和终端输出。
fn run_menu_in_pty(input: &[&str]) -> (bool, String) {
    let mut child = Command::new("script")
        .args(["--quiet", "--return", "--command"])
        .arg(env!("CARGO_BIN_EXE_ping-rust"))
        .arg("/dev/null")
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
        .expect("通过 script 启动 ping-rust 菜单");
    let mut stdin = child.stdin.take().unwrap();
    for line in input {
        // 每行之间稍等，确保菜单已经在读取下一行。
        thread::sleep(Duration::from_millis(500));
        stdin.write_all(line.as_bytes()).expect("写入菜单输入");
        stdin.write_all(b"\n").expect("写入菜单输入");
        stdin.flush().expect("写入菜单输入");
    }

    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("查询菜单进程").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("读取菜单输出");
            panic!(
                "菜单 30 秒内没有退出\n{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
    drop(stdin);
    let output = child.wait_with_output().expect("读取菜单输出");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
}

#[test]
fn declining_first_deployment_skips_every_network_step() {
    if let Some(reason) = should_skip() {
        eprintln!("跳过：{reason}");
        return;
    }
    let started = Instant::now();
    let (success, output) = run_menu_in_pty(&["n", "0"]);

    assert!(success, "菜单没有正常退出\n{output}");
    assert!(
        output.contains("首次安装：自动部署 VLESS-REALITY"),
        "缺少首次安装标题\n{output}"
    );
    assert!(
        output.contains("现在部署？") && output.contains("[Y/n]"),
        "部署前没有确认\n{output}"
    );
    assert!(
        !output.contains("正在自动安装 shoes"),
        "选择跳过后仍开始部署\n{output}"
    );
    assert!(
        !output.contains("自动检测公网地址失败"),
        "选择跳过后仍探测公网地址\n{output}"
    );
    assert!(output.contains("已跳过默认部署"), "缺少跳过提示\n{output}");
    assert!(
        output.contains("请选择 [0-10]: "),
        "没有进入主菜单\n{output}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "跳过部署后菜单启动仍然很慢：{:?}",
        started.elapsed()
    );
}

#[test]
fn accepting_first_deployment_with_enter_keeps_the_default_flow() {
    if let Some(reason) = should_skip() {
        eprintln!("跳过：{reason}");
        return;
    }
    // 直接回车 = 部署。离线环境里公网地址探测失败后会询问地址，回车跳过，再输入 0 退出。
    let (success, output) = run_menu_in_pty(&["", "", "0"]);

    assert!(success, "菜单没有正常退出\n{output}");
    assert!(output.contains("现在部署？"), "部署前没有确认\n{output}");
    assert!(
        output.contains("正在自动安装 shoes"),
        "回车后没有开始默认部署\n{output}"
    );
    assert!(
        output.contains("请选择 [0-10]: "),
        "没有进入主菜单\n{output}"
    );
}
