//! 只读 CLI 回归，不联网、不绑定端口、不依赖 shoes。
use std::{process::Stdio, time::Duration};
use tokio::process::Command;

#[tokio::test]
async fn nonterminal_scan_without_yes_exits_without_reading_stdin() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ping-rust"))
        .args(["sni", "scan"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    // wait_with_output 会关闭 child.stdin；取出并保留管道才能检测错误的阻塞读取。
    let _open_stdin = child.stdin.take().unwrap();
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("非终端无 --yes 时不得等待输入")
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--yes"));
    assert!(stderr.contains("云端扫描可能导致 VPS 被标记"));
    assert!(output.stdout.is_empty());
}

#[tokio::test]
async fn csv_check_reports_skipped_candidates_without_touching_input() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("out.csv");
    let original = b"IP,CERT,ISSUER,ORIGIN\n203.0.113.2,*.example.com,\"Example, CA\",\n";
    std::fs::write(&path, original).unwrap();
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(env!("CARGO_BIN_EXE_ping-rust"))
            .args(["sni", "check", "--csv"])
            .arg(&path)
            .args(["--subnet", "203.0.113.0/24"])
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for column in [
        "域名",
        "来源",
        "握手耗时",
        "TLS1.3/h2",
        "跳转",
        "Cloudflare",
        "shoes 预检",
        "结论",
        "说明",
    ] {
        assert!(stdout.contains(column), "缺少表格列：{column}");
    }
    assert!(stdout.contains("通配符"));
    assert!(stdout.contains("未检测"));
    assert!(stdout.contains("每条代理连接都会对它握手一次"));
    assert!(stdout.contains("选之前先在浏览器打开"));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
