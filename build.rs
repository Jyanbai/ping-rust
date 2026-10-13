use std::process::Command;

fn main() {
    // 优先使用 CI 注入的 commit；否则尝试 git；均不可用（例如 crates.io 源码包）时回退为 unknown。
    println!("cargo:rerun-if-env-changed=PING_RUST_GIT_COMMIT");
    let from_env = std::env::var("PING_RUST_GIT_COMMIT")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| is_commit(value));
    let commit = from_env
        .or_else(git_commit)
        .unwrap_or_else(|| "unknown".to_owned());
    if std::path::Path::new(".git/HEAD").exists() {
        println!("cargo:rerun-if-changed=.git/HEAD");
        println!("cargo:rerun-if-changed=.git/refs");
    }
    println!("cargo:rustc-env=PING_RUST_GIT_COMMIT={commit}");
}

fn git_commit() -> Option<String> {
    if !std::path::Path::new(".git").exists() {
        return None;
    }
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    is_commit(&commit).then_some(commit)
}

fn is_commit(value: &str) -> bool {
    value.len() >= 7 && value.len() <= 40 && value.chars().all(|c| c.is_ascii_hexdigit())
}
