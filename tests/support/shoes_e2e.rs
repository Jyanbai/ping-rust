//! 需要 shoes 二进制的测试共用的路径读取。
//!
//! 同一份源码通过 `#[path]` 编进主程序的单元测试（`src/main.rs`）和 `tests/`
//! 下的集成测试，所以只用标准库。规则：
//!
//! - 变量已设置：路径必须是存在的文件，否则 panic，不会悄悄跳过；
//!   在 stderr 打印 `RUNNING(e2e): <测试名>：<变量>=<路径>`。
//! - 变量缺失且 `PING_RUST_REQUIRE_E2E=1`：panic，报出缺了哪个变量。
//!   CI 里提供了 shoes 的步骤都设置它。
//! - 变量缺失且未要求：在 stderr 打印 `SKIPPED(e2e): <测试名>：<原因>`，
//!   调用方跳过需要 shoes 的部分。报告测试结果时这些条目算"未运行"，不算"通过"。
//!
//! 这两行直接写进程的 stderr，不经过 libtest 的输出捕获，
//! 所以 `cargo test` 不加 `--nocapture` 也能看到。

// 每个测试二进制只用到其中一部分。
#![allow(dead_code)]

use std::{ffi::OsString, io::Write, path::PathBuf};

/// 设为 `1` 时，缺少 shoes 变量的测试直接失败，不允许跳过。
pub const REQUIRE_E2E: &str = "PING_RUST_REQUIRE_E2E";
/// 单元测试使用的 shoes 路径。
pub const TEST_SHOES: &str = "PING_RUST_TEST_SHOES";
/// 端到端流量和 dry-run 测试使用的 shoes 路径。
pub const SHOES_E2E_BIN: &str = "PING_RUST_SHOES_E2E_BIN";

/// 读取环境变量的方式；单元测试传入固定的值，不修改进程环境。
pub type Lookup<'a> = &'a dyn Fn(&str) -> Option<OsString>;

fn environment(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

/// 依次读取 `variables`，返回第一个已设置的 shoes 路径。
/// 返回 `None` 时调用方跳过需要 shoes 的部分（通常直接 `return`）。
pub fn shoes_binary(test: &str, variables: &[&str]) -> Option<PathBuf> {
    shoes_binary_with(test, variables, &environment)
}

/// 给变量缺失时原本就回退到已安装路径的测试使用：保持回退，不跳过；
/// `PING_RUST_REQUIRE_E2E=1` 时不允许回退。
pub fn shoes_binary_or(test: &str, variables: &[&str], fallback: &str) -> PathBuf {
    shoes_binary_or_with(test, variables, fallback, &environment)
}

/// 给通过 `--ignored` 显式运行的测试使用：变量缺失时总是失败。
pub fn required_shoes_binary(test: &str, variables: &[&str]) -> PathBuf {
    configured(test, variables, &environment)
        .unwrap_or_else(|| panic!("{test}：没有设置 {}", missing(variables)))
}

pub fn shoes_binary_with(test: &str, variables: &[&str], lookup: Lookup<'_>) -> Option<PathBuf> {
    if let Some(path) = configured(test, variables, lookup) {
        return Some(path);
    }
    if required(lookup) {
        panic!("{}", required_message(test, variables));
    }
    report(&skip_message(test, variables));
    None
}

pub fn shoes_binary_or_with(
    test: &str,
    variables: &[&str],
    fallback: &str,
    lookup: Lookup<'_>,
) -> PathBuf {
    if let Some(path) = configured(test, variables, lookup) {
        return path;
    }
    if required(lookup) {
        panic!("{}", required_message(test, variables));
    }
    PathBuf::from(fallback)
}

pub fn skip_message(test: &str, variables: &[&str]) -> String {
    format!(
        "SKIPPED(e2e): {test}：未设置 {}，需要 shoes 的部分未运行",
        missing(variables)
    )
}

fn required_message(test: &str, variables: &[&str]) -> String {
    format!(
        "{test}：{REQUIRE_E2E}=1，但没有设置 {}，需要 shoes 的测试不允许跳过",
        missing(variables)
    )
}

fn configured(test: &str, variables: &[&str], lookup: Lookup<'_>) -> Option<PathBuf> {
    let (variable, value) = variables
        .iter()
        .find_map(|&variable| lookup(variable).map(|value| (variable, value)))?;
    let path = PathBuf::from(value);
    assert!(
        path.is_file(),
        "{test}：{variable}={path:?} 不是存在的文件，请指向固定版本的 shoes"
    );
    report(&format!("RUNNING(e2e): {test}：{variable}={}", path.display()));
    Some(path)
}

fn required(lookup: Lookup<'_>) -> bool {
    lookup(REQUIRE_E2E).is_some_and(|value| value == "1")
}

fn missing(variables: &[&str]) -> String {
    variables.join(" 或 ")
}

/// 整行一次写入进程 stderr：绕过 libtest 对 `eprintln!` 的捕获，并行测试时也不会和别的行交错。
fn report(line: &str) {
    let _ = std::io::stderr().write_all(format!("{line}\n").as_bytes());
}
