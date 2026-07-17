use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tar::Archive;
use tokio::process::Command;

use crate::utils;

const LATEST_RELEASE_API: &str = "https://api.github.com/repos/cfal/shoes/releases/latest";
const MAX_BINARY_SIZE: u64 = 128 * 1024 * 1024;
const LOW_MEMORY_THRESHOLD_KIB: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum InstallMethod {
    /// 下载 GitHub Release 预编译文件
    Release,
    /// 执行 cargo install shoes
    Cargo,
}

#[derive(Debug)]
pub struct InstallReport {
    pub version: String,
    pub source: String,
    pub destination: PathBuf,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}

pub async fn install(method: InstallMethod, force: bool) -> Result<InstallReport> {
    utils::require_linux_root()?;
    match method {
        InstallMethod::Release => install_release(Path::new(utils::SHOES_BIN)).await,
        InstallMethod::Cargo => install_cargo(force).await,
    }
}

async fn install_release(destination: &Path) -> Result<InstallReport> {
    let client = Client::builder()
        .user_agent(concat!("ping-rust/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("创建 HTTP 客户端失败")?;

    let release = client
        .get(LATEST_RELEASE_API)
        .send()
        .await
        .context("请求 shoes 最新 Release 失败")?
        .error_for_status()
        .context("GitHub Release API 返回错误")?
        .json::<GithubRelease>()
        .await
        .context("解析 GitHub Release 信息失败")?;

    let mut failures = Vec::new();
    for target in release_targets()? {
        let expected_name = format!("shoes-{target}.tar.gz");
        let Some(asset) = release
            .assets
            .iter()
            .find(|asset| asset.name == expected_name)
        else {
            failures.push(format!("{target}: Release 中缺少 {expected_name}"));
            continue;
        };
        match install_release_asset(&client, asset, destination).await {
            Ok(()) => {
                return Ok(InstallReport {
                    version: release.tag_name,
                    source: format!("GitHub Release ({})", asset.name),
                    destination: destination.to_path_buf(),
                });
            }
            Err(error) => failures.push(format!("{target}: {error:#}")),
        }
    }

    bail!(
        "Release {} 的候选资产均无法安全安装：\n- {}",
        release.tag_name,
        failures.join("\n- ")
    )
}

async fn install_release_asset(
    client: &Client,
    asset: &ReleaseAsset,
    destination: &Path,
) -> Result<()> {
    let expected_digest = asset
        .digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
        .context("Release 资产未提供 SHA-256 digest，已拒绝未经校验的安装")?;
    let work = tempfile::tempdir().context("创建临时目录失败")?;
    let archive_path = work.path().join(&asset.name);
    let actual_digest = download(client, asset, &archive_path).await?;
    if !actual_digest.eq_ignore_ascii_case(expected_digest) {
        bail!("SHA-256 校验失败：期望 {expected_digest}，实际 {actual_digest}；文件未安装");
    }
    let extracted = extract_shoes(&archive_path, work.path())?;
    set_executable(&extracted)?;
    binary_health(&extracted).await?;
    utils::atomic_copy(&extracted, destination, 0o755)
}

async fn install_cargo(force: bool) -> Result<InstallReport> {
    let cargo = utils::command_path("cargo").context(
        "无法找到 cargo；请安装 Rust toolchain，或确认 cargo 与 ping-rust 位于同一目录/已加入 PATH",
    )?;
    let mut command = Command::new(cargo);
    command.args(["install", "shoes", "--locked", "--root", "/usr/local"]);
    if is_low_memory_linux() {
        eprintln!("检测到系统内存低于 1 GiB：cargo 源码安装将使用单任务并关闭 LTO，避免严重换页。");
        command
            .env("CARGO_BUILD_JOBS", "1")
            .env("CARGO_PROFILE_RELEASE_LTO", "false");
    }
    if force || Path::new(utils::SHOES_BIN).exists() {
        command.arg("--force");
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = command
        .status()
        .await
        .context("无法执行 cargo；请检查 Rust toolchain 安装")?;
    if !status.success() {
        bail!("cargo install shoes 执行失败（退出码：{status}）");
    }

    let version = installed_version()
        .await
        .unwrap_or_else(|_| "unknown".to_owned());
    Ok(InstallReport {
        version,
        source: "crates.io (cargo install)".to_owned(),
        destination: PathBuf::from(utils::SHOES_BIN),
    })
}

fn is_low_memory_linux() -> bool {
    cfg!(target_os = "linux")
        && fs::read_to_string("/proc/meminfo")
            .ok()
            .is_some_and(|meminfo| mem_total_below_threshold(&meminfo))
}

fn mem_total_below_threshold(meminfo: &str) -> bool {
    meminfo
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix("MemTotal:")?;
            value.split_whitespace().next()?.parse::<u64>().ok()
        })
        .is_some_and(|kib| kib < LOW_MEMORY_THRESHOLD_KIB)
}

async fn download(client: &Client, asset: &ReleaseAsset, destination: &Path) -> Result<String> {
    let response = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .with_context(|| format!("下载 {} 失败", asset.name))?
        .error_for_status()
        .with_context(|| format!("下载 {} 时服务器返回错误", asset.name))?;

    let total = response.content_length().unwrap_or(asset.size);
    let progress = ProgressBar::new(total);
    progress.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{bar:36.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        )?
        .progress_chars("=>-"),
    );
    progress.set_message(format!("下载 {}", asset.name));

    let mut output = File::create(destination)
        .with_context(|| format!("无法创建临时文件 {}", destination.display()))?;
    let mut hasher = Sha256::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("下载流中断")?;
        output.write_all(&chunk).context("写入下载文件失败")?;
        hasher.update(&chunk);
        progress.inc(chunk.len() as u64);
    }
    output.sync_all().context("同步下载文件失败")?;
    progress.finish_with_message("下载完成并已校验");

    Ok(hex::encode(hasher.finalize()))
}

fn extract_shoes(archive_path: &Path, work_dir: &Path) -> Result<PathBuf> {
    let archive_file = File::open(archive_path).context("打开下载归档失败")?;
    let decoder = GzDecoder::new(archive_file);
    let mut archive = Archive::new(decoder);
    let output = work_dir.join("shoes.extracted");

    for entry in archive.entries().context("读取 tar.gz 归档失败")? {
        let mut entry = entry.context("读取归档条目失败")?;
        let path = entry.path().context("归档包含无效路径")?;
        if path.file_name() == Some(OsStr::new("shoes")) && entry.header().entry_type().is_file() {
            if entry.size() > MAX_BINARY_SIZE {
                bail!("Release 中的 shoes 文件异常大（{} bytes）", entry.size());
            }
            let mut file = File::create(&output).context("创建解压文件失败")?;
            std::io::copy(&mut entry, &mut file).context("解压 shoes 失败")?;
            file.sync_all().context("同步解压文件失败")?;
            return Ok(output);
        }
    }

    bail!("Release 归档中未找到 shoes 二进制文件")
}

fn release_targets() -> Result<Vec<&'static str>> {
    release_targets_for(std::env::consts::OS, std::env::consts::ARCH, is_musl())
}

fn release_targets_for(os: &str, arch: &str, musl: bool) -> Result<Vec<&'static str>> {
    if os != "linux" {
        bail!("预编译安装仅支持 Linux；当前系统为 {}", os);
    }

    match (arch, musl) {
        ("x86_64", true) => Ok(vec!["x86_64-unknown-linux-musl"]),
        ("x86_64", false) => Ok(vec![
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
        ]),
        ("aarch64", true) => Ok(vec!["aarch64-unknown-linux-musl"]),
        ("aarch64", false) => Ok(vec![
            "aarch64-unknown-linux-gnu",
            "aarch64-unknown-linux-musl",
        ]),
        (arch, _) => bail!("暂不支持架构 {arch}；可尝试 --method cargo"),
    }
}

fn is_musl() -> bool {
    if Path::new("/etc/alpine-release").exists() {
        return true;
    }
    std::process::Command::new("ldd")
        .arg("--version")
        .output()
        .map(|output| {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            text.to_ascii_lowercase().contains("musl")
        })
        .unwrap_or(false)
}

pub async fn installed_version() -> Result<String> {
    binary_health(Path::new(utils::SHOES_BIN)).await?;
    Ok("shoes（CLI 未提供版本参数）".to_owned())
}

async fn binary_health(binary: &Path) -> Result<()> {
    let output = Command::new(binary)
        .arg("generate-reality-keypair")
        .output()
        .await
        .with_context(|| format!("无法执行 {} 健康检查", binary.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "{} 健康检查失败（{}）：{}{}",
            binary.display(),
            output.status,
            stderr.trim(),
            stdout.trim()
        );
    }
    if output.stdout.is_empty() {
        bail!("{} 健康检查未返回 Reality 密钥", binary.display());
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("设置 {} 可执行权限失败", path.display()))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn uninstall_binary() -> Result<bool> {
    utils::require_linux_root()?;
    let path = Path::new(utils::SHOES_BIN);
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(path).context("删除 shoes 二进制失败")?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn extracts_binary_from_nested_archive() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("test.tar.gz");
        {
            let file = File::create(&archive_path).unwrap();
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut tar = tar::Builder::new(encoder);
            let bytes = b"shoes-binary";
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tar.append_data(&mut header, "release/shoes", &bytes[..])
                .unwrap();
            tar.finish().unwrap();
        }
        let extracted = extract_shoes(&archive_path, dir.path()).unwrap();
        let mut bytes = Vec::new();
        File::open(extracted)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"shoes-binary");
    }

    #[test]
    fn glibc_targets_fall_back_to_musl() {
        assert_eq!(
            release_targets_for("linux", "x86_64", false).unwrap(),
            vec!["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"]
        );
        assert_eq!(
            release_targets_for("linux", "aarch64", false).unwrap(),
            vec!["aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl"]
        );
    }

    #[test]
    fn musl_hosts_only_try_musl_asset() {
        assert_eq!(
            release_targets_for("linux", "x86_64", true).unwrap(),
            vec!["x86_64-unknown-linux-musl"]
        );
    }

    #[test]
    fn detects_low_memory_from_linux_meminfo() {
        assert!(mem_total_below_threshold("MemTotal:         413696 kB\n"));
        assert!(!mem_total_below_threshold("MemTotal:        2097152 kB\n"));
        assert!(!mem_total_below_threshold("SwapTotal:       2097152 kB\n"));
    }
}
