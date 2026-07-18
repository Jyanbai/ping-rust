use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tar::Archive;
use tokio::process::Command;

use crate::utils;

const RELEASES_API: &str = "https://api.github.com/repos/Jyanbai/ping-rust/releases";
const MAX_ARCHIVE_SIZE: u64 = 64 * 1024 * 1024;
const MAX_CHECKSUM_SIZE: u64 = 64 * 1024;
const MAX_BINARY_SIZE: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum UpdateReport {
    Current {
        current: Version,
        available: Version,
    },
    Updated {
        from: Version,
        to: Version,
        destination: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}

pub async fn update(requested: Option<&str>, force: bool) -> Result<UpdateReport> {
    utils::require_linux()?;

    let target = target_for(std::env::consts::OS, std::env::consts::ARCH)?;
    let requested = requested.map(normalize_tag).transpose()?;
    let client = Client::builder()
        .user_agent(concat!("ping-rust/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(300))
        .build()
        .context("创建自更新 HTTP 客户端失败")?;
    let release = fetch_release(&client, requested.as_ref().map(|(tag, _)| tag)).await?;
    let available = release_version(&release.tag_name)?;
    if let Some((tag, expected)) = &requested {
        if &available != expected {
            bail!("GitHub 为 {tag} 返回了不一致的版本 {}", release.tag_name);
        }
    }

    let current =
        Version::parse(env!("CARGO_PKG_VERSION")).context("当前 ping-rust 包含无效版本号")?;
    if !force
        && if requested.is_some() {
            available == current
        } else {
            available <= current
        }
    {
        return Ok(UpdateReport::Current { current, available });
    }

    let archive_name = format!("ping-rust-{target}.tar.gz");
    let archive_asset = unique_asset(&release.assets, &archive_name)?;
    let checksum_asset = unique_asset(&release.assets, "SHA256SUMS")?;
    let work = tempfile::tempdir().context("创建自更新临时目录失败")?;

    let checksum_path = work.path().join("SHA256SUMS");
    let checksum_digest = download_asset(
        &client,
        checksum_asset,
        &checksum_path,
        MAX_CHECKSUM_SIZE,
        false,
    )
    .await?;
    verify_api_digest(checksum_asset, &checksum_digest)?;
    let checksums = fs::read_to_string(&checksum_path).context("SHA256SUMS 不是有效 UTF-8 文本")?;
    let expected_digest = checksum_for(&checksums, &archive_name)?;

    let archive_path = work.path().join(&archive_name);
    let actual_digest = download_asset(
        &client,
        archive_asset,
        &archive_path,
        MAX_ARCHIVE_SIZE,
        true,
    )
    .await?;
    verify_api_digest(archive_asset, &actual_digest)?;
    if !actual_digest.eq_ignore_ascii_case(&expected_digest) {
        bail!(
            "{} SHA-256 校验失败：期望 {}，实际 {}；当前程序未修改",
            archive_name,
            expected_digest,
            actual_digest
        );
    }

    let extracted = extract_binary(&archive_path, work.path())?;
    set_executable(&extracted)?;
    verify_binary_version(&extracted, &available).await?;

    let destination = std::env::current_exe().context("无法确定当前 ping-rust 路径")?;
    if !destination.is_file() {
        bail!("当前 ping-rust 路径不是普通文件：{}", destination.display());
    }
    replace_binary(&extracted, &destination, &available).await?;

    Ok(UpdateReport::Updated {
        from: current,
        to: available,
        destination,
    })
}

async fn fetch_release(client: &Client, tag: Option<&String>) -> Result<GithubRelease> {
    let url = match tag {
        Some(tag) => format!("{RELEASES_API}/tags/{tag}"),
        None => format!("{RELEASES_API}/latest"),
    };
    client
        .get(url)
        .send()
        .await
        .context("请求 ping-rust GitHub Release 失败")?
        .error_for_status()
        .context("GitHub Release API 返回错误")?
        .json::<GithubRelease>()
        .await
        .context("解析 ping-rust GitHub Release 失败")
}

fn normalize_tag(value: &str) -> Result<(String, Version)> {
    let value = value.trim();
    let version = Version::parse(value.strip_prefix('v').unwrap_or(value))
        .with_context(|| format!("版本格式无效：{value}；示例：v0.1.1"))?;
    Ok((format!("v{version}"), version))
}

fn release_version(tag: &str) -> Result<Version> {
    Version::parse(tag.strip_prefix('v').unwrap_or(tag))
        .with_context(|| format!("Release tag 不是有效语义版本：{tag}"))
}

fn target_for(os: &str, arch: &str) -> Result<&'static str> {
    if os != "linux" {
        bail!("ping-rust 自更新仅支持 Linux；当前系统为 {os}");
    }
    match arch {
        "x86_64" => Ok("x86_64-unknown-linux-musl"),
        "aarch64" => Ok("aarch64-unknown-linux-musl"),
        _ => bail!("ping-rust 自更新暂不支持架构 {arch}"),
    }
}

fn unique_asset<'a>(assets: &'a [ReleaseAsset], name: &str) -> Result<&'a ReleaseAsset> {
    let mut matches = assets.iter().filter(|asset| asset.name == name);
    let asset = matches
        .next()
        .with_context(|| format!("Release 中缺少资产 {name}"))?;
    if matches.next().is_some() {
        bail!("Release 中存在重复资产 {name}");
    }
    Ok(asset)
}

async fn download_asset(
    client: &Client,
    asset: &ReleaseAsset,
    destination: &Path,
    max_size: u64,
    show_progress: bool,
) -> Result<String> {
    if asset.size > max_size {
        bail!("{} 尺寸异常：{} bytes", asset.name, asset.size);
    }
    let url = reqwest::Url::parse(&asset.browser_download_url)
        .with_context(|| format!("{} 下载 URL 无效", asset.name))?;
    if url.scheme() != "https" || url.host_str() != Some("github.com") {
        bail!("{} 下载 URL 不是受信任的 GitHub HTTPS 地址", asset.name);
    }

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("下载 {} 失败", asset.name))?
        .error_for_status()
        .with_context(|| format!("下载 {} 时服务器返回错误", asset.name))?;
    if response
        .content_length()
        .is_some_and(|size| size > max_size)
    {
        bail!("{} HTTP 内容长度超过安全上限", asset.name);
    }

    let progress = show_progress.then(|| {
        let progress = ProgressBar::new(response.content_length().unwrap_or(asset.size));
        if let Ok(style) = ProgressStyle::with_template(
            "{spinner:.green} [{bar:36.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        ) {
            progress.set_style(style.progress_chars("=>-"));
        }
        progress.set_message(format!("下载 {}", asset.name));
        progress
    });
    let mut output = File::create(destination)
        .with_context(|| format!("创建临时文件 {} 失败", destination.display()))?;
    let mut hasher = Sha256::new();
    let mut received = 0_u64;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("GitHub Release 下载流中断")?;
        received = received
            .checked_add(chunk.len() as u64)
            .context("下载大小溢出")?;
        if received > max_size {
            bail!("{} 下载内容超过安全上限", asset.name);
        }
        output.write_all(&chunk).context("写入下载文件失败")?;
        hasher.update(&chunk);
        if let Some(progress) = &progress {
            progress.inc(chunk.len() as u64);
        }
    }
    output.sync_all().context("同步下载文件失败")?;
    if received != asset.size {
        bail!(
            "{} 下载大小不一致：Release 声明 {} bytes，实际 {} bytes",
            asset.name,
            asset.size,
            received
        );
    }
    if let Some(progress) = progress {
        progress.finish_with_message("下载完成");
    }
    Ok(hex::encode(hasher.finalize()))
}

fn verify_api_digest(asset: &ReleaseAsset, actual: &str) -> Result<()> {
    if let Some(expected) = asset
        .digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
    {
        if !actual.eq_ignore_ascii_case(expected) {
            bail!(
                "{} 与 GitHub API digest 不一致：期望 {}，实际 {}",
                asset.name,
                expected,
                actual
            );
        }
    }
    Ok(())
}

fn checksum_for(contents: &str, filename: &str) -> Result<String> {
    let mut found = None;
    for line in contents.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 2 || fields[1] != filename {
            continue;
        }
        if found.is_some() {
            bail!("SHA256SUMS 中存在重复条目 {filename}");
        }
        let digest = fields[0];
        let decoded = hex::decode(digest)
            .with_context(|| format!("SHA256SUMS 中 {filename} 的摘要不是十六进制"))?;
        if decoded.len() != 32 {
            bail!("SHA256SUMS 中 {filename} 的摘要长度无效");
        }
        found = Some(digest.to_ascii_lowercase());
    }
    found.with_context(|| format!("SHA256SUMS 中缺少 {filename}"))
}

fn extract_binary(archive_path: &Path, work_dir: &Path) -> Result<PathBuf> {
    let file = File::open(archive_path).context("打开 ping-rust 归档失败")?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    let destination = work_dir.join("ping-rust.extracted");
    let mut found = false;

    for entry in archive.entries().context("读取 ping-rust tar.gz 失败")? {
        let mut entry = entry.context("读取 ping-rust 归档条目失败")?;
        let path = entry.path().context("ping-rust 归档包含无效路径")?;
        if path.as_ref() != Path::new("ping-rust")
            || path.file_name() != Some(OsStr::new("ping-rust"))
            || !entry.header().entry_type().is_file()
        {
            bail!("ping-rust 归档只能包含根目录普通文件 ping-rust");
        }
        if found {
            bail!("ping-rust 归档包含重复二进制");
        }
        if entry.size() > MAX_BINARY_SIZE {
            bail!("ping-rust 二进制异常大（{} bytes）", entry.size());
        }
        let mut output = File::create(&destination).context("创建解压二进制失败")?;
        std::io::copy(&mut entry, &mut output).context("解压 ping-rust 失败")?;
        output.sync_all().context("同步解压二进制失败")?;
        found = true;
    }

    if !found {
        bail!("ping-rust 归档中没有二进制");
    }
    Ok(destination)
}

async fn replace_binary(source: &Path, destination: &Path, version: &Version) -> Result<()> {
    let original = fs::read(destination)
        .with_context(|| format!("备份当前程序 {} 失败", destination.display()))?;
    let original_mode = executable_mode(destination)?;
    utils::atomic_copy(source, destination, 0o755).with_context(|| {
        format!(
            "替换 {} 失败；若它位于系统目录，请使用 sudo ping-rust self-update",
            destination.display()
        )
    })?;

    if let Err(error) = verify_binary_version(destination, version).await {
        match utils::atomic_write(destination, &original, original_mode) {
            Ok(()) => bail!("新版本安装后验证失败，已恢复原程序：{error:#}"),
            Err(rollback) => {
                bail!("新版本安装后验证失败，且恢复原程序失败：验证={error:#}；恢复={rollback:#}")
            }
        }
    }
    Ok(())
}

async fn verify_binary_version(binary: &Path, version: &Version) -> Result<()> {
    let output = Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .await
        .with_context(|| format!("无法执行 {} 版本检查", binary.display()))?;
    if !output.status.success() {
        bail!(
            "{} 版本检查失败（{}）：{}",
            binary.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8(output.stdout).context("版本输出不是有效 UTF-8")?;
    let expected = format!("ping-rust {version}");
    if stdout.trim() != expected {
        bail!(
            "{} 版本不匹配：期望 {expected:?}，实际 {:?}",
            binary.display(),
            stdout.trim()
        );
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

#[cfg(unix)]
fn executable_mode(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(path)
        .with_context(|| format!("读取 {} 权限失败", path.display()))?
        .permissions()
        .mode()
        & 0o777)
}

#[cfg(not(unix))]
fn executable_mode(_path: &Path) -> Result<u32> {
    Ok(0o755)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_archive(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (name, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            archive
                .append_data(&mut header, name, &contents[..])
                .unwrap();
        }
        archive.finish().unwrap();
    }

    #[test]
    fn normalizes_requested_versions() {
        assert_eq!(
            normalize_tag("0.1.1").unwrap(),
            ("v0.1.1".to_owned(), Version::new(0, 1, 1))
        );
        assert_eq!(
            normalize_tag("v1.2.3-beta.1").unwrap(),
            (
                "v1.2.3-beta.1".to_owned(),
                Version::parse("1.2.3-beta.1").unwrap()
            )
        );
        assert!(normalize_tag("latest").is_err());
    }

    #[test]
    fn maps_supported_release_targets() {
        assert_eq!(
            target_for("linux", "x86_64").unwrap(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            target_for("linux", "aarch64").unwrap(),
            "aarch64-unknown-linux-musl"
        );
        assert!(target_for("windows", "x86_64").is_err());
        assert!(target_for("linux", "arm").is_err());
    }

    #[test]
    fn parses_exact_checksum_entry() {
        let checksum = "a".repeat(64);
        let contents = format!(
            "{}  other.tar.gz\n{}  ping-rust-x86_64-unknown-linux-musl.tar.gz\n",
            "b".repeat(64),
            checksum
        );
        assert_eq!(
            checksum_for(&contents, "ping-rust-x86_64-unknown-linux-musl.tar.gz").unwrap(),
            checksum
        );
        assert!(checksum_for(&contents, "missing.tar.gz").is_err());
    }

    #[test]
    fn rejects_duplicate_checksum_entries() {
        let digest = "a".repeat(64);
        let contents = format!("{digest}  package.tar.gz\n{digest}  package.tar.gz\n");
        assert!(checksum_for(&contents, "package.tar.gz").is_err());
    }

    #[test]
    fn extracts_strict_single_binary_archive() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("ping-rust.tar.gz");
        write_archive(&archive, &[("ping-rust", b"binary")]);
        let extracted = extract_binary(&archive, dir.path()).unwrap();
        assert_eq!(fs::read(extracted).unwrap(), b"binary");
    }

    #[test]
    fn rejects_archive_with_extra_entry() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("ping-rust.tar.gz");
        write_archive(
            &archive,
            &[("ping-rust", b"binary"), ("unexpected", b"payload")],
        );
        assert!(extract_binary(&archive, dir.path()).is_err());
    }
}
