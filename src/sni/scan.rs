use super::{temporary::Temporary, Candidate, Mode, Subnet};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    io::{self, IsTerminal},
    net::Ipv4Addr,
    time::Duration,
};

const VERSION: &str = "v0.2.3";
pub(super) const AMD64_SHA256: &str =
    "a55595446de9f1c2e6c5c3cd766a7320a11115947df48f101749bb62c8055592";
const ARM64_SHA256: &str = "27bdd3e53d4391c66c8df3391d3c3fb5eb2dc356125f2fb33ac58fcaaf8f88b3";
const WARNING: &str = "警告：RealiTLScanner 作者建议在本地电脑上运行，在云端扫描可能导致 VPS 被标记；部分服务商的条款禁止扫描。推荐在自己电脑上扫描，再上传 CSV，使用“导入本地扫描 CSV”或 prs sni check --csv <路径> --subnet <IPv4/24>。";

pub(super) fn authorize(
    terminal: bool,
    yes: bool,
    confirm: impl FnOnce() -> Result<bool>,
) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !terminal {
        bail!("非终端扫描必须显式传入 --yes 接受风险；请先阅读 prs sni scan --help，推荐在自己电脑上扫描后导入 CSV");
    }
    confirm()
}

fn asset() -> Result<(&'static str, &'static str)> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok(("RealiTLScanner-linux-amd64", AMD64_SHA256)),
        ("linux", "aarch64") => Ok(("RealiTLScanner-linux-arm64", ARM64_SHA256)),
        _ => bail!("当前系统或架构不支持 VPS 扫描；请在自己电脑上运行 RealiTLScanner 后导入 CSV"),
    }
}

pub(super) fn verify_digest(bytes: &[u8], expected: &str) -> Result<()> {
    if hex::encode(Sha256::digest(bytes)) != expected {
        bail!("RealiTLScanner SHA-256 摘要不符，已拒绝运行；请检查下载来源或改用本地扫描 CSV");
    }
    Ok(())
}

pub(super) fn write_verified_binary(
    path: &std::path::Path,
    bytes: &[u8],
    expected: &str,
) -> Result<()> {
    verify_digest(bytes, expected)?;
    crate::utils::atomic_write(path, bytes, 0o700)
}

pub(super) async fn vps_ipv4() -> Result<Ipv4Addr> {
    // 使用专门的 IPv4 探测端点并绕开环境代理，避免扫描代理出口或误选 IPv6。
    let client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .build()?;
    for endpoint in ["https://api.ipify.org", "https://ipv4.icanhazip.com"] {
        let result = async {
            let text = client
                .get(endpoint)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            let ip: Ipv4Addr = text.trim().parse()?;
            if ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
            {
                bail!("探测结果不是公网 IPv4");
            }
            Ok::<_, anyhow::Error>(ip)
        }
        .await;
        if let Ok(ip) = result {
            return Ok(ip);
        }
    }
    bail!("未检测到 VPS IPv4，请检查 IPv4 出站网络；仅 IPv6 的 VPS 不支持扫描，请使用默认名单、输入域名或导入其他 IPv4 网段的 CSV")
}

pub(super) async fn run(yes: bool, mode: Mode) -> Result<Vec<Candidate>> {
    eprintln!("{WARNING}");
    if !authorize(io::stdin().is_terminal(), yes, || {
        crate::menu::input::validated_text(
            "确认在 VPS 上扫描？只有输入 y 才执行",
            Some("N"),
            false,
            |value| match value.to_ascii_lowercase().as_str() {
                "y" => Ok(true),
                "n" => Ok(false),
                _ => bail!("请输入 y 或 N"),
            },
        )
    })? {
        return Ok(Vec::new());
    }
    let (name, expected) = asset()?;
    let ip = vps_ipv4().await?;
    let subnet: Subnet = format!("{ip}/24").parse()?;
    let temporary = Temporary::new()?;
    let progress = indicatif::ProgressBar::new_spinner();
    progress.set_message("下载并校验 RealiTLScanner v0.2.3…");
    progress.enable_steady_tick(Duration::from_millis(150));
    let result = tokio::time::timeout(Duration::from_secs(300), async {
        let client = reqwest::Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()?;
        let url =
            format!("https://github.com/XTLS/RealiTLScanner/releases/download/{VERSION}/{name}");
        let mut response = client
            .get(url)
            .send()
            .await
            .context("下载 RealiTLScanner 失败，请检查 GitHub 网络连通性或改用本地扫描")?
            .error_for_status()
            .context("RealiTLScanner 下载返回错误状态，请稍后重试或导入本地 CSV")?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("下载 RealiTLScanner 中断，请重试")?
        {
            if bytes.len() + chunk.len() > 64 * 1024 * 1024 {
                bail!("RealiTLScanner 下载超过大小限制，已拒绝运行");
            }
            bytes.extend_from_slice(&chunk);
        }
        let binary = temporary.path().join(name);
        write_verified_binary(&binary, &bytes, expected)?;
        drop(bytes);
        let csv = temporary.path().join("out.csv");
        let address = format!("{ip}/24");
        progress.set_message("扫描 VPS IPv4 /24（5 线程，端口 443，整体最多 5 分钟）…");
        eprintln!("开始扫描 /24；RealiTLScanner -port 443 -thread 5 -timeout 5");
        temporary.spawn(
            &binary,
            &[
                "-addr".as_ref(),
                address.as_ref(),
                "-port".as_ref(),
                "443".as_ref(),
                "-thread".as_ref(),
                "5".as_ref(),
                "-timeout".as_ref(),
                "5".as_ref(),
                "-out".as_ref(),
                csv.as_os_str(),
            ],
        )?;
        if !temporary.wait().await?.success() {
            bail!("RealiTLScanner 执行失败，请检查 VPS 网络或改用本地扫描 CSV");
        }
        let mut candidates = super::import(&csv, subnet, mode)?;
        for candidate in &mut candidates {
            candidate.source = "VPS 扫描".to_owned();
        }
        if candidates.is_empty() {
            eprintln!("扫描没有候选，请改用默认名单或本地扫描 CSV。");
        }
        Ok(candidates)
    })
    .await
    .context("RealiTLScanner 整体超时（5 分钟），已停止临时进程；请改用本地扫描 CSV");
    progress.finish_and_clear();
    result?
}
