//! 可选的 SNI 检测与推荐。检测路径不写受管配置。
use anyhow::{bail, Context, Result};
use clap::{Subcommand, ValueEnum};
use reqwest::{header::HeaderMap, StatusCode};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

mod candidates;
mod preflight;
mod scan;
mod temporary;
use candidates::parse_csv;
#[cfg(test)]
use candidates::scan_domain;
pub(crate) use candidates::Subnet;
pub(crate) use temporary::cleanup_on_interrupt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ValueEnum)]
pub(crate) enum Mode {
    Reality,
    ShadowTls,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// 只输出检测结果；省略域名时检测默认名单和已有节点的 SNI
    Check {
        domains: Vec<String>,
        /// 导入自己电脑上的 RealiTLScanner CSV，需同时指定扫描网段
        #[arg(long, requires = "subnet")]
        csv: Option<PathBuf>,
        #[arg(long, requires = "csv")]
        subnet: Option<Subnet>,
        /// 指定 shoes 本机预检协议；默认使用 Reality，已有 ShadowTLS SNI 用 ShadowTLS
        #[arg(long, value_enum)]
        protocol: Option<Mode>,
    },
    /// 在 VPS 的 IPv4 /24 扫描（可能违反服务商条款，推荐本地扫描）
    Scan {
        /// 明确接受扫描风险；非终端调用必须指定
        #[arg(long)]
        yes: bool,
        #[arg(long, value_enum, default_value = "reality")]
        protocol: Mode,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    domain: String,
    pub(crate) source: String,
    mode: Mode,
    subnet: Option<Subnet>,
    skip: Option<String>,
}

impl Candidate {
    fn new(domain: &str, source: &str, mode: Mode) -> Self {
        Self {
            domain: domain.to_ascii_lowercase(),
            source: source.to_owned(),
            mode,
            subnet: None,
            skip: None,
        }
    }
}

pub(crate) fn defaults(mode: Option<Mode>) -> Result<Vec<Candidate>> {
    let mut candidates: Vec<_> = crate::config::reality_server_names()
        .into_iter()
        .map(|d| Candidate::new(d, "默认名单", mode.unwrap_or(Mode::Reality)))
        .collect();
    if Path::new(crate::utils::STATE_FILE).exists() {
        for profile in crate::config::load_state()?.profiles {
            let domain = profile.server_name();
            if domain == "-" {
                continue;
            }
            let shadowtls = matches!(
                profile.credentials,
                crate::config::Credentials::Shadowsocks {
                    shadowtls: Some(_),
                    ..
                }
            );
            candidates.push(Candidate::new(
                domain,
                if shadowtls {
                    "现有 ShadowTLS"
                } else {
                    "现有节点"
                },
                mode.unwrap_or(if shadowtls {
                    Mode::ShadowTls
                } else {
                    Mode::Reality
                }),
            ));
        }
    }
    Ok(candidates)
}

pub(crate) fn manual(domains: &str, mode: Mode) -> Result<Vec<Candidate>> {
    domains
        .split_whitespace()
        .map(|domain| {
            crate::config::validate_server_name(domain)?;
            Ok(Candidate::new(domain, "用户输入", mode))
        })
        .collect()
}

pub(crate) fn import(path: &Path, subnet: Subnet, mode: Mode) -> Result<Vec<Candidate>> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)
        .context("无法打开 CSV，请检查上传路径和文件权限")?
        .take(16 * 1024 * 1024 + 1)
        .read_to_string(&mut text)
        .context("读取 CSV 失败，请使用 UTF-8 编码")?;
    parse_csv(&text, subnet, mode, false)
}

#[derive(Debug)]
pub(crate) struct Report {
    candidate: Candidate,
    elapsed: Option<Duration>,
    tls: &'static str,
    redirect: String,
    cloudflare: &'static str,
    shoes: &'static str,
    passed: bool,
    detail: String,
}

impl Report {
    fn new(candidate: Candidate) -> Self {
        Self {
            candidate,
            elapsed: None,
            tls: "未检测",
            redirect: "未检测".to_owned(),
            cloudflare: "未检测",
            shoes: "未检测",
            passed: false,
            detail: String::new(),
        }
    }
    #[cfg(test)]
    fn test(domain: &str, millis: Option<u64>, passed: bool) -> Self {
        let mut result = Self::new(Candidate::new(domain, "测试", Mode::Reality));
        result.elapsed = millis.map(Duration::from_millis);
        result.passed = passed;
        result
    }
}

fn inspect_https(domain: &str, status: StatusCode, headers: &HeaderMap) -> (String, bool) {
    let cloudflare = headers.contains_key("cf-ray")
        || headers.get_all("server").iter().any(|v| {
            v.to_str()
                .is_ok_and(|v| v.trim().eq_ignore_ascii_case("cloudflare"))
        });
    let redirect = if status.is_redirection() {
        match headers.get("location") {
            Some(value) => match value.to_str().ok().and_then(|v| {
                reqwest::Url::parse(&format!("https://{domain}/"))
                    .ok()?
                    .join(v)
                    .ok()
            }) {
                Some(url)
                    if url
                        .host_str()
                        .is_some_and(|h| h.eq_ignore_ascii_case(domain)) =>
                {
                    "同主机"
                }
                Some(_) => "跨主机（失败）",
                None => "跳转地址无效（失败）",
            },
            None if status == StatusCode::NOT_MODIFIED => "无",
            None => "跳转缺少 Location（失败）",
        }
    } else {
        "无"
    };
    (redirect.to_owned(), cloudflare)
}

async fn check_one(report: &mut Report) -> Result<()> {
    if let Some(reason) = &report.candidate.skip {
        bail!("{reason}");
    }
    let domain = &report.candidate.domain;
    crate::config::validate_server_name(domain)?;
    let probe = crate::sni_probe::check(domain).await;
    match probe.outcome {
        Ok(elapsed) => {
            report.elapsed = Some(elapsed);
            report.tls = "是/是";
        }
        Err(reason) => {
            report.tls = "失败";
            bail!("{reason}；请更换候选或检查 VPS 网络");
        }
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let response = client
        .get(format!("https://{domain}/"))
        .send()
        .await
        .context("HTTPS GET 失败或超过 5 秒，请检查 VPS 出站网络")?;
    let (redirect, cloudflare) = inspect_https(domain, response.status(), response.headers());
    // 不读取响应体，离开本阶段就释放响应。
    drop(response);
    report.redirect = redirect;
    report.cloudflare = if cloudflare { "是" } else { "否" };
    if report.redirect.contains("失败") {
        bail!("HTTPS {}，请更换候选", report.redirect);
    }
    if cloudflare {
        bail!("目标使用 Cloudflare，请选择其他站点");
    }
    report.shoes = "失败";
    preflight::run(domain, report.candidate.mode).await?;
    report.shoes = match report.candidate.mode {
        Mode::Reality => "Reality 通过",
        Mode::ShadowTls => "ShadowTLS 通过",
    };
    if let Some(subnet) = report.candidate.subnet {
        let addresses = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((domain.as_str(), 443)),
        )
        .await
        .context("扫描域名 DNS 过滤超时，请检查 DNS")?
        .context("扫描域名 DNS 解析失败，请检查 DNS")?;
        if !addresses
            .into_iter()
            .any(|address| subnet.contains(address.ip()))
        {
            bail!("域名 DNS 结果不在扫描的 /24 内，邻居机器平时并不服务此域名，跳过");
        }
    }
    report.passed = true;
    report.detail = "全部检测通过；仅作推荐，请自行选择".to_owned();
    Ok(())
}

fn sort_reports(reports: &mut [Report]) {
    reports.sort_by_key(|r| (!r.passed, r.elapsed.unwrap_or(Duration::MAX)));
}

pub(crate) async fn check(candidates: Vec<Candidate>) -> Vec<Report> {
    let mut reports = Vec::new();
    let mut unique: Vec<Candidate> = Vec::new();
    let mut seen = HashMap::new();
    for candidate in candidates {
        // 不合并扫描与非扫描结果，避免丢失 /24 过滤与风险提示。
        let key = (
            candidate.domain.clone(),
            candidate.mode,
            candidate.subnet.map(|s| s.0),
            candidate.skip.clone(),
        );
        if let Some(&index) = seen.get(&key) {
            let prior: &mut Candidate = &mut unique[index];
            if !prior
                .source
                .split('、')
                .any(|source| source == candidate.source)
            {
                prior.source.push('、');
                prior.source.push_str(&candidate.source);
            }
        } else {
            seen.insert(key, unique.len());
            unique.push(candidate);
        }
    }
    for candidate in unique {
        eprintln!("正在检测 {}（{}）…", candidate.domain, candidate.source);
        let mut report = Report::new(candidate);
        if let Err(error) = check_one(&mut report).await {
            report.detail = format!("{error:#}");
        }
        reports.push(report);
    }
    sort_reports(&mut reports);
    reports
}

const SCAN_RISK: &str = "站点规模未知，每条代理连接都会对它握手一次；该站宕机或限流，节点就连不上。扫描结果里常有别人的代理节点，选之前先在浏览器打开，确认是正常网站。";

pub(crate) fn print_reports(reports: &[Report]) {
    println!("编号\t域名\t来源\t握手耗时\tTLS1.3/h2\t跳转\tCloudflare\tshoes 预检\t结论\t说明");
    for (index, r) in reports.iter().enumerate() {
        let elapsed = r
            .elapsed
            .map(|d| format!("{} ms", d.as_millis()))
            .unwrap_or_else(|| "—".to_owned());
        let detail: String = r
            .detail
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}{}",
            index + 1,
            r.candidate.domain,
            r.candidate.source,
            elapsed,
            r.tls,
            r.redirect,
            r.cloudflare,
            r.shoes,
            if r.passed { "通过" } else { "不推荐" },
            detail,
            if r.candidate.subnet.is_some() {
                SCAN_RISK
            } else {
                ""
            }
        );
    }
}

pub(crate) fn selected(reports: &[Report], index: usize) -> Result<String> {
    let report = reports.get(index).context("无效编号")?;
    if !report.passed {
        bail!("该候选未通过全部检测，请选择通过的条目");
    }
    Ok(report.candidate.domain.clone())
}

pub(crate) async fn run(command: Command) -> Result<()> {
    let candidates = match command {
        Command::Check {
            domains,
            csv,
            subnet,
            protocol,
        } => {
            let mut candidates = if domains.is_empty() && csv.is_none() {
                defaults(protocol)?
            } else {
                manual(&domains.join(" "), protocol.unwrap_or(Mode::Reality))?
            };
            if let Some(path) = csv {
                candidates.extend(import(
                    &path,
                    subnet.context("导入 CSV 必须指定 --subnet IPv4/24")?,
                    protocol.unwrap_or(Mode::Reality),
                )?);
            }
            candidates
        }
        Command::Scan { yes, protocol } => scan(yes, protocol).await?,
    };
    print_reports(&check(candidates).await);
    Ok(())
}

pub(crate) async fn scan(yes: bool, mode: Mode) -> Result<Vec<Candidate>> {
    scan::run(yes, mode).await
}

pub(crate) async fn local_scanner_command() -> Result<String> {
    let ip = scan::vps_ipv4().await?;
    Ok(format!(
        "RealiTLScanner -addr {ip}/24 -port 443 -thread 5 -timeout 5 -out out.csv"
    ))
}

#[cfg(test)]
mod tests;
