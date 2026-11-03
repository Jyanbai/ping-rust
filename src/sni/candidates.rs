use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use anyhow::{bail, Context, Result};

use super::{Candidate, Mode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Subnet(pub Ipv4Addr);

impl FromStr for Subnet {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (address, prefix) = value.split_once('/').context("扫描网段必须为 IPv4/24")?;
        if prefix != "24" {
            bail!("仅支持 IPv4 /24 扫描网段");
        }
        let address: Ipv4Addr = address.parse().context("扫描网段必须使用 IPv4；IPv6 不支持扫描，请使用默认名单、手动域名或导入其他 IPv4 网段的 CSV")?;
        let mut octets = address.octets();
        octets[3] = 0;
        Ok(Self(Ipv4Addr::from(octets)))
    }
}

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/24", self.0)
    }
}

impl Subnet {
    pub(super) fn contains(self, address: IpAddr) -> bool {
        matches!(address, IpAddr::V4(ip) if ip.octets()[..3] == self.0.octets()[..3])
    }
}

fn concrete_domain(value: &str) -> Result<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    crate::config::validate_server_name(&domain)?;
    if domain.parse::<IpAddr>().is_ok() || !domain.contains('.') || domain.contains('*') {
        bail!("需要具体主机名，不能使用 IP 或通配符");
    }
    Ok(domain)
}

pub(super) fn scan_domain(certificate: &str, origin: &str) -> Result<String> {
    if certificate.trim().starts_with("*.") {
        return concrete_domain(origin).context("通配符证书没有具体 ORIGIN 主机名，跳过");
    }
    concrete_domain(certificate)
}

// RFC 4180 状态机：issuer 可以包含逗号、双引号和换行，不按逗号简单 split。
fn csv_records(input: &str) -> Result<Vec<Vec<String>>> {
    if input.len() > 16 * 1024 * 1024 {
        bail!("CSV 超过 16 MiB，请缩小扫描范围");
    }
    let mut records = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut closed = false;
    let mut chars = input.trim_start_matches('\u{feff}').chars().peekable();
    while let Some(ch) = chars.next() {
        if quoted {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                    closed = true;
                }
            } else {
                field.push(ch);
            }
            continue;
        }
        match ch {
            '"' if field.is_empty() && !closed => quoted = true,
            ',' => {
                row.push(std::mem::take(&mut field));
                closed = false;
            }
            '\r' | '\n' => {
                if ch == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                row.push(std::mem::take(&mut field));
                if row.iter().any(|v| !v.is_empty()) {
                    records.push(std::mem::take(&mut row));
                } else {
                    row.clear();
                }
                closed = false;
                if records.len() > 4096 {
                    bail!("CSV 超过 4096 行，请缩小扫描范围");
                }
            }
            _ if closed || ch == '"' => bail!("CSV 引号格式错误，请使用 RealiTLScanner 原始 CSV"),
            _ => field.push(ch),
        }
    }
    if quoted {
        bail!("CSV 引号未闭合");
    }
    if !field.is_empty() || !row.is_empty() || closed {
        row.push(field);
        records.push(row);
    }
    Ok(records)
}

pub(super) fn parse_csv(
    input: &str,
    subnet: Subnet,
    mode: Mode,
    on_vps: bool,
) -> Result<Vec<Candidate>> {
    let rows = csv_records(input)?;
    let header = rows.first().context("CSV 为空")?;
    let column = |names: &[&str]| {
        header
            .iter()
            .position(|v| names.iter().any(|n| v.trim().eq_ignore_ascii_case(n)))
    };
    let cert = column(&["CERT", "DOMAIN", "SNI", "NAME", "COMMON_NAME", "CN"])
        .context("CSV 缺少 CERT/域名列，请使用 RealiTLScanner 原始 CSV")?;
    let origin = column(&["ORIGIN"]);
    let ip = column(&["IP", "ADDRESS", "ADDR"]);
    let mut candidates = Vec::new();
    for (index, row) in rows.iter().enumerate().skip(1) {
        if row.len() != header.len() {
            bail!("CSV 第 {} 行列数与表头不一致", index + 1);
        }
        let certificate = row[cert].trim();
        let domain = scan_domain(
            certificate,
            origin.map(|i| row[i].as_str()).unwrap_or_default(),
        );
        let mut skip = domain.as_ref().err().map(|e| format!("{e:#}"));
        if let Some(i) = ip {
            if !row[i]
                .parse::<IpAddr>()
                .is_ok_and(|address| subnet.contains(address))
            {
                skip = Some("CSV 目标 IP 不在指定扫描 /24 内，跳过".to_owned());
            }
        }
        candidates.push(Candidate {
            domain: domain.unwrap_or_else(|_| {
                certificate
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(253)
                    .collect()
            }),
            source: if on_vps { "VPS 扫描" } else { "本地 CSV" }.to_owned(),
            mode,
            subnet: Some(subnet),
            skip,
        });
    }
    Ok(candidates)
}
