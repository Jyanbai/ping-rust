use std::{fs, path::Path};

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use super::{Credentials, ManagedProfile};
use crate::utils;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NaiveCertificateValidity {
    pub not_before: i64,
    pub not_after: i64,
}

// CA/B Forum Ballot SC-081v3:
// https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/
// Apply each stage to the certificate's notBefore (UTC), not today's date.
// Test certificates use one day less than the limit. Public Web PKI policy is
// used for Chromium compatibility here; actual client acceptance must be tested.
const VALIDITY_PHASES: &[(i64, i64)] = &[
    (1_868_227_200, 47),  // 2029-03-15
    (1_805_068_800, 100), // 2027-03-15
    (1_773_532_800, 200), // 2026-03-15
];

fn maximum_validity_days(not_before: i64) -> i64 {
    VALIDITY_PHASES
        .iter()
        .find(|(start, _)| not_before >= *start)
        .map_or(398, |(_, days)| *days)
}

impl NaiveCertificateValidity {
    fn duration_seconds(self) -> i64 {
        self.not_after.saturating_sub(self.not_before)
    }

    pub fn needs_regeneration(self) -> bool {
        let duration = self.duration_seconds();
        duration <= 0 || duration > maximum_validity_days(self.not_before) * 86400
    }
}

pub(super) fn write_test_certificate(
    server_name: &str,
    certificate: &Path,
    key: &Path,
) -> Result<NaiveCertificateValidity> {
    write_test_certificate_at(server_name, certificate, key, OffsetDateTime::now_utc())
}

pub(super) fn write_test_certificate_at(
    server_name: &str,
    certificate: &Path,
    key: &Path,
    now: OffsetDateTime,
) -> Result<NaiveCertificateValidity> {
    let now = OffsetDateTime::from_unix_timestamp(now.unix_timestamp())?;
    let mut params = CertificateParams::new(vec![server_name.to_owned()])?;
    params.not_before = now - Duration::hours(1);
    params.not_after = params.not_before
        + Duration::days(maximum_validity_days(params.not_before.unix_timestamp()) - 1);
    let validity = NaiveCertificateValidity {
        not_before: params.not_before.unix_timestamp(),
        not_after: params.not_after.unix_timestamp(),
    };
    let key_pair = KeyPair::generate().context("生成 NaiveProxy 测试证书私钥失败")?;
    let generated = params
        .self_signed(&key_pair)
        .context("生成 NaiveProxy 测试证书失败")?;
    utils::atomic_write(certificate, generated.pem().as_bytes(), 0o644)?;
    if let Err(error) = utils::atomic_write(key, key_pair.serialize_pem().as_bytes(), 0o600) {
        let _ = fs::remove_file(certificate);
        return Err(error.context("写入 NaiveProxy 测试证书私钥失败，已清理证书"));
    }
    Ok(validity)
}

impl ManagedProfile {
    pub fn naive_certificate_warning(&self, now: i64) -> Option<String> {
        if !self.self_signed_certificate
            || !matches!(self.credentials, Credentials::NaiveProxy { .. })
        {
            return None;
        }
        let regenerate =
            "请执行 regenerate-test-certificate，或在更改配置菜单中选择“重新生成测试证书”";
        match self.naive_certificate_validity {
            None => Some(format!("警告：NaiveProxy 旧证书缺少有效期元数据；v0.2.0 的超长有效期与 Chromium 系客户端不兼容。{regenerate}。")),
            Some(validity) if validity.needs_regeneration() => Some(format!("警告：NaiveProxy 测试证书记录的有效期无效或超过其 notBefore 所在阶段的 SC-081v3 上限。{regenerate}。")),
            Some(validity) if validity.not_after <= now => Some(format!("警告：NaiveProxy 测试证书已过期。{regenerate}。")),
            Some(validity) if i128::from(validity.not_after.saturating_sub(now)) * 3 < i128::from(validity.duration_seconds()) => Some(format!("警告：NaiveProxy 测试证书剩余不足有效期的 1/3。{regenerate}。")),
            _ => None,
        }
    }

    pub fn naive_certificate_details(&self) -> Vec<String> {
        if !self.self_signed_certificate
            || !matches!(self.credentials, Credentials::NaiveProxy { .. })
        {
            return Vec::new();
        }
        let mut lines = Vec::new();
        if let Some(validity) = self.naive_certificate_validity {
            lines.push(format!(
                "NaiveProxy 测试证书记录的有效期：{} 天",
                validity.duration_seconds() / 86400
            ));
            lines.push("NaiveProxy 测试证书采用 SC-081v3 时间表".to_owned());
        }
        let expiry = self
            .naive_certificate_validity
            .and_then(|v| OffsetDateTime::from_unix_timestamp(v.not_after).ok());
        lines.push(match expiry {
            Some(time) => format!("测试证书到期日期：{} UTC", time.date()),
            None => "测试证书到期日期：未知（旧证书）".to_owned(),
        });
        if let Some(warning) =
            self.naive_certificate_warning(OffsetDateTime::now_utc().unix_timestamp())
        {
            lines.push(warning);
        }
        lines
    }
}
