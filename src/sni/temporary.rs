//! 由 RAII 和全局 Ctrl+C 清理共同管理；不让主程序直接 exit 遗留子进程。
use anyhow::{Context, Result};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tokio::process::{Child, Command};

static ACTIVE: Mutex<Vec<Weak<Mutex<Resources>>>> = Mutex::new(Vec::new());

struct Resources {
    child: Option<Child>,
    directory: Option<TempDir>,
}

impl Resources {
    fn stop_child(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let start = Instant::now();
            while child.try_wait().ok().flatten().is_none()
                && start.elapsed() < Duration::from_secs(1)
            {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    fn clean(&mut self) {
        self.stop_child();
        self.directory.take();
    }
}

pub(super) struct Temporary(Arc<Mutex<Resources>>);

impl Temporary {
    pub(super) fn new() -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("prs-sni-")
            .tempdir()
            .context("创建 SNI 临时目录失败，请检查 /tmp 权限和空间")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let resources = Arc::new(Mutex::new(Resources {
            child: None,
            directory: Some(directory),
        }));
        let mut active = ACTIVE.lock().unwrap_or_else(|e| e.into_inner());
        active.retain(|r| r.strong_count() > 0);
        active.push(Arc::downgrade(&resources));
        Ok(Self(resources))
    }
    pub(super) fn path(&self) -> PathBuf {
        self.0
            .lock()
            .unwrap()
            .directory
            .as_ref()
            .unwrap()
            .path()
            .to_owned()
    }
    pub(super) fn spawn(&self, binary: &Path, args: &[&std::ffi::OsStr]) -> Result<()> {
        let mut resources = self.0.lock().unwrap();
        resources.stop_child();
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let log = options
            .open(
                resources
                    .directory
                    .as_ref()
                    .unwrap()
                    .path()
                    .join("process.log"),
            )
            .context("创建临时检测日志失败，请检查临时目录权限和空间")?;
        let stderr = log.try_clone().context("打开临时检测错误日志失败")?;
        resources.child = Some(
            Command::new(binary)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(stderr))
                .kill_on_drop(true)
                .spawn()
                .context("启动临时检测进程失败，请检查二进制权限和系统架构")?,
        );
        Ok(())
    }
    pub(super) fn log_notice(&self, secrets: &[String]) -> String {
        let log = std::fs::read_to_string(self.path().join("process.log")).unwrap_or_default();
        // 先替换较长凭据，避免有重叠时只替换掉其中一部分；必须在截断之前脱敏。
        let mut secrets: Vec<_> = secrets.iter().filter(|s| !s.is_empty()).collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        let mut lines = Vec::new();
        for line in log.lines().rev() {
            // 取首个日志级别，避免把 INFO 消息里提到的 ERROR/WARN 当作错误行。
            let level = line
                .split(|c: char| c.is_whitespace() || matches!(c, '[' | ']' | ':'))
                .find(|token| matches!(*token, "ERROR" | "WARN" | "INFO" | "DEBUG" | "TRACE"));
            if !matches!(level, Some("ERROR" | "WARN")) {
                continue;
            }
            let mut line = line.to_owned();
            for secret in &secrets {
                line = line.replace(secret.as_str(), "***");
            }
            if line.chars().count() > 300 {
                line = line.chars().take(299).chain(std::iter::once('…')).collect();
            }
            if !lines.contains(&line) {
                lines.push(line);
                if lines.len() == 5 {
                    break;
                }
            }
        }
        if lines.is_empty() {
            "shoes 未输出错误信息".to_owned()
        } else {
            lines.reverse();
            format!("shoes 错误摘要：\n{}", lines.join("\n"))
        }
    }
    pub(super) fn status(&self) -> Result<Option<std::process::ExitStatus>> {
        self.0
            .lock()
            .unwrap()
            .child
            .as_mut()
            .context("临时检测进程未启动")?
            .try_wait()
            .context("读取临时进程状态失败")
    }
    #[cfg(test)]
    pub(super) fn child_id(&self) -> Option<u32> {
        self.0.lock().unwrap().child.as_ref().and_then(Child::id)
    }
    pub(super) async fn wait(&self) -> Result<std::process::ExitStatus> {
        loop {
            if let Some(status) = self.status()? {
                return Ok(status);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clean();
    }
}

pub(crate) fn cleanup_on_interrupt() {
    let active = ACTIVE.lock().unwrap_or_else(|e| e.into_inner());
    for resource in active.iter().filter_map(Weak::upgrade) {
        resource.lock().unwrap_or_else(|e| e.into_inner()).clean();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn process_logs_are_private_append_and_cleaned() {
        let temporary = Temporary::new().unwrap();
        let directory = temporary.path();
        let log = directory.join("process.log");
        for marker in ["dry-run", "request"] {
            temporary
                .spawn(
                    Path::new("/bin/sh"),
                    &[
                        "-c".as_ref(),
                        "printf '%s stdout\\n' \"$1\"; printf '%s stderr\\n' \"$1\" >&2".as_ref(),
                        "probe".as_ref(),
                        marker.as_ref(),
                    ],
                )
                .unwrap();
            assert!(temporary.wait().await.unwrap().success());
        }
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "dry-run stdout\ndry-run stderr\nrequest stdout\nrequest stderr\n"
        );
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(temporary);
        assert!(!directory.exists());
    }

    #[test]
    fn log_notice_summarizes_and_redacts_errors_and_warnings() {
        let temporary = Temporary::new().unwrap();
        let log = temporary.path().join("process.log");
        let secrets = [
            "test-private-key",
            "test-public-key",
            "test-user-id",
            "test-short-id",
            "test-shadowtls-password",
            "test-shadowsocks-password",
        ];
        let contents = format!(
            "ERROR oldest\nWARN older\nINFO ignore ERROR in message\nDEBUG ignore\nTRACE ignore\n\
             [time ERROR shoes] credentials {}\nWARN repeated\nERROR diagnostic\n\
             WARN repeated\nERROR {}test-private-key\nWARN newest\nINFO trailing\n",
            secrets.join(" "),
            "中".repeat(400),
        );
        crate::utils::atomic_write(&log, contents.as_bytes(), 0o600).unwrap();
        let notice = temporary.log_notice(&secrets.map(str::to_owned));
        let lines: Vec<_> = notice.lines().skip(1).collect();
        assert_eq!(lines.len(), 5);
        assert_eq!(
            lines[0],
            "[time ERROR shoes] credentials *** *** *** *** *** ***"
        );
        assert_eq!(lines[1], "ERROR diagnostic");
        assert_eq!(lines[2], "WARN repeated");
        assert!(lines[3].starts_with("ERROR 中"));
        assert_eq!(lines[3].chars().count(), 300);
        assert!(lines[3].ends_with('…'));
        assert_eq!(lines[4], "WARN newest");
        assert!(lines.iter().all(|line| line.chars().count() <= 300));
        assert!(!notice.contains("old"));
        assert!(!notice.contains("ignore"));
        assert!(!notice.contains("trailing"));
        assert!(!notice.contains(log.to_str().unwrap()));
        for secret in secrets {
            assert!(!notice.contains(secret));
        }
    }

    #[test]
    fn log_notice_handles_missing_empty_and_non_error_logs() {
        let temporary = Temporary::new().unwrap();
        let log = temporary.path().join("process.log");
        assert_eq!(temporary.log_notice(&[]), "shoes 未输出错误信息");
        for contents in ["", "INFO started\nDEBUG details\n"] {
            crate::utils::atomic_write(&log, contents.as_bytes(), 0o600).unwrap();
            assert_eq!(temporary.log_notice(&[]), "shoes 未输出错误信息");
        }
    }
}
