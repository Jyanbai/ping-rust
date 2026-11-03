//! 由 RAII 和全局 Ctrl+C 清理共同管理；不让主程序直接 exit 遗留子进程。
use anyhow::{Context, Result};
use std::{
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
        resources.child = Some(
            Command::new(binary)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .context("启动临时检测进程失败，请检查二进制权限和系统架构")?,
        );
        Ok(())
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
