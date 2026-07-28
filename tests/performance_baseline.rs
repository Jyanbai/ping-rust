#![cfg(target_os = "linux")]

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const CONFIG_DIR: &str = "/etc/shoes";
const CONFIG_FILE: &str = "/etc/shoes/config.yaml";
const STATE_FILE: &str = "/etc/shoes/ping-rust-state.json";
const PROFILES_DIR: &str = "/etc/shoes/profiles";
const SHOES_BIN: &str = "/usr/local/bin/shoes";
const SERVICE_FILE: &str = "/etc/systemd/system/shoes.service";
const DROP_IN_DIR: &str = "/etc/systemd/system/shoes.service.d";
const DROP_IN_FILE: &str = "/etc/systemd/system/shoes.service.d/performance-fault.conf";
const FAULT_MARKER: &str = "/dev/shm/ping-rust-performance-fault";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Serialize)]
struct EnvironmentReport {
    event: &'static str,
    distro_id: String,
    distro_version: String,
    architecture: String,
    kernel: String,
    ping_rust_version: String,
    logical_cpus: usize,
    mem_total_kib: Option<u64>,
}

struct Snapshot {
    config: Vec<u8>,
    state: Vec<u8>,
    profiles: Vec<(String, Vec<u8>)>,
    unit: Vec<u8>,
}

struct Harness {
    binary: PathBuf,
    expect_script: PathBuf,
    report_dir: PathBuf,
    stage_report: PathBuf,
    resource_report: PathBuf,
    claimed_host: bool,
}

impl Harness {
    fn from_environment() -> TestResult<Self> {
        if env::var_os("PING_RUST_PERFORMANCE_E2E").as_deref() != Some(OsStr::new("1")) {
            return Err(
                "set PING_RUST_PERFORMANCE_E2E=1 to authorize ephemeral-host testing".into(),
            );
        }
        if command_stdout("id", &["-u"])? != "0" {
            return Err("performance acceptance must run as root".into());
        }
        let binary = required_absolute_path("PING_RUST_PERFORMANCE_BIN")?;
        let expect_script = required_absolute_path("PING_RUST_PERFORMANCE_EXPECT")?;
        let report_dir = required_absolute_path("PING_RUST_PERFORMANCE_OUTPUT")?;
        if !binary.is_file() {
            return Err(format!("ping-rust binary is missing: {}", binary.display()).into());
        }
        if !expect_script.is_file() {
            return Err(format!("Expect script is missing: {}", expect_script.display()).into());
        }
        for path in [
            CONFIG_DIR,
            SHOES_BIN,
            SERVICE_FILE,
            DROP_IN_DIR,
            FAULT_MARKER,
        ] {
            if Path::new(path).exists() {
                return Err(format!("refusing non-clean performance host: {path} exists").into());
            }
        }
        if report_dir.exists() && fs::read_dir(&report_dir)?.next().is_some() {
            return Err(
                format!("performance output is not empty: {}", report_dir.display()).into(),
            );
        }
        fs::create_dir_all(&report_dir)?;
        fs::set_permissions(&report_dir, fs::Permissions::from_mode(0o700))?;
        let stage_report = report_dir.join("stages.jsonl");
        let resource_report = report_dir.join("resources.txt");
        create_private_file(&stage_report)?;
        create_private_file(&resource_report)?;
        let mut harness = Self {
            binary,
            expect_script,
            report_dir,
            stage_report,
            resource_report,
            claimed_host: true,
        };
        harness.write_environment_report()?;
        Ok(harness)
    }

    fn write_environment_report(&mut self) -> TestResult {
        let os_release = fs::read_to_string("/etc/os-release")?;
        let report = EnvironmentReport {
            event: "environment",
            distro_id: os_release_value(&os_release, "ID").unwrap_or_else(|| "unknown".to_owned()),
            distro_version: os_release_value(&os_release, "VERSION_ID")
                .unwrap_or_else(|| "unknown".to_owned()),
            architecture: command_stdout("uname", &["-m"])?,
            kernel: command_stdout("uname", &["-r"])?,
            ping_rust_version: command_stdout(
                self.binary
                    .to_str()
                    .ok_or("ping-rust binary path is not UTF-8")?,
                &["--version"],
            )?,
            logical_cpus: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
            mem_total_kib: mem_total_kib(),
        };
        let bytes = serde_json::to_vec(&report)?;
        fs::write(self.report_dir.join("environment.json"), bytes)?;
        Ok(())
    }

    fn run(&mut self) -> TestResult {
        self.record_disk("before_cold_install")?;
        self.run_timed("cold_install", &["bootstrap"], true)?;
        self.assert_service_ready()?;
        self.record_disk("after_cold_install")?;

        self.run_config_update()?;
        self.assert_service_ready()?;
        self.record_disk("after_config_update")?;

        self.run_timed(
            "warm_add",
            &[
                "add",
                "shadowsocks",
                "--server-address",
                "203.0.113.10",
                "--yes",
                "--plain",
            ],
            true,
        )?;
        self.assert_service_ready()?;
        self.record_disk("after_warm_add")?;

        self.run_rollback_scenario()?;
        self.assert_service_ready()?;
        self.record_disk("after_rollback")?;
        self.validate_reports()
    }

    fn run_timed(
        &self,
        scenario: &str,
        arguments: &[&str],
        expect_success: bool,
    ) -> TestResult<Output> {
        let format =
            format!("scenario={scenario} elapsed_seconds=%e max_rss_kib=%M exit_status=%x");
        let output = Command::new("/usr/bin/time")
            .args(["-f", &format, "-a", "-o"])
            .arg(&self.resource_report)
            .arg("env")
            .arg(format!(
                "PING_RUST_PERFORMANCE_REPORT={}",
                self.stage_report.display()
            ))
            .arg(format!("PING_RUST_PERFORMANCE_SCENARIO={scenario}"))
            .arg(&self.binary)
            .args(arguments)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;
        if output.status.success() != expect_success {
            return Err(format!(
                "scenario {scenario} returned unexpected status {}",
                output.status
            )
            .into());
        }
        Ok(output)
    }

    fn run_config_update(&self) -> TestResult {
        let status = Command::new("expect")
            .arg(&self.expect_script)
            .arg(&self.binary)
            .arg(&self.stage_report)
            .arg(&self.resource_report)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()?;
        if !status.success() {
            return Err(format!("config_update Expect scenario failed: {status}").into());
        }
        Ok(())
    }

    fn run_rollback_scenario(&self) -> TestResult {
        let before = Snapshot::capture()?;
        fs::create_dir_all(DROP_IN_DIR)?;
        fs::write(
            DROP_IN_FILE,
            concat!(
                "[Service]\n",
                "ExecStartPre=/bin/sh -c \"test -e ",
                "/dev/shm/ping-rust-performance-fault",
                " || { touch ",
                "/dev/shm/ping-rust-performance-fault",
                "; exit 42; }\"\n"
            ),
        )?;
        systemctl(&["daemon-reload"])?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let port_text = port.to_string();
        let output = self.run_timed(
            "rollback",
            &[
                "add",
                "reality",
                "--name",
                "must-rollback",
                "--port",
                &port_text,
                "--server-address",
                "203.0.113.10",
                "--plain",
            ],
            false,
        )?;
        let fault_executed = Path::new(FAULT_MARKER).is_file();
        remove_file_if_exists(DROP_IN_FILE)?;
        remove_file_if_exists(FAULT_MARKER)?;
        if Path::new(DROP_IN_DIR).is_dir() && fs::read_dir(DROP_IN_DIR)?.next().is_none() {
            fs::remove_dir(DROP_IN_DIR)?;
        }
        systemctl(&["daemon-reload"])?;
        if !fault_executed {
            return Err("rollback fault injection did not execute".into());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("回滚") || !stderr.contains("激活阶段失败") {
            return Err("rollback scenario did not report the expected safe failure".into());
        }
        if stderr.contains("vless://") {
            return Err("failed rollback leaked a share URI".into());
        }
        before.assert_unchanged()?;
        if Path::new(PROFILES_DIR)
            .join(format!("VLESS-REALITY-{port}.yaml"))
            .exists()
        {
            return Err("failed rollback left a profile file behind".into());
        }
        Ok(())
    }

    fn assert_service_ready(&self) -> TestResult {
        systemctl(&["is-enabled", "--quiet", "shoes.service"])?;
        systemctl(&["is-active", "--quiet", "shoes.service"])?;
        let status = Command::new(SHOES_BIN)
            .args(["--dry-run", CONFIG_FILE])
            .status()?;
        if !status.success() {
            return Err("shoes rejected the live configuration after a scenario".into());
        }
        Ok(())
    }

    fn record_disk(&self, scenario: &str) -> TestResult {
        let bytes = managed_disk_bytes()?;
        let mut report = OpenOptions::new()
            .append(true)
            .open(&self.resource_report)?;
        writeln!(report, "scenario={scenario} managed_disk_bytes={bytes}")?;
        Ok(())
    }

    fn validate_reports(&self) -> TestResult {
        let stages = fs::read_to_string(&self.stage_report)?;
        for required in [
            "\"scenario\":\"cold_install\"",
            "\"scenario\":\"warm_add\"",
            "\"scenario\":\"config_update\"",
            "\"scenario\":\"rollback\"",
            "\"stage\":\"shoes_download\"",
            "\"stage\":\"config_generate\"",
            "\"stage\":\"shoes_dry_run\"",
            "\"stage\":\"config_commit\"",
            "\"stage\":\"systemd_activate\"",
            "\"stage\":\"rollback_restore\"",
        ] {
            if !stages.contains(required) {
                return Err(format!("performance stage report is missing {required}").into());
            }
        }
        let resources = fs::read_to_string(&self.resource_report)?;
        for scenario in ["cold_install", "config_update", "warm_add", "rollback"] {
            if !resources.contains(&format!("scenario={scenario} elapsed_seconds=")) {
                return Err(format!("resource report is missing scenario {scenario}").into());
            }
        }
        for forbidden in ["vless://", "ss://", "private_key", "password", "user_id"] {
            if stages.contains(forbidden) || resources.contains(forbidden) {
                return Err(
                    format!("performance report contains forbidden field {forbidden}").into(),
                );
            }
        }
        Ok(())
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if !self.claimed_host {
            return;
        }
        let _ = Command::new(&self.binary)
            .args(["uninstall", "--purge"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = remove_file_if_exists(DROP_IN_FILE);
        let _ = remove_file_if_exists(FAULT_MARKER);
        let _ = fs::remove_dir(DROP_IN_DIR);
        let _ = remove_file_if_exists(SERVICE_FILE);
        let _ = remove_file_if_exists(SHOES_BIN);
        let _ = Command::new("systemctl")
            .arg("daemon-reload")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl Snapshot {
    fn capture() -> TestResult<Self> {
        let mut profiles = Vec::new();
        for entry in fs::read_dir(PROFILES_DIR)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                profiles.push((
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path())?,
                ));
            }
        }
        profiles.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(Self {
            config: fs::read(CONFIG_FILE)?,
            state: fs::read(STATE_FILE)?,
            profiles,
            unit: fs::read(SERVICE_FILE)?,
        })
    }

    fn assert_unchanged(&self) -> TestResult {
        let after = Self::capture()?;
        if digest(&self.config) != digest(&after.config)
            || digest(&self.state) != digest(&after.state)
            || digest(&self.unit) != digest(&after.unit)
            || self.profiles.len() != after.profiles.len()
        {
            return Err("rollback did not restore config/state/profiles/unit exactly".into());
        }
        for (before, after) in self.profiles.iter().zip(&after.profiles) {
            if before.0 != after.0 || digest(&before.1) != digest(&after.1) {
                return Err("rollback changed a managed profile file".into());
            }
        }
        Ok(())
    }
}

fn required_absolute_path(name: &str) -> TestResult<PathBuf> {
    let path = PathBuf::from(env::var_os(name).ok_or_else(|| format!("{name} is required"))?);
    if !path.is_absolute() {
        return Err(format!("{name} must be an absolute path").into());
    }
    Ok(path)
}

fn create_private_file(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

fn systemctl(arguments: &[&str]) -> TestResult {
    let status = Command::new("systemctl")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(format!("systemctl {} failed: {status}", arguments.join(" ")).into());
    }
    Ok(())
}

fn command_stdout(program: &str, arguments: &[&str]) -> TestResult<String> {
    let output = Command::new(program).args(arguments).output()?;
    if !output.status.success() {
        return Err(format!("{program} failed: {}", output.status).into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn os_release_value(contents: &str, key: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let value = line.strip_prefix(&format!("{key}="))?;
        Some(value.trim_matches('"').to_owned())
    })
}

fn mem_total_kib() -> Option<u64> {
    fs::read_to_string("/proc/meminfo")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("MemTotal:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
}

fn managed_disk_bytes() -> io::Result<u64> {
    [CONFIG_DIR, SHOES_BIN, SERVICE_FILE]
        .into_iter()
        .try_fold(0_u64, |total, path| {
            total
                .checked_add(path_bytes(Path::new(path))?)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "managed disk size overflow")
                })
        })
}

fn path_bytes(path: &Path) -> io::Result<u64> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("refusing symlink while measuring {}", path.display()),
        ));
    }
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Ok(0);
    }
    fs::read_dir(path)?.try_fold(0_u64, |total, entry| {
        total
            .checked_add(path_bytes(&entry?.path())?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "directory size overflow"))
    })
}

fn digest(contents: &[u8]) -> [u8; 32] {
    Sha256::digest(contents).into()
}

fn remove_file_if_exists(path: impl AsRef<Path>) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[test]
#[ignore = "requires an ephemeral root Linux host with systemd and outbound network access"]
fn performance_and_reliability_baseline() {
    let mut harness =
        Harness::from_environment().expect("failed to initialize performance harness");
    harness.run().expect("performance baseline failed");
}
