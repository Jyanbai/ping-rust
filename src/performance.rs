use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::Instant,
};

use serde::Serialize;

const REPORT_ENV: &str = "PING_RUST_PERFORMANCE_REPORT";
const SCENARIO_ENV: &str = "PING_RUST_PERFORMANCE_SCENARIO";

pub(crate) struct StageTimer {
    stage: &'static str,
    scenario: String,
    report: Option<PathBuf>,
    started: Instant,
}

#[derive(Serialize)]
struct StageRecord<'a> {
    event: &'static str,
    scenario: &'a str,
    stage: &'static str,
    duration_us: u128,
}

pub(crate) fn stage(stage: &'static str) -> StageTimer {
    let scenario = env::var(SCENARIO_ENV)
        .ok()
        .filter(|value| valid_label(value))
        .unwrap_or_else(|| "unspecified".to_owned());
    let report = env::var_os(REPORT_ENV).map(PathBuf::from).filter(|path| {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.file_type().is_file() && !metadata.file_type().is_symlink()
        })
    });
    StageTimer {
        stage,
        scenario,
        report,
        started: Instant::now(),
    }
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

impl Drop for StageTimer {
    fn drop(&mut self) {
        let Some(report) = &self.report else {
            return;
        };
        let record = StageRecord {
            event: "stage",
            scenario: &self.scenario,
            stage: self.stage,
            duration_us: self.started.elapsed().as_micros(),
        };
        let Ok(mut line) = serde_json::to_vec(&record) else {
            return;
        };
        line.push(b'\n');
        if let Ok(mut output) = OpenOptions::new().append(true).open(report) {
            let _ = output.write_all(&line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn performance_labels_are_bounded_and_machine_readable() {
        assert!(valid_label("cold_install"));
        assert!(valid_label("ubuntu-24_04"));
        assert!(!valid_label(""));
        assert!(!valid_label("contains space"));
        assert!(!valid_label("../escape"));
        assert!(!valid_label(&"x".repeat(65)));
    }

    #[test]
    fn performance_record_has_no_configuration_or_secret_fields() {
        let record = StageRecord {
            event: "stage",
            scenario: "warm_add",
            stage: "shoes_dry_run",
            duration_us: 42,
        };
        let value = serde_json::to_value(record).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 4);
        assert!(object.contains_key("event"));
        assert!(object.contains_key("scenario"));
        assert!(object.contains_key("stage"));
        assert!(object.contains_key("duration_us"));
    }
}
