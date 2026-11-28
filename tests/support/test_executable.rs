use std::{
    fs::{OpenOptions, Permissions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    thread,
    time::Duration,
};

const PROBE_ARG: &str = "--ping-rust-test-probe";

pub(crate) fn write_test_script(path: &Path, script: impl AsRef<[u8]>) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "#!/bin/sh\n[ \"${{1-}}\" != {PROBE_ARG} ] || exit 0")?;
    file.write_all(script.as_ref())?;
    file.set_permissions(Permissions::from_mode(0o700))?;
    file.sync_all()?;
    drop(file);

    let status = retry_text_file_busy(|| Command::new(path).arg(PROBE_ARG).status())?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "假可执行文件 {} 的启动探测失败：{status}",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn retry_text_file_busy<T>(mut run: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    for _ in 1..20 {
        match run() {
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => {
                thread::sleep(Duration::from_millis(25));
            }
            result => return result,
        }
    }
    run()
}
