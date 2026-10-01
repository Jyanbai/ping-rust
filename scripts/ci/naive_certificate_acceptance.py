"""Disposable systemd runner: regeneration uses the real deployment transaction."""

import json
import os
import shlex
import shutil
import ssl
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from acceptance_diagnostics import preserve_failure_stderr


def files():
    return {str(p): p.read_bytes() for p in Path("/etc/shoes").rglob("*") if p.is_file()}


def failed_regeneration(binary, name, environment):
    result = subprocess.run([binary, "regenerate-test-certificate", name], env=environment,
                            capture_output=True, text=True, timeout=120)
    if result.returncode == 0:
        raise AssertionError("injected certificate transaction failure was not rejected")
    preserve_failure_stderr(os.environ.get("PING_RUST_DIAGNOSTICS_DIR", "/tmp/prs-release-diagnostics"),
                            "regenerate-injected-failure", result.stderr, result.returncode)


def verify_naive_certificate_lifecycle(binary, run, state, pid, free_port):
    name = "release-naive-certificate"
    run("generate", "naiveproxy", "--name", name, "--port", str(free_port()),
        "--server-name", "acceptance.example.invalid", "--self-signed")
    document = state()
    profile = next(p for p in document["profiles"] if p["name"] == name)
    assert profile.pop("naive_certificate_validity", None), "new certificate lacks expiry metadata"
    # Model v0.2.0 metadata without replacing service or server configuration.
    Path("/etc/shoes/ping-rust-state.json").write_text(json.dumps(document))
    output, _ = run("info", name)
    assert "旧证书" in output and "重新生成" in output
    _, errors = run("status")
    assert "旧证书" in errors
    old_files = files()
    before = pid()
    shoes = Path("/usr/local/bin/shoes")
    backup = shoes.with_name("shoes-naive-fixture-backup")
    assert not backup.exists()
    shoes.rename(backup)
    try:
        shoes.write_text("#!/bin/sh\nif [ \"$1\" = --dry-run ]; then exit 42; fi\nexec " + shlex.quote(str(backup)) + ' "$@"\n')
        shoes.chmod(0o755)
        failed_regeneration(binary, name, os.environ.copy())
        assert files() == old_files, "dry-run failure changed live configuration or leaked new credentials"
        assert pid() == before, "rejected dry-run must not restart service"
    finally:
        shoes.unlink()
        backup.rename(shoes)
    with tempfile.TemporaryDirectory(prefix="prs-naive-restart-failure-") as temporary:
        root = Path(temporary)
        real_systemctl = shutil.which("systemctl")
        marker = root / "failed-once"
        wrapper = root / "systemctl"
        wrapper.write_text("#!/bin/sh\nif [ \"$1\" = restart ] && [ ! -e " + shlex.quote(str(marker)) + " ]; then\n touch " + shlex.quote(str(marker)) + "\n exit 42\nfi\nexec " + shlex.quote(real_systemctl) + ' "$@"\n')
        wrapper.chmod(0o755)
        environment = dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"])
        failed_regeneration(binary, name, environment)
        assert marker.exists(), "controlled restart failure was not exercised"
        assert files() == old_files, "activation rollback did not restore all configuration and credentials"
        pid()  # The original service must be active after rollback.
    before = pid()
    output, _ = run("regenerate-test-certificate", name)
    assert "受控重启已完成" in output and pid() != before
    fresh = next(p for p in state()["profiles"] if p["name"] == name)
    assert fresh["certificate_path"] != profile["certificate_path"]
    assert not Path(profile["certificate_path"]).exists()
    assert not Path(profile["certificate_key_path"]).exists()
    certificate = ssl._ssl._test_decode_cert(fresh["certificate_path"])
    parse = lambda value: datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).timestamp()
    start, end = parse(certificate["notBefore"]), parse(certificate["notAfter"])
    assert start <= datetime.now(timezone.utc).timestamp()
    assert end - start == 397 * 86400
    assert fresh["naive_certificate_validity"] == {"not_before": int(start), "not_after": int(end)}
    assert "旧证书" not in run("info", name)[0]
    print("PASS Naive certificate migration: 397-day actual certificate; dry-run rejection; controlled restart; exact activation rollback")
