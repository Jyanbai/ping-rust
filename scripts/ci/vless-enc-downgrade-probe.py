#!/usr/bin/env python3
"""Read the VLESS-ENC state fixture with the checksum-pinned v0.2.2 Release.

Uses a user namespace and isolated root; never touches the host /etc/shoes.
"""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request


def main():
    with tempfile.TemporaryDirectory(prefix="vless-enc-downgrade-") as directory:
        work = Path(directory)
        asset = "ping-rust-x86_64-unknown-linux-musl.tar.gz"
        archive = work / asset
        urllib.request.urlretrieve(
            "https://github.com/Jyanbai/ping-rust/releases/download/v0.2.2/" + asset,
            archive,
        )
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == (
            "66a8502a199c31971ab474545ecc18661c4cfd2dc1b0afe81511b33aaf04ba0b"
        )
        root = work / "root"
        state = root / "etc/shoes/ping-rust-state.json"
        state.parent.mkdir(parents=True)
        fixture = Path(__file__).resolve().parents[2] / "tests/fixtures/yaml/vless-enc/state.json"
        shutil.copyfile(fixture, state)
        before = state.read_bytes()
        with tarfile.open(archive) as bundle:
            member = next(m for m in bundle.getmembers() if Path(m.name).name == "ping-rust" and m.isfile())
            (root / "ping-rust").write_bytes(bundle.extractfile(member).read())
        (root / "ping-rust").chmod(0o755)
        prefix = ["unshare", "--user", "--map-root-user", "--mount", "--root", str(root), "/ping-rust"]
        version = subprocess.run(prefix + ["--version"], capture_output=True, timeout=30)
        assert version.returncode == 0, "isolated Release execution failed"
        assert version.stdout.strip() == b"ping-rust 0.2.2"
        result = subprocess.run(prefix + ["info"], capture_output=True, timeout=30)
        assert result.returncode != 0, "old Release unexpectedly read VLESS-ENC state"
        error = re.search(rb"unknown variant [`']VlessEnc[`'][^\r\n]*", result.stderr)
        assert error is not None, "expected VlessEnc parser error missing; output withheld"
        assert state.read_bytes() == before, "state changed during read"
        print("v0.2.2 Release SHA-256 verified; isolated state read exit=" + str(result.returncode))
        print(error[0].decode())
        print("state unchanged: PASS")


if __name__ == "__main__":
    main()
