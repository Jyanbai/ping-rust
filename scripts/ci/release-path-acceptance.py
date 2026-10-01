#!/usr/bin/env python3
"""Fresh disposable systemd runner only; no credential-bearing output is printed."""

import importlib.util
import json
import os
import re
import subprocess
import tempfile
import threading
from pathlib import Path

import pexpect

spec = importlib.util.spec_from_file_location("h2mux_fixture", Path(__file__).with_name("validate-h2mux.py"))
h2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h2)
STATE = Path("/etc/shoes/ping-rust-state.json")
BIN = os.environ["PING_RUST_BIN"]


def run(*args):
    result = subprocess.run([BIN, *args], capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, f"ping-rust {args[0]} failed; credential-bearing output suppressed"
    return result.stdout, result.stderr


def pid():
    assert subprocess.run(["systemctl", "is-active", "--quiet", "shoes.service"]).returncode == 0
    return int(subprocess.check_output(["systemctl", "show", "shoes.service", "-p", "MainPID", "--value"]))


def state():
    return json.loads(STATE.read_text())


def port_present(port):
    output = subprocess.check_output(["ss", "-H", "-lnt"], text=True)
    return any(line.split()[3].endswith(f":{port}") for line in output.splitlines())


def notice(output):
    for marker in ("GitHub Release v0.2.7", "固定 pin", "受控重启", "Update Center", "update --method cargo"):
        assert marker in output, f"restart explanation missing {marker}"


def menu_edit(profile_index, h2mux=False, port=None):
    child = pexpect.spawn(BIN, encoding="utf-8", timeout=120)
    transcript = []
    try:
        child.expect(r"请选择 \[0-10\]")
        child.sendline("2")
        child.expect("请选择配置")
        child.expect(r"请选择 \[")
        child.sendline(str(profile_index + 1))
        child.expect("选择更改项目")
        child.expect(r"请选择 \[")
        choices = child.before
        if h2mux:
            match = re.search(r"(\d+)\) 配置 H2MUX 客户端偏好", choices)
            assert match, "H2MUX edit option missing"
            child.sendline(match[1])
            child.expect("H2MUX 客户端偏好")
            child.expect(r"请选择 \[")
            child.sendline("2")
            for prompt in ("Max connections", "Min streams"):
                child.expect(prompt)
                child.sendline("")
            child.expect("启用 H2MUX padding")
            child.sendline("n")
        else:
            child.sendline("1")
            child.expect("输入新端口")
            child.sendline(str(port))
        child.expect("配置更改成功")
        transcript.append(child.before)
        child.expect(r"请选择 \[0-10\]")
        child.sendline("0")
        child.expect(pexpect.EOF)
        child.close()
        assert child.exitstatus == 0
        return "".join(transcript)
    except Exception:
        raise AssertionError("menu acceptance failed; private terminal transcript suppressed") from None
    finally:
        child.close(force=True)


def main():
    assert os.environ.get("CI") == "true" and os.geteuid() == 0
    assert not STATE.exists() and not Path("/etc/systemd/system/shoes.service").exists()
    output, _ = run("bootstrap")
    assert "首次安装：自动部署 VLESS-REALITY" in output
    assert "选择协议" not in output and "输入端口" not in output
    before = pid()
    provenance = json.loads(Path("/var/lib/ping-rust/shoes-install.json").read_text())
    assert provenance["source"] == "github-release" and provenance["release_tag"] == "v0.2.7"
    reality = state()["profiles"][0]
    assert port_present(reality["port"])
    print("PASS default Release zero-input Reality deployment; github-release v0.2.7; enabled/active and listener")
    socks_port = h2.free_port()
    _, errors = run("add", "socks5", "--name", "release-auth-socks", "--port", str(socks_port),
                    "--server-address", "127.0.0.1", "--yes", "--plain")
    socks = next(p for p in state()["profiles"] if p["name"] == "release-auth-socks")
    assert socks["credentials"]["Socks5"]["username"] and socks["credentials"]["Socks5"]["password"]
    notice(errors)
    assert pid() != before and port_present(socks_port)
    before = pid()
    new_port = h2.free_port()
    notice(menu_edit(state()["profiles"].index(socks), port=new_port))
    assert pid() != before and not port_present(socks_port) and port_present(new_port)
    before = pid()
    _, errors = run("delete", socks["id"], "--yes")
    notice(errors)
    assert pid() != before and not port_present(new_port)
    print("PASS authenticated SOCKS add/edit/non-last delete: controlled restart notice and correct listeners")
    run("generate", "trojan-tls", "--name", "release-h2mux", "--port", str(h2.free_port()), "--server-name", h2.HOST)
    profile = next(p for p in state()["profiles"] if p["name"] == "release-h2mux")
    before = pid()
    menu_edit(state()["profiles"].index(profile), h2mux=True)
    assert pid() == before, "H2MUX preference must not restart unchanged server YAML"
    output, _ = run("export", "sing-box", "--profile", profile["id"], "--server", "127.0.0.1")
    client = json.loads(output)
    outbound = client["outbounds"][0]
    assert outbound["multiplex"]["protocol"] == "h2mux"
    with tempfile.TemporaryDirectory(prefix="prs-release-acceptance-") as temporary, h2.socket.socket() as listener:
        root = Path(temporary)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        done = threading.Event()
        worker = threading.Thread(target=h2.origin, args=(listener, done), daemon=True)
        worker.start()
        port = h2.free_port()
        client["inbounds"] = [{"type": "socks", "listen": "127.0.0.1", "listen_port": port,
                               "users": [{"username": h2.SOCKS_USER, "password": h2.SOCKS_PASSWORD}]}]
        client["route"] = {"final": outbound["tag"]}
        path = root / "client.json"
        path.write_text(json.dumps(client))
        with (root / "client.log").open("wb") as log:
            process = subprocess.Popen([os.environ["PING_RUST_SING_BOX_BIN"], "run", "-c", str(path)], stdout=log, stderr=log)
            try:
                h2.wait_port(port)
                h2.through_socks(port, listener.getsockname()[1], b"Release H2MUX small payload")
                h2.through_socks(port, listener.getsockname()[1], bytes(range(256)) * 4096)
            finally:
                process.terminate()
                process.wait(timeout=5)
                done.set()
                worker.join(timeout=2)
    print("PASS github-release v0.2.7 H2MUX preference/export/sing-box 1.14.2 data: small and 1MiB half-close")
    run("uninstall", "--purge")


if __name__ == "__main__":
    main()
