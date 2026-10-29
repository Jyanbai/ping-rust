#!/usr/bin/env python3
"""Pinned client interoperability; never persist or print server credentials."""
import contextlib
import http.server
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import threading
import time
import urllib.parse


PRS = os.environ["PING_RUST"]
WORK = Path(os.environ["WORK"])
RECORDS = Path(os.environ["RECORDS"])
SECRETS = []
LOGS = []
RESULTS = []
DOWNGRADE = {}
FORBIDDEN = re.compile(rb"mlkem768x25519plus\.(?:native|xorpub|random)\.600s\.[A-Za-z0-9_-]+")


class AcceptanceFailure(Exception):
    """A fixed stage label, never child output or credential data."""


def require(condition, stage):
    if not condition:
        raise AcceptanceFailure(stage)


def safe(data):
    require(not FORBIDDEN.search(data), "decryption pattern detected")
    require(not any(secret in data for secret in SECRETS), "decryption value detected")


def command(args, label):
    result = subprocess.run(args, capture_output=True, timeout=120)
    # CLI output must be safe even when a subprocess fails.
    safe(result.stdout)
    safe(result.stderr)
    LOGS.append((label, result.stdout + result.stderr))
    require(result.returncode == 0, label)
    return result.stdout.decode()


def pid():
    value = command(["systemctl", "show", "shoes", "-p", "MainPID", "--value"], "main-pid").strip()
    require(value.isdecimal() and int(value) > 0, "service has no MainPID")
    return value


def wait_port(port, process):
    for _ in range(100):
        require(process.poll() is None, "client exited before listening")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("client listen timeout")


HITS = []


class Endpoint(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        HITS.append(self.path)
        body = self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


@contextlib.contextmanager
def client_process(args, label):
    # Raw child logs remain in memory; no credentials can reach a file.
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        wait_port(18081, process)
        yield process
    finally:
        process.terminate()
        try:
            raw, _ = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            raw, _ = process.communicate()
        safe(raw)
        LOGS.append((label, raw))


def test_case(client, mode, auth, vision, index):
    label = f"{client}-{mode}-{auth}-vision-{str(vision).lower()}"
    port = 25100 + index
    old_pid = pid()
    args = [PRS, "add", "vless-enc", "--port", str(port), "--name", label,
            "--server-address", "127.0.0.1", "--yes", "--plain",
            "--encryption-mode", mode, "--encryption-auth", auth]
    if vision:
        args.append("--vision")
    uri = command(args, label + "-add").strip()
    require(pid() != old_pid, "Release add must perform controlled restart")
    require(command(["systemctl", "is-active", "shoes"], label + "-active").strip() == "active",
            "service must be active after controlled restart")
    listeners = command(["ss", "-H", "-ltn", "sport", "=", str(port)], label + "-listener")
    require(bool(listeners.strip()), "new server port must listen after controlled restart")
    profile_path = Path(f"/etc/shoes/profiles/VLESS-ENC-{port}.yaml")
    aggregate = Path("/etc/shoes/config.yaml")
    for path in (profile_path, aggregate):
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, "runtime permissions must be 0600")
    profile_text = profile_path.read_text()
    match = re.search(r"^\s*decryption: ([A-Za-z0-9_.-]+)\s*$", profile_text, re.M)
    require(match is not None, "server decryption missing")
    SECRETS.append(match[1].encode())
    require("encryption_limits:" not in profile_text, "must use shoes default limits")
    require("tls_targets:" not in profile_text and "reality_targets:" not in profile_text, "must be native TCP")
    state_bytes = Path("/etc/shoes/ping-rust-state.json").read_bytes()
    safe(state_bytes)
    state = json.loads(state_bytes)
    profile = next(p for p in state["profiles"] if p["port"] == port)
    parsed = urllib.parse.urlsplit(uri)
    query = urllib.parse.parse_qs(parsed.query)
    require(parsed.scheme == "vless" and parsed.hostname == "127.0.0.1", "invalid URI authority")
    require(query["security"] == ["none"] and query["type"] == ["tcp"], "invalid URI security or transport")
    require(query.get("flow") == (["xtls-rprx-vision"] if vision else None), "invalid URI Vision")
    encryption = profile["credentials"]["VlessEnc"]["encryption"]
    require(query["encryption"] == [encryption], "URI encryption differs from state")
    details = command([PRS, "info", label], label + "-info")
    require("Encryption" in details and mode in details, "details missing encryption or mode")
    for target in ("sing-box", "nekobox"):
        result = subprocess.run([PRS, "export", target, "--profile", profile["id"], "--server", "127.0.0.1"], capture_output=True, timeout=30)
        safe(result.stdout + result.stderr)
        require(result.returncode != 0 and "不支持 VLESS Encryption" in result.stderr.decode(), "unsupported export must refuse")

    config = WORK / (label + (".json" if client == "xray" else ".yaml"))
    if client == "xray":
        user = {"id": parsed.username, "encryption": encryption}
        if vision:
            user["flow"] = "xtls-rprx-vision"
        content = json.dumps({
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": 18081, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": port, "users": [user]}]}, "streamSettings": {"network": "tcp", "security": "none"}}],
        })
        client_args = [os.environ["XRAY"], "run", "-c", str(config)]
    else:
        content = command([PRS, "export", "clash-meta", "--profile", profile["id"], "--server", "127.0.0.1"], label + "-export")
        require("encryption:" in content, "Mihomo export missing encryption")
        content += f"\nsocks-port: 18081\nallow-lan: false\nmode: rule\nlog-level: warning\nrules:\n  - MATCH,{label}\n"
        client_args = [os.environ["MIHOMO"], "-d", str(WORK / "mihomo"), "-f", str(config)]
    config.write_text(content)
    config.chmod(0o600)
    request_path = "/" + label
    before = HITS.count(request_path)
    with client_process(client_args, label + "-client"):
        response = command(["curl", "--noproxy", "", "--fail", "--silent", "--show-error", "--max-time", "15", "--proxy", "socks5h://127.0.0.1:18081", f"http://127.0.0.1:18080{request_path}"], label + "-request")
        require(response == request_path, "proxy response marker differs")
    require(HITS.count(request_path) == before + 1, "endpoint did not receive exactly one request")
    RESULTS.append({"case": label, "result": "PASS", "endpoint_requests": 1, "controlled_restart": True, "service_active": True, "new_port_listening": True})
    print(label + ": PASS", flush=True)


def main():
    os.umask(0o077)
    WORK.mkdir(parents=True, exist_ok=True)
    RECORDS.mkdir(parents=True, exist_ok=True)
    endpoint = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), Endpoint)
    threading.Thread(target=endpoint.serve_forever, daemon=True).start()
    status = 0
    try:
        # Establish an active managed service before testing ENC additions.
        command([PRS, "add", "socks5", "--port", "25099", "--server-address", "127.0.0.1", "--yes", "--plain"], "baseline-add")
        matrix = [("xray", mode, "x25519", vision) for mode in ("native", "xorpub", "random") for vision in (False, True)]
        matrix += [("xray", "native", "mlkem768", False), ("mihomo", "native", "x25519", False), ("mihomo", "native", "x25519", True)]
        for index, case in enumerate(matrix):
            test_case(*case, index)
        # Read the real state produced above with the published v0.2.2 binary.
        # Keep only the parser error: never persist any old CLI profile output.
        old = os.environ["OLD_PING_RUST"]
        version = command([old, "--version"], "downgrade-version").strip()
        require(version.startswith("ping-rust 0.2.2"), "downgrade binary version")
        state_path = Path("/etc/shoes/ping-rust-state.json")
        before = state_path.read_bytes()
        result = subprocess.run([old, "info"], capture_output=True, timeout=30)
        require(result.returncode != 0, "v0.2.2 must refuse VLESS-ENC state")
        safe(result.stdout + result.stderr)
        error = re.search(rb"unknown variant [`']VlessEnc[`'][^\r\n]*", result.stderr)
        require(error is not None, "v0.2.2 must report unknown VlessEnc variant")
        require(state_path.read_bytes() == before, "v0.2.2 read must preserve state")
        DOWNGRADE.update(version="v0.2.2", exit_code=result.returncode,
                         error=error[0].decode(), state_unchanged=True)
        print("v0.2.2 downgrade probe: " + error[0].decode(), flush=True)
    except Exception as error:
        # Do not print exception chains, argv, captured output or config data.
        stage = str(error) if isinstance(error, AcceptanceFailure) else "unexpected error; details withheld"
        print("VLESS-ENC acceptance failed at " + stage, flush=True)
        RESULTS.append({"result": "FAIL", "stage": stage, "completed_cases": len(RESULTS)})
        status = 1
    finally:
        journal = subprocess.run(["journalctl", "-u", "shoes", "--no-pager", "-o", "cat"], capture_output=True, timeout=30)
        try:
            safe(journal.stdout + journal.stderr)
            LOGS.append(("shoes-journal", journal.stdout + journal.stderr))
            for label, raw in LOGS:
                safe(raw)
                (RECORDS / (label + ".log")).write_bytes(raw)
            # Scan the exact directory later uploaded as an artifact.
            for path in RECORDS.rglob("*"):
                if path.is_file():
                    safe(path.read_bytes())
        except Exception:
            print("Secret audit failed; raw output has been withheld.", flush=True)
            status = 1
        report = {"xray": "v26.6.27", "mihomo": "v1.19.33", "shoes": "v0.3.6", "cases": RESULTS, "downgrade": DOWNGRADE, "artifact_secret_audit": status == 0}
        (RECORDS / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        endpoint.shutdown()
        subprocess.run(["systemctl", "stop", "shoes"], capture_output=True, timeout=30)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
