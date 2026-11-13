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
VLESS_SUDOKU_RESULTS = []
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


def test_case(client, mode, auth, vision, index, sudoku=None, plain=False):
    label = "xray-vless-plain" if plain else f"{client}-{mode}-{auth}-vision-{str(vision).lower()}"
    if sudoku:
        label += "-sudoku-" + sudoku
    # Preserve the existing workflow's exact ENC matrix assertions. The new
    # protocol has a separate report and mandatory checks in this script.
    case_results = VLESS_SUDOKU_RESULTS if plain else RESULTS
    port = 25100 + index
    old_pid = pid()
    args = [PRS, "add", "vless-sudoku" if plain else "vless-enc", "--port", str(port), "--name", label,
            "--server-address", "127.0.0.1", "--yes", "--plain"]
    if not plain:
        args += ["--encryption-mode", mode, "--encryption-auth", auth]
    if vision:
        args.append("--vision")
    if sudoku:
        if not plain:
            args.append("--sudoku")
        args += ["--sudoku-ascii", sudoku.replace("_", "-")]
    uri = command(args, label + "-add").strip()
    require(pid() != old_pid, "Release add must perform controlled restart")
    require(command(["systemctl", "is-active", "shoes"], label + "-active").strip() == "active",
            "service must be active after controlled restart")
    listeners = command(["ss", "-H", "-ltn", "sport", "=", str(port)], label + "-listener")
    require(bool(listeners.strip()), "new server port must listen after controlled restart")
    prefix = "VLESS-SUDOKU" if plain else "VLESS-ENC"
    profile_path = Path(f"/etc/shoes/profiles/{prefix}-{port}.yaml")
    aggregate = Path("/etc/shoes/config.yaml")
    for path in (profile_path, aggregate):
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, "runtime permissions must be 0600")
    profile_text = profile_path.read_text()
    match = re.search(r"^\s*decryption: ([A-Za-z0-9_.-]+)\s*$", profile_text, re.M)
    if plain:
        require(match is None, "plain VLESS must omit decryption")
        require(not re.search(r"^\s*(?:encryption|vision):", profile_text, re.M), "plain VLESS must omit encryption and Vision")
        require("type: vless" in profile_text, "plain VLESS inner protocol missing")
    else:
        require(match is not None, "server decryption missing")
        SECRETS.append(match[1].encode())
    require("encryption_limits:" not in profile_text, "must use shoes default limits")
    require("tls_targets:" not in profile_text and "reality_targets:" not in profile_text, "must be native TCP")
    state_bytes = Path("/etc/shoes/ping-rust-state.json").read_bytes()
    safe(state_bytes)
    state = json.loads(state_bytes)
    profiles = [entry["profile"] for entry in state["sudoku_profiles"]] if plain else state["profiles"]
    profile = next(p for p in profiles if p["port"] == port)
    credentials = profile["credentials"]["VlessSudoku" if plain else "VlessEnc"]
    parsed = urllib.parse.urlsplit(uri)
    query = urllib.parse.parse_qs(parsed.query)
    require(parsed.scheme == "vless" and parsed.hostname == "127.0.0.1", "invalid URI authority")
    require(query["security"] == ["none"] and query["type"] == ["tcp"], "invalid URI security or transport")
    require(query.get("flow") == (["xtls-rprx-vision"] if vision else None), "invalid URI Vision")
    encryption = "none" if plain else credentials["encryption"]
    require(query["encryption"] == [encryption], "URI encryption differs from state")
    details = command([PRS, "info", label], label + "-info")
    if plain:
        for text in ("加密：无", "没有任何加密和认证", "目标地址", "非 HTTPS", "VLESS-ENC + Sudoku", "VLESS-REALITY"):
            require(text not in details, "plain VLESS details contain redundant warning")
        require("UUID" in details, "plain VLESS details missing UUID")
    else:
        require("Encryption" in details and mode in details, "details missing encryption or mode")
    if sudoku:
        require("sudoku_mask" in profile_text, "server must have Sudoku mask")
        mask = credentials["sudoku"]
        require(mask["ascii"] == sudoku, "state Sudoku mode differs")
        require(len(mask["password"]) == 24 and mask["password"].isascii()
                and mask["password"].isalnum(), "generated Sudoku password format")
        require("外观：Sudoku" in details, "details missing Sudoku")
        expected = {"tcp": [{"type": "sudoku", "settings": {
            "password": mask["password"], "ascii": sudoku, "paddingMin": 0, "paddingMax": 0}}]}
        require(json.loads(query["fm"][0]) == expected, "URI FinalMask differs from state")
    else:
        require("fm" not in query, "disabled Sudoku must omit fm")
        require("sudoku" not in profile["credentials"]["VlessEnc"], "disabled Sudoku must omit state field")
    targets = ("clash-meta", "sing-box", "nekobox") if sudoku else ("sing-box", "nekobox")
    for target in targets:
        result = subprocess.run([PRS, "export", target, "--profile", profile["id"], "--server", "127.0.0.1"], capture_output=True, timeout=30)
        safe(result.stdout + result.stderr)
        if sudoku:
            require(result.returncode != 0 and "该客户端导出不支持 Xray FinalMask Sudoku，请用分享链接导入 v2rayN 或 Xray ≥ v26.3.27" in result.stderr.decode(), "Sudoku unsupported export must refuse")
        else:
            require(result.returncode != 0 and "不支持 VLESS Encryption" in result.stderr.decode(), "unsupported export must refuse")

    config = WORK / (label + (".json" if client == "xray" else ".yaml"))
    if client == "xray":
        user = {"id": parsed.username, "encryption": encryption}
        if vision:
            user["flow"] = "xtls-rprx-vision"
        xray_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": 18081, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": port, "users": [user]}]}, "streamSettings": {"network": "raw" if plain else "tcp", "security": "none"}}],
        }
        if sudoku:
            xray_config["outbounds"][0]["streamSettings"]["finalmask"] = json.loads(query["fm"][0])
        content = json.dumps(xray_config)
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
    if sudoku:
        # The same working client, with only the mask password changed, must
        # fail before reaching the endpoint. This proves the mask is in use.
        xray_config["outbounds"][0]["streamSettings"]["finalmask"]["tcp"][0]["settings"]["password"] += "Mismatch"
        config.write_text(json.dumps(xray_config))
        before_bad = HITS.count(request_path)
        with client_process(client_args, label + "-wrong-password-client"):
            result = subprocess.run(["curl", "--noproxy", "", "--fail", "--silent", "--show-error",
                                     "--max-time", "8", "--proxy", "socks5h://127.0.0.1:18081",
                                     f"http://127.0.0.1:18080{request_path}"], capture_output=True, timeout=15)
            safe(result.stdout + result.stderr)
            require(result.returncode != 0, "wrong Sudoku password must fail")
        require(HITS.count(request_path) == before_bad, "wrong Sudoku password reached endpoint")
        case_results.append({"case": label + "-wrong-password", "result": "PASS", "endpoint_requests": 0})
        print(label + "-wrong-password: PASS", flush=True)
        if plain:
            # Strip FinalMask entirely: an ordinary unmasked VLESS client must
            # not reach the endpoint, even with the correct UUID.
            del xray_config["outbounds"][0]["streamSettings"]["finalmask"]
            config.write_text(json.dumps(xray_config))
            before_unmasked = HITS.count(request_path)
            with client_process(client_args, label + "-unmasked-client"):
                result = subprocess.run(["curl", "--noproxy", "", "--fail", "--silent", "--show-error",
                                         "--max-time", "8", "--proxy", "socks5h://127.0.0.1:18081",
                                         f"http://127.0.0.1:18080{request_path}"], capture_output=True, timeout=15)
                safe(result.stdout + result.stderr)
                require(result.returncode != 0, "unmasked plain VLESS must fail")
            require(HITS.count(request_path) == before_unmasked, "unmasked plain VLESS reached endpoint")
            case_results.append({"case": label + "-unmasked", "result": "PASS", "endpoint_requests": 0})
            print(label + "-unmasked: PASS", flush=True)
    case_results.append({"case": label, "result": "PASS", "endpoint_requests": 1, "controlled_restart": True, "service_active": True, "new_port_listening": True})
    print(label + ": PASS", flush=True)


def validate_vless_sudoku_results():
    expected = {"xray-vless-plain-sudoku-" + mode for mode in ("prefer_entropy", "ascii")}
    positive = [case for case in VLESS_SUDOKU_RESULTS if case["case"] in expected]
    negative = [case for case in VLESS_SUDOKU_RESULTS if case["case"] not in expected]
    require(len(positive) == 2 and {case["case"] for case in positive} == expected,
            "plain VLESS Sudoku positive matrix incomplete")
    require(all(case["result"] == "PASS" and case["endpoint_requests"] == 1
                and case["controlled_restart"] and case["service_active"] and case["new_port_listening"]
                for case in positive), "plain VLESS Sudoku positive failed")
    expected_negative = {name + suffix for name in expected for suffix in ("-wrong-password", "-unmasked")}
    require(len(negative) == 4 and {case["case"] for case in negative} == expected_negative,
            "plain VLESS Sudoku negative matrix incomplete")
    require(all(case["result"] == "PASS" and case["endpoint_requests"] == 0 for case in negative),
            "plain VLESS Sudoku negative reached endpoint")


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
        for offset, (ascii_mode, vision) in enumerate(
                (ascii_mode, vision) for ascii_mode in ("prefer_entropy", "ascii") for vision in (False, True)):
            test_case("xray", "native", "x25519", vision, len(matrix) + offset, sudoku=ascii_mode)
        for offset, ascii_mode in enumerate(("prefer_entropy", "ascii")):
            test_case("xray", "native", "x25519", False, len(matrix) + 4 + offset,
                      sudoku=ascii_mode, plain=True)
        validate_vless_sudoku_results()
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
        RESULTS.append({"result": "FAIL", "stage": stage, "completed_cases": len(RESULTS) + len(VLESS_SUDOKU_RESULTS)})
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
        report = {"xray": "v26.6.27", "mihomo": "v1.19.33", "shoes": "v0.3.7", "cases": RESULTS, "vless_sudoku_cases": VLESS_SUDOKU_RESULTS, "downgrade": DOWNGRADE, "artifact_secret_audit": status == 0}
        (RECORDS / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        endpoint.shutdown()
        subprocess.run(["systemctl", "stop", "shoes"], capture_output=True, timeout=30)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
