#!/usr/bin/env python3
"""Isolated source comparison; credentials are created at runtime and never logged."""

import argparse
import base64
import importlib.util
import json
import os
import secrets
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path


spec = importlib.util.spec_from_file_location("h2mux_fixture", Path(__file__).with_name("validate-h2mux.py"))
h2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h2)


def record(rows, feature, status, evidence):
    row = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "feature": feature,
           "status": status, "evidence": evidence}
    rows.append(row)
    print(json.dumps(row, ensure_ascii=False), flush=True)


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def dry_run(shoes, path):
    return subprocess.run([shoes, "--dry-run", str(path)], capture_output=True, timeout=30).returncode


def chain_case(shoes, root):
    """Authenticated ingress, two authenticated SS hops, pool, BLOCK and DIRECT."""
    a, b, ingress, pool_port = [h2.free_port() for _ in range(4)]
    credentials = [base64.b64encode(secrets.token_bytes(32)).decode() for _ in range(2)]
    hops = [{"address": f"127.0.0.1:{port}", "protocol": {
        "type": "shadowsocks", "cipher": "2022-blake3-aes-256-gcm",
        "password": password, "udp_enabled": False}}
        for port, password in zip((a, b), credentials)]
    upstream = root / "upstreams.json"
    upstream.write_text(json.dumps(hops))
    auth = {"type": "socks", "udp_enabled": False,
            "username": h2.SOCKS_USER, "password": h2.SOCKS_PASSWORD}
    default = {"masks": "0.0.0.0/0", "action": "allow", "client_chains": {"chain": hops}}
    rules = [
        {"masks": "blocked.example.invalid", "action": "block"},
        {"masks": "127.0.0.1/32", "action": "allow", "client_chains": {"protocol": {"type": "direct"}}},
        default,
    ]
    server = root / "chain-v2.json"
    server.write_text(json.dumps([
        {"address": f"127.0.0.1:{ingress}", "protocol": auth, "rules": rules},
        {"address": f"127.0.0.1:{pool_port}", "protocol": auth, "rules": [
            {"masks": "0.0.0.0/0", "action": "allow", "client_chains": {"chain": [{"pool": hops}]}}]},
    ]))
    if dry_run(shoes, upstream) or dry_run(shoes, server):
        return "被 dry-run 拦截", "authenticated SS hops + Pool + ordered BLOCK/DIRECT/default Chain schema rejected"
    processes = []
    with (root / "chain.log").open("wb") as log, h2.socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        port = origin.getsockname()[1]
        done = threading.Event()
        worker = threading.Thread(target=h2.origin, args=(origin, done), daemon=True)
        worker.start()
        try:
            for path in (upstream, server):
                processes.append(subprocess.Popen([shoes, str(path)], stdout=log, stderr=log))
            for port_number in (a, b, ingress, pool_port):
                h2.wait_port(port_number)
            # 127.0.0.1 is DIRECT; localhost remains a domain and uses default Chain.
            request(ingress, "127.0.0.1", port)
            request(ingress, "localhost", port)
            request(pool_port, "localhost", port)
            try:
                request(ingress, "blocked.example.invalid", port)
            except (OSError, AssertionError):
                pass
            else:
                raise AssertionError("BLOCK did not reject request")
            stop(processes[0])
            request(ingress, "127.0.0.1", port)
            try:
                request(ingress, "localhost", port)
            except (OSError, AssertionError):
                pass
            else:
                raise AssertionError("broken Chain silently fell back to DIRECT")
            return "可用", "dry-run + authenticated data: two-hop Chain, Pool, BLOCK, DIRECT survives failed upstream; default fails closed"
        finally:
            for process in processes:
                if process.poll() is None:
                    stop(process)
            done.set()
            worker.join(timeout=2)


def request(proxy_port, host, port):
    with h2.socket.create_connection(("127.0.0.1", proxy_port), 5) as connection:
        connection.settimeout(5)
        connection.sendall(b"\x05\x01\x02")
        assert h2.receive_exact(connection, 2) == b"\x05\x02"
        user, password = h2.SOCKS_USER.encode(), h2.SOCKS_PASSWORD.encode()
        connection.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        assert h2.receive_exact(connection, 2) == b"\x01\x00"
        target = host.encode()
        connection.sendall(b"\x05\x01\x00\x03" + bytes([len(target)]) + target + port.to_bytes(2, "big"))
        reply = h2.receive_exact(connection, 4)
        assert reply[:2] == b"\x05\x00"
        h2.receive_exact(connection, {1: 6, 4: 18}.get(reply[3], 0))
        if reply[3] == 3:
            h2.receive_exact(connection, h2.receive_exact(connection, 1)[0] + 2)
        payload = secrets.token_bytes(256)
        connection.sendall(payload)
        connection.shutdown(h2.socket.SHUT_WR)
        response = bytearray()
        while chunk := connection.recv(4096):
            response.extend(chunk)
        assert response == f"{len(payload)}:{h2.hashlib.sha256(payload).hexdigest()}".encode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, choices=["github-release-v0.2.7", "verified-pin"])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    shoes, binary = os.environ["SHOES_BIN"], os.environ["PING_RUST_BIN"]
    rows = []
    version_probe = subprocess.run([shoes, "--version"], text=True, capture_output=True)
    version = (version_probe.stdout.strip() if version_probe.returncode == 0
               else args.source + " (verified artifact/revision; --version unsupported)")
    print(f"source={args.source}; runtime={version}", flush=True)
    with tempfile.TemporaryDirectory(prefix="prs-source-matrix-") as temporary:
        root = Path(temporary)
        protocols = ["reality", "hysteria2", "tuic", "shadowsocks", "anytls", "vless-tls",
                     "vless-ws-tls", "trojan-tls", "trojan-reality", "vmess-ws-tls", "snell", "socks5", "naiveproxy"]
        for protocol in protocols + ["shadowtls-v3"]:
            path = root / f"{protocol}.yaml"
            command = [binary, "generate", "shadowsocks" if protocol == "shadowtls-v3" else protocol,
                       "--port", str(h2.free_port()), "--output", str(path)]
            if protocol in ("reality", "trojan-reality"):
                command += ["--server-name", "www.cloudflare.com", "--dest", "www.cloudflare.com:443"]
            elif protocol == "shadowtls-v3":
                command += ["--shadowtls", "--server-name", "www.cloudflare.com"]
            elif protocol == "socks5":
                command += ["--username", h2.SOCKS_USER, "--password", h2.SOCKS_PASSWORD]
            elif protocol == "naiveproxy":
                command += ["--server-name", "matrix.example.invalid", "--self-signed"]
            elif protocol not in ("shadowsocks", "snell"):
                command += ["--server-name", "matrix.example.invalid"]
            result = subprocess.run(command, capture_output=True, timeout=90)
            if result.returncode:
                output = (result.stdout + result.stderr).decode(errors="replace")
                if "shoes" not in output or "验证" not in output:
                    raise AssertionError(f"{protocol}: generation failed before known dry-run gate (private output suppressed)")
                record(rows, protocol, "被 dry-run 拦截", f"ping-rust generate {protocol} --output <TEMP>; exit={result.returncode}; shoes candidate validation rejected")
            else:
                assert dry_run(shoes, path) == 0
                record(rows, protocol, "可用", f"ping-rust generate {protocol} --output <TEMP> + shoes --dry-run: exit=0; schema only, external data not verified here")
        status, evidence = chain_case(shoes, root)
        record(rows, "Chain 2.0", status, evidence)
        try:
            h2.main()
        except (OSError, AssertionError, subprocess.SubprocessError) as error:
            record(rows, "H2MUX", "不可用", f"authenticated TLS/WS + sing-box 1.14.2 data probe failed: {type(error).__name__}; private logs not published")
        else:
            record(rows, "H2MUX", "可用", "VMess/VLESS WS TLS + Trojan TLS: small/1MiB half-close, 12 concurrent streams, two hops; sing-box 1.14.2 Trojan small/1MiB passed")
    args.output.write_text(json.dumps({"source": args.source, "version": version, "rows": rows}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
