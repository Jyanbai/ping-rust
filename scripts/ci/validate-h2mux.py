#!/usr/bin/env python3
"""Exercise pinned shoes H2MUX over the product's TLS and WebSocket stacks."""

import concurrent.futures
import copy
import hashlib
import json
import os
import secrets
import uuid
import datetime
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


USER_ID = str(uuid.uuid4())
PASSWORD = secrets.token_urlsafe(24)
SOCKS_USER = secrets.token_hex(8)
SOCKS_PASSWORD = secrets.token_urlsafe(24)
HOST = "h2mux.example.com"


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_port(port):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"shoes did not listen on {port}")


def receive_exact(sock, count):
    result = bytearray()
    while len(result) < count:
        block = sock.recv(count - len(result))
        if not block:
            raise AssertionError(f"premature EOF after {len(result)} of {count} bytes")
        result.extend(block)
    return bytes(result)


def origin(listener, stop):
    listener.settimeout(0.2)
    while not stop.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        threading.Thread(target=serve_origin, args=(connection,), daemon=True).start()


def serve_origin(connection):
    with connection:
        connection.settimeout(12)
        body = bytearray()
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            body.extend(chunk)
        connection.sendall(f"{len(body)}:{hashlib.sha256(body).hexdigest()}".encode())


def through_socks(proxy_port, origin_port, payload):
    with socket.create_connection(("127.0.0.1", proxy_port), 5) as connection:
        connection.settimeout(20)
        connection.sendall(b"\x05\x01\x02")
        assert receive_exact(connection, 2) == b"\x05\x02"
        user, password = SOCKS_USER.encode(), SOCKS_PASSWORD.encode()
        connection.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        assert receive_exact(connection, 2) == b"\x01\x00"
        connection.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + origin_port.to_bytes(2, "big"))
        reply = receive_exact(connection, 4)
        assert reply[:2] == b"\x05\x00", f"SOCKS connect failed: {reply!r}"
        if reply[3] == 1:
            receive_exact(connection, 6)
        elif reply[3] == 4:
            receive_exact(connection, 18)
        elif reply[3] == 3:
            length = receive_exact(connection, 1)[0]
            receive_exact(connection, length + 2)
        else:
            raise AssertionError(f"invalid SOCKS reply address: {reply!r}")
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        response = bytearray()
        while chunk := connection.recv(4096):
            response.extend(chunk)
        expected = f"{len(payload)}:{hashlib.sha256(payload).hexdigest()}".encode()
        assert response == expected, f"half-close/truncation: {response!r} != {expected!r}"


def protocol_yaml(kind, h2mux):
    options = {"max_connections": h2mux[0], "min_streams": h2mux[1], "max_streams": 0, "padding": h2mux[2]}
    if kind == "vmess":
        inner = {"type": "vmess", "cipher": "any", "user_id": USER_ID, "udp_enabled": False}
    elif kind == "vless":
        inner = {"type": "vless", "user_id": USER_ID, "udp_enabled": False}
    else:
        inner = {"type": "trojan", "password": PASSWORD}
    inner["h2mux"] = options
    if kind != "trojan":
        inner = {"type": "websocket", "matching_path": f"/{kind}", "protocol": inner}
    return inner


def run_case(shoes, directory, kind, options, cert, key, origin_port):
    server_port, proxy_port = free_port(), free_port()
    second_port = free_port() if kind == "vmess" else None
    if kind == "trojan":
        server_inner = {"type": "trojan", "password": PASSWORD}
        client_inner = protocol_yaml(kind, options)
        alpn = ["h2", "http/1.1"]
    else:
        server_leaf = ({"type": "vmess", "cipher": "any", "user_id": USER_ID, "udp_enabled": False} if kind == "vmess" else {"type": "vless", "user_id": USER_ID, "udp_enabled": False})
        server_inner = {"type": "websocket", "targets": [{"matching_path": f"/{kind}", "protocol": server_leaf}]}
        client_inner = protocol_yaml(kind, options)
        alpn = ["http/1.1"]
    server = [{"address": f"127.0.0.1:{server_port}", "protocol": {"type": "tls", "tls_targets": {HOST: {"cert": cert.as_posix(), "key": key.as_posix(), "alpn_protocols": alpn, "protocol": server_inner}}}}]
    outbound = {"address": f"127.0.0.1:{server_port}", "protocol": {"type": "tls", "verify": False, "sni_hostname": HOST, "alpn_protocols": alpn, "protocol": client_inner}}
    if second_port is not None:
        server.append({"address": f"127.0.0.1:{second_port}", "protocol": {"type": "socks", "udp_enabled": False, "username": SOCKS_USER, "password": SOCKS_PASSWORD}})
        outbound = {"chain": [outbound, {"address": f"127.0.0.1:{second_port}", "protocol": {"type": "socks", "username": SOCKS_USER, "password": SOCKS_PASSWORD}}]}
    client = [{"address": f"127.0.0.1:{proxy_port}", "protocol": {"type": "socks", "udp_enabled": False, "username": SOCKS_USER, "password": SOCKS_PASSWORD}, "rules": [{"masks": "0.0.0.0/0", "action": "allow", "client_chains": outbound}]}]
    server_path = directory / f"{kind}-server.yaml"
    client_path = directory / f"{kind}-client.yaml"
    server_path.write_text(json.dumps(server))
    client_path.write_text(json.dumps(client))
    for path in (server_path, client_path):
        subprocess.run([shoes, "--dry-run", str(path)], check=True)
    if kind == "trojan":
        stream_mode = copy.deepcopy(client)
        stream_mux = stream_mode[0]["rules"][0]["client_chains"]["protocol"]["protocol"]["h2mux"]
        stream_mux.update({"max_connections": 0, "min_streams": 0, "max_streams": 8})
        stream_path = directory / "trojan-stream-mode.yaml"
        stream_path.write_text(json.dumps(stream_mode))
        subprocess.run([shoes, "--dry-run", str(stream_path)], check=True)
    with (directory / f"{kind}-server.log").open("wb") as server_log, (directory / f"{kind}-client.log").open("wb") as client_log:
        server_proc = subprocess.Popen([shoes, str(server_path)], stdout=server_log, stderr=subprocess.STDOUT)
        client_proc = subprocess.Popen([shoes, str(client_path)], stdout=client_log, stderr=subprocess.STDOUT)
        try:
            wait_port(server_port)
            if second_port is not None:
                wait_port(second_port)
            wait_port(proxy_port)
            through_socks(proxy_port, origin_port, b"small half-close payload")
            through_socks(proxy_port, origin_port, bytes(range(256)) * 4096)
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                futures = [executor.submit(through_socks, proxy_port, origin_port, f"stream-{index}".encode() * 1024) for index in range(12)]
                for future in futures:
                    future.result()
            print(f"PASS {kind}: TLS product transport, small/1 MiB half-close, 12 concurrent streams, padding={options[2]}, multi-hop={second_port is not None}")
            sing_box = os.environ.get("PING_RUST_SING_BOX_BIN")
            if kind == "trojan" and sing_box:
                sing_port = free_port()
                sing_config = {"inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": sing_port, "users": [{"username": SOCKS_USER, "password": SOCKS_PASSWORD}]}], "outbounds": [{"type": "trojan", "tag": "out", "server": "127.0.0.1", "server_port": server_port, "password": PASSWORD, "tls": {"enabled": True, "server_name": HOST, "insecure": True, "alpn": alpn}, "multiplex": {"enabled": True, "protocol": "h2mux", "max_connections": options[0], "min_streams": options[1], "max_streams": 0, "padding": options[2]}}], "route": {"final": "out"}}
                sing_path = directory / "sing-box-trojan.json"
                sing_path.write_text(json.dumps(sing_config))
                subprocess.run([sing_box, "check", "-c", str(sing_path)], check=True)
                with (directory / "sing-box.log").open("wb") as sing_log:
                    sing_process = subprocess.Popen([sing_box, "run", "-c", str(sing_path)], stdout=sing_log, stderr=subprocess.STDOUT)
                    try:
                        wait_port(sing_port)
                        through_socks(sing_port, origin_port, b"sing-box half-close")
                        through_socks(sing_port, origin_port, bytes(range(256)) * 4096)
                        print("PASS sing-box 1.14.2 -> pinned shoes Trojan H2MUX: small/1 MiB half-close")
                    except Exception:
                        print("sing-box data-plane failed (private log retained until fixture cleanup)")
                        raise
                    finally:
                        sing_process.terminate()
                        try:
                            sing_process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            sing_process.kill()
                            sing_process.wait()
        except Exception:
            print(f"{kind} server/client data-plane failed (private logs retained until fixture cleanup)")
            raise
        finally:
            for process in (client_proc, server_proc):
                process.terminate()
            for process in (client_proc, server_proc):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    shoes = os.environ.get("PING_RUST_SHOES_E2E_BIN") or os.environ.get("SHOES_BIN") or "shoes"
    with tempfile.TemporaryDirectory(prefix="ping-rust-h2mux-") as temporary:
        directory = Path(temporary)
        cert, key = directory / "cert.pem", directory / "key.pem"
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, HOST)])
            certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(private_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
                .sign(private_key, hashes.SHA256()))
            key.write_bytes(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            origin_port = listener.getsockname()[1]
            stop = threading.Event()
            worker = threading.Thread(target=origin, args=(listener, stop), daemon=True)
            worker.start()
            try:
                for kind, options in (("vmess", (4, 4, False)), ("vless", (4, 4, False)), ("trojan", (2, 2, True))):
                    run_case(shoes, directory, kind, options, cert, key, origin_port)
            finally:
                stop.set()
                worker.join(timeout=2)


if __name__ == "__main__":
    main()
