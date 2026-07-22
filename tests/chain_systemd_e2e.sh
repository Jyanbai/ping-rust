#!/usr/bin/env bash
set -Eeuo pipefail

PING_RUST_BIN="${PING_RUST_BIN:-/usr/local/bin/ping-rust}"
SHOES_BIN="${SHOES_BIN:-/usr/local/bin/shoes}"
REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "chain systemd acceptance must run as root" >&2
    exit 1
fi
for command in expect ip python3 curl systemctl base64; do
    command -v "$command" >/dev/null || {
        echo "missing test dependency: $command" >&2
        exit 1
    }
done
[[ -x "$PING_RUST_BIN" ]] || { echo "ping-rust binary missing" >&2; exit 1; }
[[ -x "$SHOES_BIN" ]] || { echo "shoes binary missing" >&2; exit 1; }

work_dir="$(mktemp -d)"
suffix="$$"
namespace_one="pr-chain-a-${suffix}"
namespace_two="pr-chain-b-${suffix}"
root_one="pra${suffix: -5}"
peer_one="pca${suffix: -5}"
root_two="prb${suffix: -5}"
peer_two="pcb${suffix: -5}"
origin_pid=""
upstream_one_pid=""
upstream_two_pid=""
client_pid=""
current_stage="initializing"

show_failure_diagnostics() {
    local line="$1" status="$2"
    echo "chain acceptance failed during '${current_stage}' at line ${line} (exit ${status})" >&2
    for log in upstream-one upstream-two client; do
        if [[ -s "$work_dir/${log}.log" ]]; then
            echo "--- ${log}.log (last 80 lines) ---" >&2
            tail -n 80 "$work_dir/${log}.log" >&2
        fi
    done
    echo "--- shoes.service journal (last 80 lines) ---" >&2
    journalctl -u shoes.service --no-pager -n 80 >&2 || true
}

cleanup() {
    set +e
    [[ -n "$client_pid" ]] && kill "$client_pid" 2>/dev/null
    [[ -n "$upstream_one_pid" ]] && kill "$upstream_one_pid" 2>/dev/null
    [[ -n "$upstream_two_pid" ]] && kill "$upstream_two_pid" 2>/dev/null
    [[ -n "$origin_pid" ]] && kill "$origin_pid" 2>/dev/null
    ip netns delete "$namespace_one" 2>/dev/null
    ip netns delete "$namespace_two" 2>/dev/null
    systemctl disable --now shoes.service >/dev/null 2>&1
    rm -f /etc/systemd/system/shoes.service
    systemctl daemon-reload >/dev/null 2>&1
    rm -rf /etc/shoes "$work_dir"
}
trap 'show_failure_diagnostics "$LINENO" "$?"' ERR
trap cleanup EXIT

choose_ports() {
    python3 - "$@" <<'PY'
import socket
import sys

sockets = []
try:
    for _ in range(int(sys.argv[1])):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
}

current_stage="creating isolated network exits"
read -r origin_port upstream_one_port upstream_two_port client_port server_port < <(choose_ports 5)

ip netns add "$namespace_one"
ip link add "$root_one" type veth peer name "$peer_one"
ip link set "$peer_one" netns "$namespace_one"
ip address add 10.231.1.1/30 dev "$root_one"
ip link set "$root_one" up
ip -n "$namespace_one" link set lo up
ip -n "$namespace_one" address add 10.231.1.2/30 dev "$peer_one"
ip -n "$namespace_one" link set "$peer_one" up
ip -n "$namespace_one" route add default via 10.231.1.1

ip netns add "$namespace_two"
ip link add "$root_two" type veth peer name "$peer_two"
ip link set "$peer_two" netns "$namespace_two"
ip address add 10.231.2.1/30 dev "$root_two"
ip link set "$root_two" up
ip -n "$namespace_two" link set lo up
ip -n "$namespace_two" address add 10.231.2.2/30 dev "$peer_two"
ip -n "$namespace_two" link set "$peer_two" up
ip -n "$namespace_two" route add default via 10.231.2.1

cat >"$work_dir/origin.py" <<'PY'
import http.server
import pathlib
import sys

peer_log = pathlib.Path(sys.argv[2])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        peer_log.write_text(self.client_address[0] + "\n", encoding="utf-8")
        body = b"ping-rust-production-chain"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass

http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
PY
python3 "$work_dir/origin.py" "$origin_port" "$work_dir/peer.log" &
origin_pid=$!

cat >"$work_dir/upstream-one.yaml" <<EOF
- address: 0.0.0.0:${upstream_one_port}
  protocol:
    type: shadowsocks
    cipher: aes-128-gcm
    password: chain-one-password
    udp_enabled: false
  rules:
    - allow-all-direct
EOF
cat >"$work_dir/upstream-two.yaml" <<EOF
- address: 0.0.0.0:${upstream_two_port}
  protocol:
    type: shadowsocks
    cipher: aes-128-gcm
    password: chain-two-password
    udp_enabled: false
  rules:
    - allow-all-direct
EOF
"$SHOES_BIN" --dry-run "$work_dir/upstream-one.yaml" >/dev/null
"$SHOES_BIN" --dry-run "$work_dir/upstream-two.yaml" >/dev/null
ip netns exec "$namespace_one" "$SHOES_BIN" "$work_dir/upstream-one.yaml" \
    >"$work_dir/upstream-one.log" 2>&1 &
upstream_one_pid=$!
ip netns exec "$namespace_two" "$SHOES_BIN" "$work_dir/upstream-two.yaml" \
    >"$work_dir/upstream-two.log" 2>&1 &
upstream_two_pid=$!

wait_port() {
    local host="$1" port="$2"
    for _ in {1..100}; do
        if timeout 1 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    echo "listener did not become ready: ${host}:${port}" >&2
    return 1
}
wait_port 10.231.1.2 "$upstream_one_port"
wait_port 10.231.2.2 "$upstream_two_port"

current_stage="generating deterministic managed Reality listener"
"$PING_RUST_BIN" generate reality \
    --name chain-entry \
    --port "$server_port" \
    --server-name www.cloudflare.com \
    --dest www.cloudflare.com:443 \
    >"$work_dir/bootstrap.out"
rm -f "$work_dir/bootstrap.out"
systemctl is-active --quiet shoes.service
systemctl is-enabled --quiet shoes.service

userinfo_one="$(printf '%s' 'aes-128-gcm:chain-one-password' | base64 -w 0)"
userinfo_two="$(printf '%s' 'aes-128-gcm:chain-two-password' | base64 -w 0)"
uri_one="ss://${userinfo_one}@10.231.1.2:${upstream_one_port}#namespace-one"
uri_two="ss://${userinfo_two}@10.231.2.2:${upstream_two_port}#namespace-two"

current_stage="adding first Shadowsocks chain node"
expect "$REPO_DIR/tests/chain_menu.exp" "$PING_RUST_BIN" add "$uri_one"
current_stage="testing first node with full protocol handshake"
rm -f "$work_dir/peer.log"
PING_RUST_CHAIN_TEST_URL="http://10.231.1.1:${origin_port}/probe" \
    expect "$REPO_DIR/tests/chain_menu.exp" "$PING_RUST_BIN" test 1
[[ "$(tr -d '\r\n' <"$work_dir/peer.log")" == "10.231.1.2" ]]
current_stage="adding second Shadowsocks chain node"
expect "$REPO_DIR/tests/chain_menu.exp" "$PING_RUST_BIN" add "$uri_two"
current_stage="enabling first chain node"
expect "$REPO_DIR/tests/chain_menu.exp" "$PING_RUST_BIN" enable

python3 - "$client_port" >"$work_dir/client.yaml" <<'PY'
import json
import sys

state = json.load(open("/etc/shoes/ping-rust-state.json", encoding="utf-8"))
profile = state["profiles"][0]
credentials = profile["credentials"]["Reality"]
print(f'''- address: 127.0.0.1:{sys.argv[1]}
  protocol:
    type: socks
    udp_enabled: false
  rules:
    - masks: 0.0.0.0/0
      action: allow
      client_chain:
        address: 127.0.0.1:{profile["port"]}
        protocol:
          type: reality
          public_key: {credentials["public_key"]}
          short_id: {credentials["short_id"]}
          sni_hostname: {credentials["server_name"]}
          vision: true
          protocol:
            type: vless
            user_id: {credentials["user_id"]}
            udp_enabled: false
''')
PY
"$SHOES_BIN" --dry-run "$work_dir/client.yaml" >/dev/null
"$SHOES_BIN" "$work_dir/client.yaml" >"$work_dir/client.log" 2>&1 &
client_pid=$!
wait_port 127.0.0.1 "$client_port"

probe_expect_peer() {
    local expected_peer="$1"
    rm -f "$work_dir/peer.log" "$work_dir/body"
    curl --fail --silent --show-error --max-time 10 \
        --socks5-hostname "127.0.0.1:${client_port}" \
        "http://10.231.1.1:${origin_port}/probe" >"$work_dir/body"
    grep -qx 'ping-rust-production-chain' "$work_dir/body"
    for _ in {1..50}; do
        [[ -s "$work_dir/peer.log" ]] && break
        sleep 0.1
    done
    [[ "$(tr -d '\r\n' <"$work_dir/peer.log")" == "$expected_peer" ]] || {
        echo "unexpected origin peer; expected ${expected_peer}" >&2
        return 1
    }
}

probe_must_fail() {
    rm -f "$work_dir/peer.log" "$work_dir/body"
    if curl --fail --silent --show-error --max-time 5 \
        --socks5-hostname "127.0.0.1:${client_port}" \
        "http://10.231.1.1:${origin_port}/probe" >"$work_dir/body" 2>/dev/null; then
        echo "request unexpectedly succeeded while active upstream was offline" >&2
        return 1
    fi
    [[ ! -s "$work_dir/peer.log" ]] || {
        echo "origin received a request while active upstream was offline" >&2
        return 1
    }
}

current_stage="routing through first chain node"
probe_expect_peer 10.231.1.2
current_stage="restarting systemd service"
systemctl restart shoes.service
current_stage="routing through first node after systemd restart"
systemctl is-active --quiet shoes.service
probe_expect_peer 10.231.1.2

kill "$upstream_one_pid"
wait "$upstream_one_pid" 2>/dev/null || true
current_stage="verifying no direct fallback while first node is offline"
upstream_one_pid=""
probe_must_fail

current_stage="switching to second chain node"
expect "$REPO_DIR/tests/chain_menu.exp" "$PING_RUST_BIN" select 2
probe_expect_peer 10.231.2.2

current_stage="disabling chain proxy and restoring direct routing"
expect "$REPO_DIR/tests/chain_menu.exp" "$PING_RUST_BIN" disable
probe_expect_peer 10.231.1.1

current_stage="deleting first chain node"
expect "$REPO_DIR/tests/chain_menu.exp" "$PING_RUST_BIN" delete 1
current_stage="deleting final chain node"
expect "$REPO_DIR/tests/chain_menu.exp" "$PING_RUST_BIN" delete 1
python3 - <<'PY'
import json

state = json.load(open("/etc/shoes/ping-rust-state.json", encoding="utf-8"))
assert state["chain_proxy"]["enabled"] is False
assert state["chain_proxy"].get("active_node") is None
assert state["chain_proxy"].get("nodes", []) == []
PY
! grep -q 'client_chain' /etc/shoes/config.yaml
systemctl restart shoes.service
systemctl is-active --quiet shoes.service

echo "chain systemd acceptance passed"
