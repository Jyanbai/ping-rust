#!/usr/bin/env bash
# Backward-compat acceptance: files written by the new build must be read by the
# published v0.2.1 Release binary with identical exports and info except for
# the intentional shoes --version probe introduced by the v0.3.6 upgrade.
# Runs as root inside a disposable systemd container. Placeholder data only.
set -euo pipefail

NEW="${NEW_PING_RUST:-/usr/local/bin/ping-rust}"
OLD_TAG="${OLD_TAG:-v0.2.1}"
WORK="${WORK:-/tmp/compat}"
SERVER="192.0.2.10"
EXPECT_SCRIPT="${EXPECT_SCRIPT:-/workspace/tests/chain_menu.exp}"
export NO_COLOR=1 TERM=dumb
mkdir -p "$WORK/new" "$WORK/old" "$WORK/dl"

echo "== install pinned shoes via new build"
"$NEW" install --method release

echo "== generate profiles with new build"
"$NEW" add reality --port 24431 --name compat-reality --server-address "$SERVER" --yes >/dev/null
"$NEW" add socks5 --port 24432 --name compat-socks5 --server-address "$SERVER" --yes >/dev/null
socks_uri="$("$NEW" url compat-socks5 | grep -Eo 'socks5?://[^[:space:]]+' | head -n1)"
test -n "$socks_uri"
expect "$EXPECT_SCRIPT" "$NEW" add "$socks_uri"
expect "$EXPECT_SCRIPT" "$NEW" enable

ls -la /etc/shoes /etc/shoes/profiles
for f in /etc/shoes/config.yaml /etc/shoes/ping-rust-state.json; do test -s "$f"; done
:
jq -e '.chain_proxy.enabled == true and (.chain_proxy.nodes | length) >= 1' /etc/shoes/ping-rust-state.json >/dev/null \
  || { echo "Chain 2.0 state missing"; jq '.chain_proxy' /etc/shoes/ping-rust-state.json | sed -E 's/"(password|uuid|private_key|key)": "[^"]*"/"\1": "<redacted>"/g'; exit 1; }
mapfile -t ids < <(jq -r '.profiles[].id' /etc/shoes/ping-rust-state.json)
test "${#ids[@]}" -eq 2
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-before"

capture() {
  local bin="$1" out="$2"
  local rc
  rc=0; "$bin" info >"$out/info" 2>&1 || rc=$?; echo "exit=$rc" >>"$out/info"
  for id in "${ids[@]}"; do
    for fmt in clash-meta sing-box nekobox; do
      rc=0
      "$bin" export "$fmt" --profile "$id" --server "$SERVER" >"$out/export-$fmt-$id" 2>&1 || rc=$?
      echo "exit=$rc" >>"$out/export-$fmt-$id"
    done
  done
}
capture "$NEW" "$WORK/new"

echo "== download $OLD_TAG Release and verify SHA256SUMS"
base="https://github.com/Jyanbai/ping-rust/releases/download/$OLD_TAG"
asset="ping-rust-x86_64-unknown-linux-musl.tar.gz"
curl -fsSL --retry 3 -o "$WORK/dl/$asset" "$base/$asset"
curl -fsSL --retry 3 -o "$WORK/dl/SHA256SUMS" "$base/SHA256SUMS"
(cd "$WORK/dl" && grep -E "[[:space:]]\*?$asset\$" SHA256SUMS | sha256sum -c -)
tar -xzf "$WORK/dl/$asset" -C "$WORK/dl"
OLD="$(find "$WORK/dl" -type f -name ping-rust -perm -111 | head -n1)"
test -x "$OLD"
"$OLD" --version | grep -Fx "ping-rust ${OLD_TAG#v}"

capture "$OLD" "$WORK/old"

echo "== compare"
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-after"
diff -u "$WORK/hash-before" "$WORK/hash-after"
python3 "$(dirname "$0")/compare-compat-outputs.py" "$WORK/new" "$WORK/old"
count="$(find "$WORK/new" -type f | wc -l)"
ok="$(grep -lx 'exit=0' "$WORK"/new/* | wc -l)"
echo "$count outputs; $ok exited 0 in both"
grep -x 'exit=0' "$WORK/new/info"
grep -H -v '^exit=0$' -x "$WORK"/new/* /dev/null | grep 'exit=' || true

/usr/local/bin/shoes --dry-run /etc/shoes/config.yaml
echo "backward compatibility: PASS"

# The XHTTP extension must leave legacy profiles readable by the actual v0.2.1
# binary, with identical legacy info/exports and no changes made by reading.
cp /etc/shoes/ping-rust-state.json "$WORK/legacy-state.json"
jq -e 'all(.profiles[]; .credentials | has("VlessXhttpReality") | not)' \
  "$WORK/legacy-state.json" >/dev/null
"$NEW" add vless-xhttp-reality --port 24433 --name compat-xhttp \
  --server-address "$SERVER" --server-name www.cloudflare.com --yes >"$WORK/xhttp-add.txt" 2>&1
python3 - "$WORK/legacy-state.json" /etc/shoes/ping-rust-state.json <<'PY'
import json
import sys
with open(sys.argv[1]) as source:
    before = json.load(source)
with open(sys.argv[2]) as source:
    after = json.load(source)
assert after["profiles"] == before["profiles"]
assert len(after["xhttp_profiles"]) == 1
entry = after["xhttp_profiles"][0]
assert entry["position"] == len(before["profiles"])
assert "VlessXhttpReality" in entry["profile"]["credentials"]
assert after["chain_proxy"] == before["chain_proxy"]
PY
"$NEW" url compat-xhttp >"$WORK/xhttp-url.txt"
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-xhttp-before"
capture "$OLD" "$WORK/old"
grep -x 'exit=0' "$WORK/old/info"
python3 "$(dirname "$0")/compare-compat-outputs.py" "$WORK/new" "$WORK/old"
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-xhttp-after"
diff -u "$WORK/hash-xhttp-before" "$WORK/hash-xhttp-after"
echo 'v0.2.1: legacy info/exports unchanged with XHTTP extension present: PASS'

# VLESS-Sudoku must coexist with XHTTP without exposing an unknown credential
# variant to v0.2.1 or changing any existing profile or chain configuration.
cp /etc/shoes/ping-rust-state.json "$WORK/before-sudoku-state.json"
"$NEW" add vless-sudoku --port 24434 --name compat-sudoku \
  --server-address "$SERVER" --yes >"$WORK/sudoku-add.txt" 2>&1
python3 - "$WORK/before-sudoku-state.json" /etc/shoes/ping-rust-state.json <<'PY'
import json
import sys
with open(sys.argv[1]) as source:
    before = json.load(source)
with open(sys.argv[2]) as source:
    after = json.load(source)
assert after["profiles"] == before["profiles"]
assert after["xhttp_profiles"] == before["xhttp_profiles"]
assert after["chain_proxy"] == before["chain_proxy"]
assert len(after["sudoku_profiles"]) == 1
entry = after["sudoku_profiles"][0]
assert entry["position"] == len(before["profiles"]) + len(before["xhttp_profiles"])
assert "VlessSudoku" in entry["profile"]["credentials"]
PY
"$NEW" url compat-sudoku >"$WORK/sudoku-url.txt"
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-sudoku-before"
capture "$OLD" "$WORK/old"
grep -x 'exit=0' "$WORK/old/info"
python3 "$(dirname "$0")/compare-compat-outputs.py" "$WORK/new" "$WORK/old"
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-sudoku-after"
diff -u "$WORK/hash-sudoku-before" "$WORK/hash-sudoku-after"
echo 'v0.2.1: legacy info/exports unchanged with Sudoku and XHTTP extensions: PASS'

# v0.2.1 ignores the SOCKS5 `listen` extension, so a newly generated anonymous
# node must also persist its loopback address in the legacy client-address field.
"$NEW" generate socks5 --port 24435 --name compat-socks5-no-auth --no-auth \
  >"$WORK/socks5-no-auth-generate.txt" 2>&1
jq -e '.profiles[] | select(.name == "compat-socks5-no-auth") |
  .server_address == "127.0.0.1" and
  .credentials.Socks5.listen.address == "127.0.0.1" and
  .credentials.Socks5.username == null and .credentials.Socks5.password == null' \
  /etc/shoes/ping-rust-state.json >/dev/null
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-socks5-before"
capture_anonymous_socks5() {
  local bin="$1" out="$2"
  mkdir -p "$out"
  "$bin" url compat-socks5-no-auth >"$out/url"
  "$bin" qr compat-socks5-no-auth >"$out/qr"
  "$bin" info compat-socks5-no-auth >"$out/info"
  grep -Eq '^socks5://127\.0\.0\.1:24435#' "$out/url"
  grep -F '客户端地址：127.0.0.1' "$out/info" >/dev/null
  grep -F -f "$out/url" "$out/info" >/dev/null
}
capture_anonymous_socks5 "$NEW" "$WORK/socks5-new"
capture_anonymous_socks5 "$OLD" "$WORK/socks5-old"
diff -u "$WORK/socks5-new/url" "$WORK/socks5-old/url"
diff -u "$WORK/socks5-new/qr" "$WORK/socks5-old/qr"
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-socks5-after"
diff -u "$WORK/hash-socks5-before" "$WORK/hash-socks5-after"
echo 'v0.2.1: anonymous SOCKS5 URL/QR/info preserve loopback address: PASS'

# Exercise the same address-edit menu used by owners before reading with v0.2.1.
# This node was appended last; include extension profiles in the menu count.
socks5_index="$(jq '[.profiles[], .xhttp_profiles[]?.profile, .sudoku_profiles[]?.profile] |
  length' /etc/shoes/ping-rust-state.json)"
edit_socks5() {
  # Inline Expect reads stdin and environment values using the process locale.
  # Debian's default C locale would misdecode the UTF-8 Chinese menu patterns.
  SOCKS5_EDIT_BINARY="$NEW" SOCKS5_EDIT_INDEX="$socks5_index" \
    SOCKS5_EDIT_ACTION="$1" SOCKS5_EDIT_INPUT="$2" SOCKS5_EDIT_RESULT="$3" \
    LC_ALL=C.UTF-8 LANG=C.UTF-8 expect <<'TCL'
set timeout 180
log_user 0
proc expect_or_fail {pattern} {
    expect {
        -re $pattern { return $expect_out(0,string) }
        eof { puts stderr "SOCKS5 address edit ended before $pattern"; exit 1 }
        timeout { puts stderr "SOCKS5 address edit timed out before $pattern"; exit 1 }
    }
}
spawn $env(SOCKS5_EDIT_BINARY)
expect_or_fail {请选择 \[0-10\]: }
send -- "2\r"
expect_or_fail {请选择配置:}
expect_or_fail {请选择 \[0-[0-9]+\]: }
send -- "$env(SOCKS5_EDIT_INDEX)\r"
if {$env(SOCKS5_EDIT_ACTION) eq "authentication"} {
    regexp {^([0-9]+)} [expect_or_fail {[0-9]+\) 更改认证模式}] unused action
} else {
    expect_or_fail {3\) 更改客户端公网地址}
    set action 3
}
expect_or_fail {请选择 \[0-[0-9]+\]: }
send -- "$action\r"
if {$env(SOCKS5_EDIT_ACTION) eq "authentication"} {
    expect_or_fail {启用用户名 \+ 密码认证？}
} else {
    expect_or_fail {VPS 公网域名或 IP（默认：自动检测）（输入 0 返回）：}
}
send -- "$env(SOCKS5_EDIT_INPUT)\r"
expect_or_fail $env(SOCKS5_EDIT_RESULT)
expect_or_fail {按回车返回主菜单}
send -- "\r"
expect_or_fail {请选择 \[0-10\]: }
send -- "0\r"
expect_or_fail {已退出}
expect eof
set result [wait]
if {[lindex $result 2] != 0 || [lindex $result 3] != 0} {
    puts stderr "SOCKS5 address edit menu failed: $result"
    exit 1
}
TCL
}
edit_socks5 address "$SERVER" '安全加固流程'
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-socks5-rejected"
diff -u "$WORK/hash-socks5-after" "$WORK/hash-socks5-rejected"
edit_socks5 address 127.0.0.2 '配置更改成功。'
python3 - <<'PY'
import json
import yaml
with open('/etc/shoes/ping-rust-state.json') as source:
    state = json.load(source)
profile = next(p for p in state['profiles'] if p['name'] == 'compat-socks5-no-auth')
assert profile['server_address'] == '127.0.0.2'
assert profile['credentials']['Socks5']['listen']['address'] == '127.0.0.2'
with open('/etc/shoes/config.yaml') as source:
    servers = yaml.safe_load(source)
assert any(s['address'] == '127.0.0.2:24435' for s in servers)
PY
ss -H -ltn 'sport = :24435' | grep -F '127.0.0.2:24435' >/dev/null
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-socks5-edited-before"
"$NEW" url compat-socks5-no-auth >"$WORK/socks5-new/edited-url"
"$OLD" url compat-socks5-no-auth >"$WORK/socks5-old/edited-url"
grep -Eq '^socks5://127\.0\.0\.2:24435#' "$WORK/socks5-old/edited-url"
diff -u "$WORK/socks5-new/edited-url" "$WORK/socks5-old/edited-url"
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-socks5-edited-after"
diff -u "$WORK/hash-socks5-edited-before" "$WORK/hash-socks5-edited-after"
echo 'v0.2.1: edited anonymous SOCKS5 URL matches loopback listener: PASS'

# Enabling authentication must not allow a loopback listener to advertise a
# public client address, including when rolling back to v0.2.1.
edit_socks5 authentication y '配置更改成功。'
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-socks5-auth-before"
edit_socks5 address "$SERVER" '安全加固流程'
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-socks5-auth-rejected"
diff -u "$WORK/hash-socks5-auth-before" "$WORK/hash-socks5-auth-rejected"
edit_socks5 address 127.0.0.3 '配置更改成功。'
jq -e '.profiles[] | select(.name == "compat-socks5-no-auth") |
  .server_address == "127.0.0.3" and
  .credentials.Socks5.listen.address == "127.0.0.3" and
  (.credentials.Socks5.username | type) == "string" and
  (.credentials.Socks5.password | type) == "string"' \
  /etc/shoes/ping-rust-state.json >/dev/null
python3 - <<'PY'
import yaml
with open('/etc/shoes/config.yaml') as source:
    servers = yaml.safe_load(source)
assert any(s['address'] == '127.0.0.3:24435' for s in servers)
PY
ss -H -ltn 'sport = :24435' | grep -F '127.0.0.3:24435' >/dev/null
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-socks5-auth-edited-before"
"$NEW" url compat-socks5-no-auth >"$WORK/socks5-new/auth-edited-url"
"$OLD" url compat-socks5-no-auth >"$WORK/socks5-old/auth-edited-url"
grep -Eq '^socks5://[^[:space:]@]+@127\.0\.0\.3:24435#' "$WORK/socks5-old/auth-edited-url"
diff -u "$WORK/socks5-new/auth-edited-url" "$WORK/socks5-old/auth-edited-url"
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-socks5-auth-edited-after"
diff -u "$WORK/hash-socks5-auth-edited-before" "$WORK/hash-socks5-auth-edited-after"
echo 'v0.2.1: edited authenticated SOCKS5 URL matches loopback listener: PASS'

# Reproduce a legacy wildcard listener without touching the checked-in fixtures.
"$NEW" generate socks5 --port 24436 --name compat-socks5-legacy --no-auth \
  >"$WORK/socks5-legacy-generate.txt" 2>&1
python3 - <<'PY'
import json
import pathlib
import re

directory = pathlib.Path('/etc/shoes')
state_path = directory / 'ping-rust-state.json'
state = json.loads(state_path.read_text())
profile = next(p for p in state['profiles'] if p['name'] == 'compat-socks5-legacy')
del profile['credentials']['Socks5']['listen']
state_path.write_text(json.dumps(state))

for path in [directory / 'config.yaml', directory / 'profiles/SOCKS5-24436.yaml']:
    # Preserve the aggregate's YAML scalars and the other protocols verbatim.
    contents, count = re.subn(
        rb'(?m)^([ \t]*(?:- )?address: )([\'"]?)127\.0\.0\.1:24436\2$',
        rb'\g<1>\g<2>0.0.0.0:24436\g<2>', path.read_bytes(),
    )
    assert count == 1, 'expected exactly one loopback listener in the generated file'
    path.write_bytes(contents)
PY
systemctl restart shoes.service
for _ in {1..50}; do
  if ss -H -ltn 'sport = :24436' | grep -F '0.0.0.0:24436' >/dev/null; then break; fi
  sleep 0.1
done
ss -H -ltn 'sport = :24436' | grep -F '0.0.0.0:24436' >/dev/null
"$NEW" socks5 secure compat-socks5-legacy --auth --dry-run >"$WORK/socks5-secure-preview.txt"
grep -q '^--- profile' "$WORK/socks5-secure-preview.txt"
# Exercise signal cancellation and an unattended timeout with the same substitute.
(
  shoes=/usr/local/bin/shoes
  scenario="$(mktemp -d /usr/local/lib/socks5-preflight.XXXXXX)"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  mv "$shoes" "$scenario/shoes"
  trap 'mv -f "$scenario/shoes" "$shoes"; rm -rf "$scenario"' EXIT
  cat >"$shoes" <<'PY'
#!/usr/bin/python3
import json
import os
import pathlib
import sys
import time
import yaml

marker = pathlib.Path(os.environ['SOCKS5_PREFLIGHT'])
marker.with_suffix('.entered').touch()
candidate = pathlib.Path(sys.argv[2])
assert sys.argv[1] == '--dry-run'
assert candidate.stat().st_mode & 0o777 == 0o600
servers = yaml.safe_load(candidate.read_text())
protocol = next(s['protocol'] for s in servers if s['address'] == '0.0.0.0:24436')
assert protocol['type'] == 'socks' and protocol['username'] and protocol['password']
marker.with_suffix('.tmp').write_text(json.dumps([os.getpid(), str(candidate)]))
marker.with_suffix('.tmp').replace(marker)
time.sleep(60)
marker.with_suffix('.finished').touch()
PY
  chmod 0755 "$shoes"
  python3 - "$NEW" "$scenario" <<'PY'
import fcntl
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

for sig in (signal.SIGINT, signal.SIGTERM, None):
    marker = pathlib.Path(sys.argv[2]) / (sig.name if sig else 'timeout')
    proc = subprocess.Popen(
        [sys.argv[1], 'socks5', 'secure', 'compat-socks5-legacy', '--auth', '--yes'],
        env={**os.environ, 'SOCKS5_PREFLIGHT': str(marker)},
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    child = None
    try:
        deadline = time.monotonic() + 10
        while not marker.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.exists(), (
            'shoes did not receive a credential-bearing candidate '
            f'(substitute entered={marker.with_suffix(".entered").exists()}, CLI exit={proc.poll()})'
        )
        child, candidate = json.loads(marker.read_text())
        if sig is None:
            _, stderr = proc.communicate(timeout=30)
            assert proc.returncode == 1, 'stalled dry-run did not fail on its own'
            assert 'shoes 配置校验超时' in stderr.decode(), 'missing dry-run timeout error'
        else:
            proc.send_signal(sig)
            assert proc.wait(timeout=5) == 128 + sig
        assert not pathlib.Path(candidate).exists(), 'candidate survived cancellation'
        assert not pathlib.Path(f'/proc/{child}').exists(), 'dry-run survived cancellation'
        assert not marker.with_suffix('.finished').exists(), 'dry-run finished after cancellation'
        with open('/run/lock/ping-rust.lock', 'rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        child = None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if child is not None:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
PY
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"
)
echo 'SOCKS5 preflight: SIGINT, SIGTERM and timeout remove the candidate and stop dry-run: PASS'

# Exercise an actual systemd stop whose client exits before ExecStop finishes.
(
  systemctl_bin="$(command -v systemctl)"
  # /run can be mounted noexec, and shoes.service has its own /tmp.
  scenario="$(mktemp -d /usr/local/lib/socks5-rollback.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d
  mkdir -p "$dropin"
  trap 'rm -f "$dropin/90-compat-socks5-rollback.conf"; "$systemctl_bin" daemon-reload; rm -rf "$scenario"' EXIT
  cat >"$scenario/systemctl" <<'SH'
#!/bin/sh
case "$1" in
  probe)
    exit 0
    ;;
  restart)
    # Start the candidate, then report a client error to trigger rollback.
    if [ ! -e "$SOCKS5_ROLLBACK/activation-failed" ]; then
      "$SOCKS5_SYSTEMCTL" "$@" || exit $?
      touch "$SOCKS5_ROLLBACK/activation-failed"
      exit 1
    fi
    ;;
  stop)
    echo "$$" >"$SOCKS5_ROLLBACK/stop-client"
    ;;
esac
exec "$SOCKS5_SYSTEMCTL" "$@"
SH
  cat >"$scenario/exec-stop" <<'SH'
#!/bin/sh
[ -s "$1/stop-client" ] || exit 0
read -r client <"$1/stop-client"
touch "$1/stop-entered"
while kill -0 "$client" 2>/dev/null; do sleep 0.1; done
touch "$1/stop-after-client"
SH
  cat >"$scenario/exec-start-pre" <<'SH'
#!/bin/sh
set -eu
"$1" info compat-socks5-legacy >"$2/info"
grep -Fq '用户名：无认证' "$2/info"
echo ok >>"$2/start-pre-runs"
SH
  chmod 0755 "$scenario/systemctl" "$scenario/exec-stop" "$scenario/exec-start-pre"
  env PATH="$scenario:$PATH" systemctl probe
  cat >"$dropin/90-compat-socks5-rollback.conf" <<EOF
[Service]
TimeoutStartSec=10s
TimeoutStopSec=150s
ReadWritePaths=$scenario
ExecStartPre=$scenario/exec-start-pre $NEW $scenario
ExecStop=$scenario/exec-stop $scenario
EOF
  "$systemctl_bin" daemon-reload
  before_pid="$("$systemctl_bin" show --property=MainPID --value shoes.service)"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  if PATH="$scenario:$PATH" SOCKS5_ROLLBACK="$scenario" SOCKS5_SYSTEMCTL="$systemctl_bin" \
    "$NEW" socks5 secure compat-socks5-legacy --auth --yes >"$WORK/socks5-stop-rollback.txt" 2>&1; then
    echo 'Expected SOCKS5 activation to fail' >&2
    exit 1
  fi
  test -f "$scenario/activation-failed"
  test "$(grep -c '^ok$' "$scenario/start-pre-runs")" -eq 2
  test -f "$scenario/stop-entered"
  for _ in {1..50}; do
    [[ -f "$scenario/stop-after-client" ]] && break
    sleep 0.1
  done
  test -f "$scenario/stop-after-client"
  "$systemctl_bin" is-active --quiet shoes.service
  after_pid="$("$systemctl_bin" show --property=MainPID --value shoes.service)"
  test "$after_pid" != "$before_pid"
  grep -Fq '原配置、防火墙及服务已恢复并再次验证' "$WORK/socks5-stop-rollback.txt"
  ss -H -ltn 'sport = :24436' | grep -F '0.0.0.0:24436' >/dev/null
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"
)
echo 'SOCKS5 rollback: ExecStartPre reads published state and systemd restores service after slow stop: PASS'

# A referenced, stopped unit keeps its start-rate counter. Inject a firewall
# error only after systemd has started the loopback candidate and it passes verification.
(
  scenario="$(mktemp -d /usr/local/lib/socks5-start-limit.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d/90-compat-socks5-start-limit.conf
  target=/run/systemd/system/compat-socks5-rollback.target
  trap 'systemctl stop "${target##*/}" || true; rm -f "$dropin" "$target"; systemctl daemon-reload; rm -rf "$scenario"' EXIT
  cat >"$target" <<'EOF'
[Unit]
Description=Keep shoes.service loaded during SOCKS5 rollback
Wants=shoes.service
EOF
  cat >"$dropin" <<'EOF'
[Unit]
StartLimitIntervalSec=10min
StartLimitBurst=1
EOF
  cat >"$scenario/iptables" <<'SH'
#!/bin/sh
set -eu
case "$*" in
  --version) echo 'iptables v1.8.9 (legacy)' ;;
  '-w -S INPUT') echo '-A INPUT -p tcp --dport 24436 -j ACCEPT' ;;
  '-w -D INPUT -p tcp --dport 24436 -j ACCEPT')
    touch "$SOCKS5_ROLLBACK/firewall-reached"
    exit 1
    ;;
  *) exit 2 ;;
esac
SH
  chmod 0755 "$scenario/iptables"
  systemctl daemon-reload
  systemctl start "${target##*/}"
  systemctl is-active --quiet "${target##*/}"
  systemctl is-active --quiet shoes.service
  before_pid="$(systemctl show --property=MainPID --value shoes.service)"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  if PATH="$scenario:$PATH" SOCKS5_ROLLBACK="$scenario" \
    "$NEW" socks5 secure compat-socks5-legacy --local --yes >"$WORK/socks5-start-limit.txt" 2>&1; then
    echo 'Expected SOCKS5 firewall change to fail' >&2
    exit 1
  fi
  test -f "$scenario/firewall-reached"
  systemctl is-active --quiet shoes.service
  test "$(systemctl show --property=MainPID --value shoes.service)" != "$before_pid"
  grep -Fq '原配置、防火墙及服务已恢复并再次验证' "$WORK/socks5-start-limit.txt"
  ss -H -ltn 'sport = :24436' | grep -F '0.0.0.0:24436' >/dev/null
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"
)
echo 'SOCKS5 rollback: an inactive unit with StartLimitBurst=1 restarts after firewall failure: PASS'
