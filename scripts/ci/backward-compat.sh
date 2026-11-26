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
profile['server_address'] = 'example.com'
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
legacy_socks5_id="$(jq -er '.profiles[] | select(.name == "compat-socks5-legacy") | .id' /etc/shoes/ping-rust-state.json)"
systemctl restart shoes.service
for _ in {1..50}; do
  if ss -H -ltn 'sport = :24436' | grep -F '0.0.0.0:24436' >/dev/null; then break; fi
  sleep 0.1
done
ss -H -ltn 'sport = :24436' | grep -F '0.0.0.0:24436' >/dev/null
"$NEW" socks5 secure compat-socks5-legacy --auth --dry-run >"$WORK/socks5-secure-preview.txt"
grep -q '^--- profile' "$WORK/socks5-secure-preview.txt"

write_failing_socks5_iptables() {
  cat >"$1/iptables" <<'SH'
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
  chmod 0755 "$1/iptables"
}

# Inject a unit change at the first restart, after the loaded command has passed preflight.
write_socks5_restart_override() {
  cat >"$1/systemctl" <<'SH'
#!/bin/sh
set -eu
override="${0%/*}/restart.conf"
if [ "$1" = restart ] && [ -f "$override" ]; then
  mv "$override" "$SOCKS5_RESTART_DROPIN"
  "$SOCKS5_SYSTEMCTL" daemon-reload
fi
exec "$SOCKS5_SYSTEMCTL" "$@"
SH
  chmod 0755 "$1/systemctl"
}

# The running unit can still be using a configuration with a narrower listener.
(
  scenario="$(mktemp -d /usr/local/lib/socks5-listener-drift.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d/90-compat-socks5-listener.conf
  mkdir -p "${dropin%/*}"
  trap 'rm -f "$dropin"; systemctl daemon-reload; systemctl restart shoes.service; rm -rf "$scenario"' EXIT
  sed 's/0\.0\.0\.0:24436/127.0.0.1:24436/' /etc/shoes/config.yaml >"$scenario/config.yaml"
  chmod 0600 "$scenario/config.yaml"
  cat >"$dropin" <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/shoes $scenario/config.yaml
EOF
  systemctl daemon-reload
  systemctl restart shoes.service
  for _ in {1..50}; do
    if ss -H -ltn 'sport = :24436' | grep -Fq '127.0.0.1:24436'; then break; fi
    sleep 0.1
  done
  ss -H -ltn 'sport = :24436' | grep -Fq '127.0.0.1:24436'
  rm "$dropin"
  systemctl daemon-reload
  before_pid="$(systemctl show --property=MainPID --value shoes.service)"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  write_failing_socks5_iptables "$scenario"
  for mode in --auth --local; do
    if PATH="$scenario:$PATH" SOCKS5_ROLLBACK="$scenario" \
      "$NEW" socks5 secure "$legacy_socks5_id" "$mode" --yes >"$scenario/result" 2>&1; then
      echo "Expected SOCKS5 $mode hardening to reject listener drift" >&2
      exit 1
    fi
    grep -Fq '实际监听地址不符合预期' "$scenario/result"
    test ! -e "$scenario/firewall-reached"
    test "$(systemctl show --property=MainPID --value shoes.service)" = "$before_pid"
    ss -H -ltn 'sport = :24436' | grep -Fq '127.0.0.1:24436'
    find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
    diff -u "$scenario/before" "$scenario/after"
  done
)
echo 'SOCKS5 auth and local: reject drift between the running and managed listener: PASS'

check_other_reality_drift() (
  kind="$1"
  scenario="$(mktemp -d /usr/local/lib/socks5-other-reality.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d/90-compat-socks5-other-reality.conf
  trap 'rm -f "$dropin"; systemctl daemon-reload; systemctl restart shoes.service; rm -rf "$scenario"' EXIT
  umask 077
  reality_port=24431
  if [[ "$kind" == port ]]; then reality_port=24437; fi
  python3 - "$scenario/config.yaml" "$kind" "$reality_port" <<'PY'
import sys
import uuid

import yaml

with open('/etc/shoes/config.yaml') as source:
    servers = yaml.safe_load(source)
reality, = (server for server in servers if server['address'] == '0.0.0.0:24431')
if sys.argv[2] == 'port':
    reality['address'] = f'0.0.0.0:{sys.argv[3]}'
else:
    target, = reality['protocol']['reality_targets'].values()
    protocol = target['protocol']
    assert 'user_id' in protocol
    protocol['user_id'] = str(uuid.uuid4())
with open(sys.argv[1], 'w') as output:
    yaml.safe_dump(servers, output)
PY
  cat >"$dropin" <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/shoes $scenario/config.yaml
EOF
  systemctl daemon-reload
  systemctl restart shoes.service
  # The target is loaded after the drifted Reality listener.
  for _ in {1..50}; do
    if ss -H -ltn "sport = :$reality_port" | grep -Fq "0.0.0.0:$reality_port" &&
       ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'; then break; fi
    sleep 0.1
  done
  ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436' ||
    { echo 'Target SOCKS5 listener did not start' >&2; exit 1; }
  ss -H -ltn "sport = :$reality_port" | grep -Fq "0.0.0.0:$reality_port" ||
    { echo 'Drifted Reality listener did not start' >&2; exit 1; }
  rm "$dropin"
  systemctl daemon-reload
  before_pid="$(systemctl show --property=MainPID --value shoes.service)"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  if "$NEW" socks5 secure "$legacy_socks5_id" --auth --yes >"$scenario/result" 2>&1; then
    echo "Expected SOCKS5 hardening to reject Reality $kind drift" >&2
    exit 1
  fi
  if [[ "$kind" == port ]]; then
    # anyhow prints the context and the missing port on separate lines.
    grep -Fq '原监听与受管配置不一致' "$scenario/result" ||
      { echo 'Missing listener drift diagnostic' >&2; exit 1; }
    grep -Fq '未找到 shoes 的预期监听 0.0.0.0:24431' "$scenario/result" ||
      { echo 'Listener drift diagnostic did not identify the managed Reality port' >&2; exit 1; }
  else
    grep -Fq '原 shoes 进程未使用受管聚合配置' "$scenario/result"
  fi
  test "$(systemctl show --property=MainPID --value shoes.service)" = "$before_pid"
  ss -H -ltn "sport = :$reality_port" | grep -Fq "0.0.0.0:$reality_port"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"
)
check_other_reality_drift port
echo 'SOCKS5 auth: reject drift on the Reality listener with an unchanged target: PASS'
check_other_reality_drift uuid
echo 'SOCKS5 auth: reject a different Reality UUID on the same running listener: PASS'

# Keep shoes on the original credentials while changing only the managed file.
(
  scenario="$(mktemp -d /usr/local/lib/socks5-reality-uuid.XXXXXX)"
  umask 077
  cp -a /etc/shoes "$scenario/original"
  trap 'cp -a "$scenario/original/." /etc/shoes/; systemctl restart shoes.service; rm -rf "$scenario"' EXIT
  for _ in {1..50}; do
    if ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'; then break; fi
    sleep 0.1
  done
  ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'
  before_pid="$(systemctl show --property=MainPID --value shoes.service)"
  ss -H -ltn 'sport = :24431' | grep -Fq '0.0.0.0:24431'
  "$NEW" url compat-reality >"$scenario/before-url"
  python3 - <<'PY'
import json
import mmap
import uuid

with open('/etc/shoes/ping-rust-state.json') as source:
    state = json.load(source)
profile, = (profile for profile in state['profiles'] if profile['port'] == 24431)
original = profile['credentials']['Reality']['user_id'].encode()
replacement = str(uuid.uuid4()).encode()
assert len(original) == len(replacement) and original != replacement
# Mapped writes keep the inode and let the running listener retain its loaded config.
with open('/etc/shoes/config.yaml', 'r+b') as source, mmap.mmap(source.fileno(), 0) as config:
    offset = config.find(original)
    assert offset >= 0 and config.find(original, offset + len(original)) < 0
    config[offset:offset + len(original)] = replacement
    config.flush()
PY
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  if "$NEW" socks5 secure "$legacy_socks5_id" --auth --yes >"$scenario/result" 2>&1; then
    echo 'Expected SOCKS5 hardening to reject Reality UUID drift in the managed file' >&2
    exit 1
  fi
  grep -Fq '端口 24431 的 Reality 凭据与管理状态不一致' "$scenario/result"
  test "$(systemctl show --property=MainPID --value shoes.service)" = "$before_pid"
  ss -H -ltn 'sport = :24431' | grep -Fq '0.0.0.0:24431'
  "$NEW" url compat-reality >"$scenario/after-url"
  cmp -s "$scenario/before-url" "$scenario/after-url"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"
)
echo 'SOCKS5 auth: reject Reality UUID drift in the managed file without restarting shoes: PASS'

# Keep the native Shadowsocks listener on its original password while changing the managed file.
(
  scenario="$(mktemp -d /usr/local/lib/socks5-shadowsocks-password.XXXXXX)"
  umask 077
  cp -a /etc/shoes "$scenario/original"
  trap 'rm -f /etc/shoes/profiles/SHADOWSOCKS-24438.yaml; cp -a "$scenario/original/." /etc/shoes/; systemctl restart shoes.service; rm -rf "$scenario"' EXIT
  "$NEW" add shadowsocks --port 24438 --name compat-shadowsocks --server-address "$SERVER" --yes >/dev/null
  for _ in {1..50}; do
    if ss -H -ltn 'sport = :24438' | grep -Fq '0.0.0.0:24438'; then break; fi
    sleep 0.1
  done
  ss -H -ltn 'sport = :24438' | grep -Fq '0.0.0.0:24438'
  before_pid="$(systemctl show --property=MainPID --value shoes.service)"
  shadowsocks_id="$(jq -er '.profiles[] | select(.name == "compat-shadowsocks") | .id' /etc/shoes/ping-rust-state.json)"
  "$NEW" url compat-shadowsocks >"$scenario/before-url"
  "$NEW" export sing-box --profile "$shadowsocks_id" --server "$SERVER" >"$scenario/before-export"
  jq -e '[.outbounds[] | select(.type == "shadowsocks" and .server_port == 24438)] | length == 1' \
    "$scenario/before-export" >/dev/null
  python3 - <<'PY'
import base64
import json
import mmap

with open('/etc/shoes/ping-rust-state.json') as source:
    state = json.load(source)
profile, = (profile for profile in state['profiles'] if profile['port'] == 24438)
original = profile['credentials']['Shadowsocks']['password'].encode()
replacement = base64.b64encode(bytes(32))
assert len(original) == len(replacement) and original != replacement
with open('/etc/shoes/config.yaml', 'r+b') as source, mmap.mmap(source.fileno(), 0) as config:
    offset = config.find(original)
    assert offset >= 0 and config.find(original, offset + len(original)) < 0
    config[offset:offset + len(original)] = replacement
    config.flush()
PY
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  if "$NEW" socks5 secure "$legacy_socks5_id" --auth --yes >"$scenario/result" 2>&1; then
    echo 'Expected SOCKS5 hardening to reject native Shadowsocks password drift' >&2
    exit 1
  fi
  grep -Fq '端口 24438 的 Shadowsocks 配置与管理状态不一致' "$scenario/result"
  test "$(systemctl show --property=MainPID --value shoes.service)" = "$before_pid"
  ss -H -ltn 'sport = :24438' | grep -Fq '0.0.0.0:24438'
  "$NEW" url compat-shadowsocks >"$scenario/after-url"
  "$NEW" export sing-box --profile "$shadowsocks_id" --server "$SERVER" >"$scenario/after-export"
  cmp -s "$scenario/before-url" "$scenario/after-url"
  cmp -s "$scenario/before-export" "$scenario/after-export"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"
)
echo 'SOCKS5 auth: reject same-path native Shadowsocks password drift before restart or writes: PASS'

# Keep Snell on its original PSK while changing only the managed file.
(
  scenario="$(mktemp -d /usr/local/lib/socks5-snell-password.XXXXXX)"
  umask 077
  cp -a /etc/shoes "$scenario/original"
  trap 'rm -f /etc/shoes/profiles/SNELL-24439.yaml; cp -a "$scenario/original/." /etc/shoes/; systemctl restart shoes.service; rm -rf "$scenario"' EXIT
  "$NEW" add snell --port 24439 --name compat-snell --server-address "$SERVER" --yes >/dev/null
  for _ in {1..50}; do
    if ss -H -ltn 'sport = :24439' | grep -Fq '0.0.0.0:24439'; then break; fi
    sleep 0.1
  done
  ss -H -ltn 'sport = :24439' | grep -Fq '0.0.0.0:24439'
  before_pid="$(systemctl show --property=MainPID --value shoes.service)"
  snell_id="$(jq -er '.profiles[] | select(.name == "compat-snell") | .id' /etc/shoes/ping-rust-state.json)"
  "$NEW" export clash-meta --profile "$snell_id" --server "$SERVER" >"$scenario/before-export"
  python3 - "$scenario/before-export" <<'PY'
import json
import mmap
import sys

import yaml

with open('/etc/shoes/ping-rust-state.json') as source:
    profile, = (p for p in json.load(source)['profiles'] if p['name'] == 'compat-snell')
password = profile['credentials']['Snell']['password']
with open(sys.argv[1]) as source:
    proxy, = yaml.safe_load(source)['proxies']
assert proxy['type'] == 'snell' and proxy['psk'] == password
original = password.encode()
replacement = (b'b' if original.startswith(b'a') else b'a') + original[1:]
with open('/etc/shoes/config.yaml', 'r+b') as source, mmap.mmap(source.fileno(), 0) as config:
    offset = config.find(original)
    assert offset >= 0 and config.find(original, offset + len(original)) < 0
    config[offset:offset + len(original)] = replacement
    config.flush()
PY
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  if "$NEW" socks5 secure "$legacy_socks5_id" --auth --yes >"$scenario/result" 2>&1; then
    echo 'Expected SOCKS5 hardening to reject Snell password drift' >&2
    exit 1
  fi
  grep -Fq '端口 24439 的 Snell 配置与管理状态不一致' "$scenario/result"
  test "$(systemctl show --property=MainPID --value shoes.service)" = "$before_pid"
  ss -H -ltn 'sport = :24439' | grep -Fq '0.0.0.0:24439'
  "$NEW" export clash-meta --profile "$snell_id" --server "$SERVER" >"$scenario/after-export"
  cmp -s "$scenario/before-export" "$scenario/after-export"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"
)
echo 'SOCKS5 auth: reject Snell PSK drift before restart or writes: PASS'

# Reload the default ExecStart while the authenticated process still owns the
# same wildcard listener that the managed configuration would start anonymously.
(
  scenario="$(mktemp -d /usr/local/lib/socks5-auth-drift.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d/90-compat-socks5-auth-drift.conf
  mkdir -p "${dropin%/*}"
  trap 'rm -f "$dropin"; systemctl daemon-reload; systemctl restart shoes.service; rm -rf "$scenario"' EXIT
  python3 - /etc/shoes/config.yaml "$scenario/config.yaml" <<'PY'
import os
import sys

import yaml

with open(sys.argv[1]) as source:
    servers = yaml.safe_load(source)
server, = (entry for entry in servers if entry['address'] == '0.0.0.0:24436')
server['protocol'].update(username='compat-user', password='compat-password')
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as output:
    yaml.safe_dump(servers, output)
PY
  cat >"$dropin" <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/shoes $scenario/config.yaml
EOF
  systemctl daemon-reload
  systemctl restart shoes.service
  for _ in {1..50}; do
    if ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'; then break; fi
    sleep 0.1
  done
  ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'
  check_authentication() {
    python3 - <<'PY'
import socket

with socket.create_connection(('127.0.0.1', 24436), timeout=5) as sock:
    sock.sendall(bytes([5, 1, 2]))
    assert sock.makefile('rb').read(2) == bytes([5, 2]), 'expected username/password authentication'
with socket.create_connection(('127.0.0.1', 24436), timeout=5) as sock:
    sock.sendall(bytes([5, 1, 0]))
    try:
        reply = sock.makefile('rb').read(2)
    except ConnectionResetError:
        reply = b''
    assert reply in (b'', bytes([5, 255])), 'expected anonymous authentication to be rejected'
PY
  }
  check_authentication
  rm "$dropin"
  systemctl daemon-reload
  before_pid="$(systemctl show --property=MainPID --value shoes.service)"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  write_failing_socks5_iptables "$scenario"
  if PATH="$scenario:$PATH" SOCKS5_ROLLBACK="$scenario" \
    "$NEW" socks5 secure "$legacy_socks5_id" --local --yes >"$scenario/result" 2>&1; then
    echo 'Expected SOCKS5 local hardening to reject authentication drift' >&2
    exit 1
  fi
  grep -Fq '原认证与受管配置不一致' "$scenario/result"
  test ! -e "$scenario/firewall-reached"
  test "$(systemctl show --property=MainPID --value shoes.service)" = "$before_pid"
  check_authentication
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"
)
echo 'SOCKS5 local: reject authentication drift on the same listener before rollback can expose it: PASS'

# Keep all listeners and the target unchanged, but give another node a different live password.
(
  scenario="$(mktemp -d /usr/local/lib/socks5-other-auth.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d/90-compat-socks5-other-auth.conf
  trap 'rm -f "$dropin"; systemctl daemon-reload; systemctl restart shoes.service; rm -rf "$scenario"' EXIT
  umask 077
  python3 - /etc/shoes/config.yaml "$scenario/config.yaml" <<'PY'
import sys

import yaml

with open(sys.argv[1]) as source:
    servers = yaml.safe_load(source)
server, = (entry for entry in servers if entry['address'] == '0.0.0.0:24432')
protocol = server['protocol']
assert protocol['username'] and protocol['password'] != 'compat-live-password'
protocol['password'] = 'compat-live-password'
with open(sys.argv[2], 'w') as output:
    yaml.safe_dump(servers, output)
PY
  cat >"$dropin" <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/shoes $scenario/config.yaml
EOF
  systemctl daemon-reload
  systemctl restart shoes.service
  for _ in {1..50}; do
    if ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'; then break; fi
    sleep 0.1
  done
  ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'
  check_live_password() {
    python3 - "$scenario/config.yaml" <<'PY'
import socket
import sys

import yaml

with open(sys.argv[1]) as source:
    server, = (entry for entry in yaml.safe_load(source) if entry['address'] == '0.0.0.0:24432')
username = server['protocol']['username'].encode()
password = server['protocol']['password'].encode()
with socket.create_connection(('127.0.0.1', 24432), timeout=5) as sock, sock.makefile('rb') as reply:
    sock.sendall(bytes([5, 1, 2]))
    assert reply.read(2) == bytes([5, 2]), 'expected username/password authentication'
    sock.sendall(bytes([1, len(username)]) + username + bytes([len(password)]) + password)
    assert reply.read(2) == bytes([1, 0]), 'the running node must still accept its live password'
PY
  }
  check_live_password
  rm "$dropin"
  systemctl daemon-reload
  before_pid="$(systemctl show --property=MainPID --value shoes.service)"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  if "$NEW" socks5 secure "$legacy_socks5_id" --auth --yes >"$scenario/result" 2>&1; then
    echo 'Expected SOCKS5 hardening to reject password drift on another node' >&2
    exit 1
  fi
  grep -Fq '端口 24432 的原认证与受管配置不一致' "$scenario/result"
  test "$(systemctl show --property=MainPID --value shoes.service)" = "$before_pid"
  check_live_password
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"
)
echo 'SOCKS5 auth: reject password drift on another SOCKS5 listener: PASS'

# A SOCKS5-only deployment can have identical TCP and auth with different UDP settings.
(
  scenario="$(mktemp -d /usr/local/lib/socks5-udp-drift.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d/90-compat-socks5-udp-drift.conf
  cp -a /etc/shoes "$scenario/original"
  trap 'rm -f "$dropin"; cp -a "$scenario/original/." /etc/shoes/; systemctl daemon-reload; systemctl restart shoes.service; rm -rf "$scenario"' EXIT
  umask 077
  state=/etc/shoes/ping-rust-state.json
  jq '.profiles |= map(select(.port == 24432 or .port == 24436)) |
    del(.xhttp_profiles, .sudoku_profiles)' "$state" >"$scenario/state.json"
  cat "$scenario/state.json" >"$state"
  python3 - "$scenario/live.yaml" <<'PY'
import pathlib
import sys

import yaml

config = pathlib.Path('/etc/shoes/config.yaml')
ports = {'0.0.0.0:24432', '0.0.0.0:24436'}
servers = [entry for entry in yaml.safe_load(config.read_text()) if entry['address'] in ports]
assert {entry['address'] for entry in servers} == ports and len(servers) == 2
config.write_text(yaml.safe_dump(servers))
other, = (entry for entry in servers if entry['address'] == '0.0.0.0:24432')
assert other['protocol']['udp_enabled'] is True
other['protocol']['udp_enabled'] = False
pathlib.Path(sys.argv[1]).write_text(yaml.safe_dump(servers))
PY
  cat >"$dropin" <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/shoes $scenario/live.yaml
EOF
  systemctl daemon-reload
  systemctl restart shoes.service
  for _ in {1..50}; do
    if ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'; then break; fi
    sleep 0.1
  done
  ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'
  rm "$dropin"
  systemctl daemon-reload
  before_pid="$(systemctl show --property=MainPID --value shoes.service)"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  if "$NEW" socks5 secure "$legacy_socks5_id" --auth --yes >"$scenario/result" 2>&1; then
    echo 'Expected SOCKS5-only hardening to reject configuration source drift' >&2
    exit 1
  fi
  grep -Fq '原 shoes 进程未使用受管聚合配置' "$scenario/result"
  test "$(systemctl show --property=MainPID --value shoes.service)" = "$before_pid"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"

  # Start the original shoes executable with the managed path, then change
  # that same inode without waking the inotify watcher or racing its debounce.
  cat "$scenario/live.yaml" >/etc/shoes/config.yaml
  python3 - "$NEW" "$legacy_socks5_id" "$scenario" <<'PY'
import mmap
from pathlib import Path
import socket
import subprocess
import sys
import time

import yaml

binary, profile, scenario = sys.argv[1:]
config = Path('/etc/shoes/config.yaml')

def main_pid():
    return subprocess.check_output(
        ['systemctl', 'show', '--property=MainPID', '--value', 'shoes.service'],
        text=True,
    ).strip()

def require_udp_disabled(protocol):
    username, password = (protocol[key].encode() for key in ('username', 'password'))
    deadline = time.monotonic() + 5
    while True:
        try:
            sock = socket.create_connection(('127.0.0.1', 24432), timeout=5)
            break
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
    with sock, sock.makefile('rb') as reply:
        sock.sendall(bytes([5, 1, 2]))
        assert reply.read(2) == bytes([5, 2])
        sock.sendall(bytes([1, len(username)]) + username + bytes([len(password)]) + password)
        assert reply.read(2) == bytes([1, 0])
        sock.sendall(bytes([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]))
        assert reply.read(4) == bytes([5, 7, 0, 1]), 'live UDP must still be disabled'

with config.open('r+b') as file, mmap.mmap(file.fileno(), 0) as mapped:
    subprocess.run(['systemctl', 'restart', 'shoes.service'], check=True)
    other, = (entry['protocol'] for entry in yaml.safe_load(mapped[:])
              if entry['address'] == '0.0.0.0:24432')
    assert other['udp_enabled'] is False
    require_udp_disabled(other)
    original_pid = main_pid()
    original_inode = config.stat().st_ino
    proc = Path('/proc') / original_pid
    assert (proc / 'cmdline').read_bytes().split(b'\0')[1:] == [bytes(config), b'']
    assert (proc / 'root/etc/shoes/config.yaml').stat().st_ino == original_inode
    assert mapped[:].count(b'udp_enabled: false\n') == 1
    offset = mapped.find(b'udp_enabled: false\n') + len(b'udp_enabled: ')
    mapped[offset:offset + 5] = b'true '
    mapped.flush()
    files = {path: path.read_bytes() for path in config.parent.rglob('*') if path.is_file()}
    require_udp_disabled(other)
    with (Path(scenario) / 'same-path-result').open('wb') as log:
        result = subprocess.run([binary, 'socks5', 'secure', profile, '--auth', '--yes'],
                                stdout=log, stderr=subprocess.STDOUT, timeout=30)
    assert result.returncode != 0, 'expected preflight to reject same-path UDP drift'
    assert '端口 24432 的原 UDP 设置与受管配置不一致' in (
        Path(scenario) / 'same-path-result').read_text()
    assert main_pid() == original_pid and config.stat().st_ino == original_inode
    assert {path: path.read_bytes() for path in config.parent.rglob('*') if path.is_file()} == files
    require_udp_disabled(other)
PY
)
echo 'SOCKS5-only auth: reject an alternate config with different UDP settings before restart: PASS'
echo 'SOCKS5-only auth: reject same-path live UDP drift before restarting or writing files: PASS'

# A daemon-reload can change the next ExecStart while the original process
# still owns all managed listeners.
(
  scenario="$(mktemp -d /usr/local/lib/socks5-next-start.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d/90-compat-socks5-next-start.conf
  trap 'rm -f "$dropin"; systemctl daemon-reload; systemctl restart shoes.service; rm -rf "$scenario"' EXIT
  umask 077
  sed 's/0\.0\.0\.0:24431/0.0.0.0:24437/' /etc/shoes/config.yaml >"$scenario/config.yaml"
  before_pid="$(systemctl show --property=MainPID --value shoes.service)"
  cat >"$dropin" <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/shoes $scenario/config.yaml
EOF
  systemctl daemon-reload
  test "$(systemctl show --property=MainPID --value shoes.service)" = "$before_pid"
  ss -H -ltn 'sport = :24431' | grep -Fq '0.0.0.0:24431'
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  if "$NEW" socks5 secure "$legacy_socks5_id" --auth --yes >"$scenario/result" 2>&1; then
    echo 'Expected SOCKS5 hardening to reject the loaded ExecStart override' >&2
    exit 1
  fi
  grep -Fq 'shoes.service 的 ExecStart 未直接使用受管聚合配置' "$scenario/result"
  test "$(systemctl show --property=MainPID --value shoes.service)" = "$before_pid"
  systemctl is-active --quiet shoes.service
  ss -H -ltn 'sport = :24431' | grep -Fq '0.0.0.0:24431'
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"
)
echo 'SOCKS5 auth: reject an alternate ExecStart loaded for the next restart: PASS'

# Inject drift after preflight so this still exercises verification and rollback.
check_other_auth_after_restart() (
  kind="$1"
  systemctl_bin="$(command -v systemctl)"
  scenario="$(mktemp -d /usr/local/lib/socks5-restart-auth.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d/90-compat-socks5-restart-auth.conf
  trap 'rm -f "$dropin"; systemctl daemon-reload; rm -rf "$scenario"' EXIT
  umask 077
  python3 - /etc/shoes/config.yaml "$scenario/config.yaml" "$kind" <<'PY'
import sys
import uuid

import yaml

with open(sys.argv[1]) as source:
    servers = yaml.safe_load(source)
target, = (entry for entry in servers if entry['address'] == '0.0.0.0:24436')
target['address'] = '127.0.0.1:24436'
if sys.argv[3] == 'socks5':
    other, = (entry for entry in servers if entry['address'] == '0.0.0.0:24432')
    username = other['protocol'].pop('username')
    password = other['protocol'].pop('password')
    assert username and password
else:
    other, = (entry for entry in servers if entry['address'] == '0.0.0.0:24431')
    reality, = other['protocol']['reality_targets'].values()
    reality['protocol']['user_id'] = str(uuid.uuid4())
with open(sys.argv[2], 'w') as output:
    yaml.safe_dump(servers, output)
PY
  cat >"$scenario/start" <<'SH'
#!/bin/sh
set -eu
config=/etc/shoes/config.yaml
if grep -Fq '127.0.0.1:24436' "$config"; then
  config="$1"
fi
exec /usr/local/bin/shoes "$config"
SH
  chmod 0700 "$scenario/start"
  cat >"$scenario/restart.conf" <<EOF
[Service]
ExecStart=
ExecStart=$scenario/start $scenario/config.yaml
EOF
  write_socks5_restart_override "$scenario"
  before_pid="$(systemctl show --property=MainPID --value shoes.service)"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  if PATH="$scenario:$PATH" SOCKS5_SYSTEMCTL="$systemctl_bin" SOCKS5_RESTART_DROPIN="$dropin" \
    "$NEW" socks5 secure "$legacy_socks5_id" --local --yes >"$scenario/result" 2>&1; then
    echo 'Expected SOCKS5 local hardening to reject authentication drift on another node after restart' >&2
    exit 1
  fi
  if [[ "$kind" == socks5 ]]; then
    grep -Fq '端口 24432 的运行态认证与受管配置不一致' "$scenario/result"
  else
    grep -Fq '重启后的 shoes 进程未使用受管聚合配置' "$scenario/result"
  fi
  grep -Fq '原配置、防火墙及服务已恢复并再次验证' "$scenario/result"
  systemctl is-active --quiet shoes.service
  test "$(systemctl show --property=MainPID --value shoes.service)" != "$before_pid"
  ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"
)
check_other_auth_after_restart socks5
echo 'SOCKS5 local: reject authentication drift on another node after restart and roll back: PASS'
check_other_auth_after_restart reality
echo 'SOCKS5 local: reject a different Reality UUID after restart and roll back: PASS'

# Exercise signal cancellation and an unattended timeout with the same substitute.
(
  shoes=/usr/local/bin/shoes
  scenario="$(mktemp -d /usr/local/lib/socks5-preflight.XXXXXX)"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  ln "$shoes" "$scenario/shoes"
  cat >"$scenario/dry-run.py" <<'PY'
#!/usr/bin/python3
import json
import os
import pathlib
import sys
import time

preflight = os.environ.get('SOCKS5_PREFLIGHT')
if sys.argv[1:2] != ['--dry-run'] or not preflight:
    shoes = pathlib.Path(__file__).resolve().with_name('shoes')
    os.execv(shoes, [str(shoes), *sys.argv[1:]])

import yaml

marker = pathlib.Path(preflight)
marker.with_suffix('.entered').touch()
candidate = pathlib.Path(sys.argv[2])
assert sys.argv[1] == '--dry-run'
assert candidate.stat().st_mode & 0o777 == 0o600
servers = yaml.safe_load(candidate.read_text())
protocol = next(s['protocol'] for s in servers if s['address'] == '0.0.0.0:24436')
assert protocol['type'] == 'socks' and protocol['username'] and protocol['password']
marker.with_suffix('.tmp').write_text(json.dumps([os.getpid(), os.getpgrp(), str(candidate)]))
marker.with_suffix('.tmp').replace(marker)
time.sleep(60)
marker.with_suffix('.finished').touch()
PY
  chmod 0755 "$scenario/dry-run.py"
  ln -s "$scenario/dry-run.py" "$scenario/substitute"
  mv -fT "$scenario/substitute" "$shoes"
  trap 'mv -fT "$scenario/shoes" "$shoes"; rm -rf "$scenario"' EXIT
  # A normal start while the substitute is installed must still run real shoes.
  systemctl restart shoes.service
  for _ in {1..50}; do
    if ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'; then break; fi
    sleep 0.1
  done
  ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'
  python3 - "$NEW" "$scenario" <<'PY'
import fcntl
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

for name, sig, signal_group in (
    ('SIGINT', signal.SIGINT, False),
    ('SIGTERM', signal.SIGTERM, False),
    ('group-SIGINT', signal.SIGINT, True),
    ('timeout', None, False),
):
    marker = pathlib.Path(sys.argv[2]) / name
    proc = subprocess.Popen(
        [sys.argv[1], 'socks5', 'secure', 'compat-socks5-legacy', '--auth', '--yes'],
        env={**os.environ, 'SOCKS5_PREFLIGHT': str(marker)},
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        start_new_session=signal_group,
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
        child, child_group, candidate = json.loads(marker.read_text())
        if sig is None:
            _, stderr = proc.communicate(timeout=30)
            assert proc.returncode == 1, 'stalled dry-run did not fail on its own'
            assert 'shoes 配置校验超时' in stderr.decode(), 'missing dry-run timeout error'
        else:
            if signal_group:
                # Deliver SIGINT to the CLI's entire group, like terminal Ctrl+C.
                os.killpg(proc.pid, sig)
            else:
                proc.send_signal(sig)
            _, stderr = proc.communicate(timeout=5)
            assert proc.returncode == 128 + sig, (name, proc.returncode, stderr.decode())
            assert 'shoes 拒绝生成的配置' not in stderr.decode()
        assert not pathlib.Path(candidate).exists(), 'candidate survived cancellation'
        assert not pathlib.Path(f'/proc/{child}').exists(), 'dry-run survived cancellation'
        assert not marker.with_suffix('.finished').exists(), 'dry-run finished after cancellation'
        with open('/run/lock/ping-rust.lock', 'rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if signal_group:
            assert child_group != proc.pid, 'dry-run shared the CLI foreground process group'
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
echo 'SOCKS5 preflight: PID signals, process-group SIGINT and timeout clean up dry-run: PASS'

# Exercise an actual slow stop with an exhausted start limit on a referenced unit.
(
  systemctl_bin="$(command -v systemctl)"
  # /run can be mounted noexec, and shoes.service has its own /tmp.
  scenario="$(mktemp -d /usr/local/lib/socks5-rollback.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d
  target=/run/systemd/system/compat-socks5-slow-stop.target
  reader=/run/systemd/system/compat-socks5-start-reader.service
  reader_unit="${reader##*/}"
  reload_helper=/run/systemd/system/compat-socks5-reload-reader.service
  reload_unit="${reload_helper##*/}"
  dependency=/run/systemd/system/compat-socks5-required-export.service
  dependency_unit="${dependency##*/}"
  notify=/run/systemd/system/compat-socks5-required-notify.service
  notify_unit="${notify##*/}"
  forking=/run/systemd/system/compat-socks5-required-forking.service
  forking_unit="${forking##*/}"
  simple=/run/systemd/system/compat-socks5-required-simple.service
  simple_unit="${simple##*/}"
  dependency_dropin=$dropin/90-compat-socks5-required-export.conf
  companion=/run/systemd/system/compat-socks5-start-companion.service
  timer=/run/systemd/system/compat-socks5-timer-export.timer
  exporter="${timer%.timer}.service"
  mkdir -p "$dropin"
  trap '"$systemctl_bin" stop "${target##*/}" "$reader_unit" "$reload_unit" "$dependency_unit" "$notify_unit" "$forking_unit" "$simple_unit" "${companion##*/}" "${timer##*/}" "${exporter##*/}" || true; rm -f "$dropin/90-compat-socks5-rollback.conf" "$dependency_dropin" "$target" "$reader" "$reload_helper" "$dependency" "$notify" "$forking" "$simple" "$companion" "$timer" "$exporter"; "$systemctl_bin" daemon-reload; rm -rf "$scenario"' EXIT
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
      "$SOCKS5_SYSTEMCTL" start compat-socks5-timer-export.timer || exit $?
      for _ in $(seq 1 50); do
        [ ! -e "$SOCKS5_ROLLBACK/timer-started" ] || break
        sleep 0.1
      done
      [ -e "$SOCKS5_ROLLBACK/timer-started" ] || exit 1
      # Keep the unverified candidate active long enough for the timer's reader to run.
      for _ in $(seq 1 20); do
        if [ -e "$SOCKS5_ROLLBACK/timer-export.json" ]; then
          touch "$SOCKS5_ROLLBACK/timer-exported-candidate"
          break
        fi
        sleep 0.1
      done
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
set -eu
[ -s "$2/stop-client" ] || exit 0
read -r client <"$2/stop-client"
touch "$2/stop-entered"
if "$1" export sing-box --profile "$3" --server example.com \
  >"$2/stop-redirected.json" 2>"$2/stop-redirected-error"; then
  exit 1
fi
grep -Fq '请在 SOCKS5 加固结束后重试文件导出' "$2/stop-redirected-error"
test ! -s "$2/stop-redirected.json"
touch "$2/stop-redirect-checked"
while kill -0 "$client" 2>/dev/null; do sleep 0.1; done
touch "$2/stop-after-client"
SH
  cat >"$scenario/exec-start-pre" <<'SH'
#!/bin/sh
set -eu
if "$1" info compat-socks5-legacy >"$2/info" 2>"$2/info-error"; then
  grep -Fq '用户名：无认证' "$2/info"
  echo original >>"$2/start-pre-auth"
else
  grep -Fq '请在加固结束后重试读取' "$2/info-error"
  if grep -Eq '^配置数量：|^  URL：' "$2/info"; then exit 1; fi
  echo deferred >>"$2/start-pre-auth"
fi
echo ok >>"$2/start-pre-runs"
SH
  cat >"$scenario/start-oneshot" <<'SH'
#!/bin/sh
set -eu
"$1" --quiet start "$2" "$3"
# Keep the shell as ControlPID while systemctl waits.
echo ok >>"$4/oneshot-wrapper-runs"
SH
  cat >"$scenario/reader" <<'SH'
#!/bin/sh
set -eu
if "$1" info compat-socks5-legacy >"$2/oneshot-info" 2>"$2/oneshot-info-error"; then
  grep -Fq '用户名：无认证' "$2/oneshot-info"
  echo original >>"$2/oneshot-auth"
else
  grep -Fq '请在加固结束后重试读取' "$2/oneshot-info-error"
  if grep -Eq '^配置数量：|^  URL：' "$2/oneshot-info"; then exit 1; fi
  echo deferred >>"$2/oneshot-auth"
fi
if [ ! -e "$2/oneshot-export.json" ]; then
  if ! "$1" export sing-box --profile "$3" --server example.com \
    --output "$2/oneshot-export.json" >/dev/null 2>"$2/oneshot-export-error"; then
    grep -Fq '请在 SOCKS5 加固结束后重试文件导出' "$2/oneshot-export-error"
    test ! -e "$2/oneshot-export.json"
    touch "$2/oneshot-deferred-export"
  fi
fi
echo ok >>"$2/oneshot-runs"
SH
  cat >"$scenario/timer-export" <<'SH'
#!/bin/sh
set -eu
test -n "${INVOCATION_ID:-}"
touch "$2/timer-started"
"$1" export sing-box --profile "$3" --server example.com \
  --output "$2/timer-export.json" >/dev/null
touch "$2/timer-finished"
SH
  chmod 0755 "$scenario/systemctl" "$scenario/exec-stop" "$scenario/exec-start-pre"
  chmod 0755 "$scenario/reader" "$scenario/timer-export" "$scenario/start-oneshot"
  env PATH="$scenario:$PATH" systemctl probe
  cat >"$reader" <<EOF
[Service]
Type=oneshot
TimeoutStartSec=5s
ExecStart=$scenario/reader $NEW $scenario $legacy_socks5_id
EOF
  cat >"$reload_helper" <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=5s
ExecStart=/bin/true
ExecReload=$NEW export sing-box --profile ${ids[1]} --server example.com --output $scenario/reload-client.json
ExecReload=/bin/sh -c 'echo ok >>$scenario/reload-runs'
EOF
  "$NEW" export sing-box --profile "${ids[1]}" --server example.com \
    --output "$scenario/dependency-expected.json" >/dev/null
  cat >"$dependency" <<EOF
[Service]
Type=oneshot
TimeoutStartSec=5s
ExecStart=$NEW export sing-box --profile ${ids[1]} --server example.com --output $scenario/dependency-export.json
ExecStart=/usr/bin/cmp -s $scenario/dependency-expected.json $scenario/dependency-export.json
ExecStart=/bin/sh -c 'echo ok >>$scenario/dependency-runs'
EOF
  cat >"$scenario/notify-dependency" <<'SH'
#!/bin/sh
set -eu
test "$(systemctl show --property=ControlPID --value "$4")" = 0
"$1" export sing-box --profile "$2" --server example.com --output "$3/notify-export.json" >/dev/null
cmp -s "$3/dependency-expected.json" "$3/notify-export.json"
echo ok >>"$3/notify-dependency-runs"
systemd-notify --ready
exec sleep infinity
SH
  chmod 0755 "$scenario/notify-dependency"
  cat >"$notify" <<EOF
[Unit]
PartOf=shoes.service
[Service]
Type=notify
NotifyAccess=all
TimeoutStartSec=5s
ExecStart=$scenario/notify-dependency $NEW ${ids[1]} $scenario $notify_unit
EOF
  cat >"$scenario/forking-dependency" <<'SH'
#!/bin/sh
set -eu
test "$(systemctl show --property=ControlPID --value "$4")" = "$$"
"$1" export sing-box --profile "$2" --server example.com --output "$3/forking-export.json" >/dev/null
cmp -s "$3/dependency-expected.json" "$3/forking-export.json"
echo ok >>"$3/forking-dependency-runs"
sleep infinity &
echo "$!" >"$3/forking.pid"
SH
  chmod 0755 "$scenario/forking-dependency"
  cat >"$forking" <<EOF
[Unit]
PartOf=shoes.service
[Service]
Type=forking
PIDFile=$scenario/forking.pid
TimeoutStartSec=5s
ExecStart=$scenario/forking-dependency $NEW ${ids[1]} $scenario $forking_unit
EOF
  cat >"$simple" <<EOF
[Unit]
PartOf=shoes.service
[Service]
Type=simple
TimeoutStartSec=5s
ExecStartPre=$NEW export sing-box --profile ${ids[1]} --server example.com --output $scenario/simple-export.json
ExecStartPre=/usr/bin/cmp -s $scenario/dependency-expected.json $scenario/simple-export.json
ExecStartPre=/bin/sh -c 'echo ok >>$scenario/simple-dependency-runs'
ExecStart=/bin/sleep infinity
EOF
  cat >"$companion" <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/true
EOF
  cat >"$exporter" <<EOF
[Service]
Type=oneshot
# The export waits for the write lock across both bounded rollback jobs.
TimeoutStartSec=5min
ExecStart=$scenario/timer-export $NEW $scenario $legacy_socks5_id
EOF
  cat >"$timer" <<'EOF'
[Timer]
OnActiveSec=100ms
AccuracySec=1ms
EOF
  cat >"$target" <<'EOF'
[Unit]
Description=Keep shoes.service loaded during a slow SOCKS5 rollback
Wants=shoes.service
EOF
  cat >"$dropin/90-compat-socks5-rollback.conf" <<EOF
[Unit]
StartLimitIntervalSec=10min
StartLimitBurst=1

[Service]
TimeoutStartSec=10s
TimeoutStopSec=150s
ReadWritePaths=$scenario
ExecStartPre=$scenario/exec-start-pre $NEW $scenario
ExecStartPre=+$scenario/start-oneshot $systemctl_bin ${reader_unit%.service} ${companion##*/} $scenario
ExecStop=$scenario/exec-stop $NEW $scenario $legacy_socks5_id
EOF
  "$systemctl_bin" daemon-reload
  "$systemctl_bin" start "$reload_unit"
  "$systemctl_bin" start "${target##*/}"
  "$systemctl_bin" is-active --quiet "${target##*/}"
  "$systemctl_bin" is-active --quiet shoes.service
  # Install the ordered dependency after the initial start. Both restarts must run it.
  cat >"$dependency_dropin" <<EOF
[Unit]
Requires=$dependency_unit $notify_unit $forking_unit $simple_unit
After=$dependency_unit $notify_unit $forking_unit $simple_unit

[Service]
ExecStartPre=+$systemctl_bin --quiet reload $reload_unit
EOF
  "$systemctl_bin" daemon-reload
  before_pid="$("$systemctl_bin" show --property=MainPID --value shoes.service)"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  if PATH="$scenario:$PATH" SOCKS5_ROLLBACK="$scenario" SOCKS5_SYSTEMCTL="$systemctl_bin" \
    "$NEW" socks5 secure compat-socks5-legacy --auth --yes >"$WORK/socks5-stop-rollback.txt" 2>&1; then
    echo 'Expected SOCKS5 activation to fail' >&2
    exit 1
  fi
  test -f "$scenario/activation-failed" || { echo 'SOCKS5 rollback did not reach the injected activation failure' >&2; exit 1; }
  test "$(grep -c '^ok$' "$scenario/dependency-runs")" -eq 2
  test "$(grep -c '^ok$' "$scenario/notify-dependency-runs")" -eq 2
  test "$(grep -c '^ok$' "$scenario/forking-dependency-runs")" -eq 2
  test "$(grep -c '^ok$' "$scenario/simple-dependency-runs")" -eq 2
  test "$(grep -c '^ok$' "$scenario/start-pre-runs")" -eq 2
  test "$(grep -cx ok "$scenario/reload-runs")" -eq 2
  cmp -s "$scenario/dependency-expected.json" "$scenario/reload-client.json"
  test "$(grep -c '^ok$' "$scenario/oneshot-runs")" -eq 2
  test "$(grep -c '^ok$' "$scenario/oneshot-wrapper-runs")" -eq 2
  test "$(cat "$scenario/start-pre-auth")" = $'deferred\noriginal'
  test "$(cat "$scenario/oneshot-auth")" = $'deferred\noriginal'
  test -f "$scenario/oneshot-deferred-export"
  jq -e '[.outbounds[] | select(.type == "socks")] | length == 1 and
    (.[0] | (has("username") or has("password")) | not)' "$scenario/oneshot-export.json" >/dev/null
  test ! -e "$scenario/timer-exported-candidate"
  for _ in {1..50}; do
    [[ -f "$scenario/timer-finished" ]] && break
    sleep 0.1
  done
  test -f "$scenario/timer-finished" || { echo 'SOCKS5 timer export did not finish after rollback' >&2; exit 1; }
  cmp -s "$scenario/timer-export.json" "$scenario/oneshot-export.json"
  test -f "$scenario/stop-entered"
  test -f "$scenario/stop-redirect-checked"
  test ! -s "$scenario/stop-redirected.json"
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
echo 'SOCKS5 rollback: synchronous readers finish and timer export waits for rollback: PASS'
echo 'SOCKS5 rollback: synchronous ExecReload exports during candidate and restored starts: PASS'
echo 'SOCKS5 rollback: ordered startup dependency exports during candidate and restored starts: PASS'
echo 'SOCKS5 rollback: ordered Type=notify dependency exports before READY=1 on both starts: PASS'
echo 'SOCKS5 rollback: ordered Type=forking dependency exports before forking on both starts: PASS'
echo 'SOCKS5 rollback: ordered Type=simple dependency exports in ExecStartPre on both starts: PASS'
echo 'SOCKS5 rollback: candidate credentials are withheld from redirected export stdout: PASS'

# A referenced, stopped unit keeps its start-rate counter. Inject a firewall
# error only after systemd has started the loopback candidate and it passes verification.
(
  systemctl_bin="$(command -v systemctl)"
  scenario="$(mktemp -d /usr/local/lib/socks5-start-limit.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d/90-compat-socks5-start-limit.conf
  target=/run/systemd/system/compat-socks5-rollback.target
  stop_reader=/run/systemd/system/compat-socks5-stop-reader.service
  trap 'systemctl stop "${target##*/}" "${stop_reader##*/}" || true; rm -f "$dropin" "$target" "$stop_reader"; systemctl daemon-reload; rm -rf "$scenario"' EXIT
  cat >"$target" <<'EOF'
[Unit]
Description=Keep shoes.service loaded during SOCKS5 rollback
Wants=shoes.service
EOF
  "$NEW" export sing-box --profile "${ids[1]}" --server example.com \
    --output "$scenario/stop-other-expected.json" >/dev/null
  cat >"$stop_reader" <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStopSec=5s
ExecStart=/bin/true
ExecStop=$NEW export sing-box --profile ${ids[1]} --server example.com --output $scenario/stop-other.json
ExecStop=/usr/bin/cmp -s $scenario/stop-other-expected.json $scenario/stop-other.json
ExecStop=/bin/sh -c 'echo ok >>$scenario/delegated-stop-reads'
EOF
  cat >"$scenario/start-notify" <<'SH'
#!/bin/sh
set -eu
test "$(systemctl show --property=ControlPID --value shoes.service)" = 0
if "$1" url "$2" >"$3/notify-url" 2>"$3/notify-url-error"; then
  cmp -s "$3/stop-expected-url" "$3/notify-url"
  echo original
else
  grep -Fq '请在加固结束后重试读取' "$3/notify-url-error"
  test ! -s "$3/notify-url"
  echo deferred
fi >>"$3/notify-reads"
systemd-notify --ready
exec /usr/local/bin/shoes /etc/shoes/config.yaml
SH
  cat >"$scenario/stop-export" <<'SH'
#!/bin/sh
set -eu
test -e /etc/shoes/.ping-rust-socks5-secure.pending || exit 0
if [ ! -s "$3/notify-reads" ]; then
  "$1" url "$2" --server-address example.com >"$3/stop-url"
  cmp -s "$3/stop-expected-url" "$3/stop-url"
  "$1" export sing-box --profile "$2" --server example.com --output "$3/stop-client.json" >/dev/null
else
  "$1" url "$4" >"$3/stop-other-url"
  cmp -s "$3/stop-other-expected-url" "$3/stop-other-url"
  if "$1" url "$2" >"$3/stop-candidate-url" 2>"$3/stop-candidate-url-error"; then
    mv "$3/stop-candidate-url" "$3/stop-url"
    exit 1
  fi
  grep -Fq '请在加固结束后重试读取' "$3/stop-candidate-url-error"
  test ! -s "$3/stop-candidate-url"
  if "$1" qr "$2" >"$3/stop-candidate-qr" 2>"$3/stop-candidate-qr-error"; then
    exit 1
  fi
  grep -Fq '请在加固结束后重试读取' "$3/stop-candidate-qr-error"
  test ! -s "$3/stop-candidate-qr"
  if "$1" info "$2" >"$3/stop-candidate-info" 2>"$3/stop-candidate-info-error"; then
    exit 1
  fi
  grep -Fq '请在加固结束后重试读取' "$3/stop-candidate-info-error"
  if grep -Eq '^配置数量：|^  URL：' "$3/stop-candidate-info"; then exit 1; fi
  if "$1" export sing-box --profile "$2" --server 127.0.0.1 \
    --output "$3/stop-candidate-client.json" >/dev/null 2>"$3/stop-candidate-error"; then
    exit 1
  fi
  grep -Fq '请在 SOCKS5 加固结束后重试文件导出' "$3/stop-candidate-error"
  test ! -e "$3/stop-candidate-client.json"
  touch "$3/stop-candidate-checked"
fi
SH
  chmod 0755 "$scenario/start-notify" "$scenario/stop-export"
  cat >"$dropin" <<EOF
[Unit]
StartLimitIntervalSec=10min
StartLimitBurst=1

[Service]
TimeoutStartSec=10s
ReadWritePaths=$scenario
ExecStartPre=+systemctl --quiet start ${stop_reader##*/}
ExecStop=+systemctl --quiet stop ${stop_reader##*/}
ExecStop=$scenario/stop-export $NEW $legacy_socks5_id $scenario ${ids[1]}
EOF
  cp "$dropin" "$scenario/restart.conf"
  cat >>"$scenario/restart.conf" <<EOF
Type=notify
NotifyAccess=all
ExecStart=
ExecStart=$scenario/start-notify $NEW $legacy_socks5_id $scenario
EOF
  write_socks5_restart_override "$scenario"
  write_failing_socks5_iptables "$scenario"
  systemctl daemon-reload
  systemctl start "${target##*/}"
  systemctl is-active --quiet "${target##*/}"
  systemctl is-active --quiet shoes.service
  before_pid="$(systemctl show --property=MainPID --value shoes.service)"
  "$NEW" url "$legacy_socks5_id" --server-address example.com >"$scenario/stop-expected-url"
  "$NEW" url "${ids[1]}" >"$scenario/stop-other-expected-url"
  "$NEW" export sing-box --profile "$legacy_socks5_id" --server example.com \
    --output "$scenario/stop-expected-client.json" >/dev/null
  : >"$scenario/notify-reads"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  if PATH="$scenario:$PATH" SOCKS5_ROLLBACK="$scenario" \
    SOCKS5_SYSTEMCTL="$systemctl_bin" SOCKS5_RESTART_DROPIN="$dropin" \
    "$NEW" socks5 secure compat-socks5-legacy --local --yes >"$WORK/socks5-start-limit.txt" 2>&1; then
    echo 'Expected SOCKS5 firewall change to fail' >&2
    exit 1
  fi
  test -f "$scenario/firewall-reached"
  cmp -s "$scenario/stop-expected-url" "$scenario/stop-url"
  cmp -s "$scenario/stop-expected-client.json" "$scenario/stop-client.json"
  test "$(cat "$scenario/delegated-stop-reads")" = $'ok\nok'
  test -f "$scenario/stop-candidate-checked"
  test "$(cat "$scenario/notify-reads")" = $'deferred\noriginal'
  systemctl is-active --quiet shoes.service
  test "$(systemctl show --property=MainPID --value shoes.service)" != "$before_pid"
  grep -Fq '原配置、防火墙及服务已恢复并再次验证' "$WORK/socks5-start-limit.txt"
  ss -H -ltn 'sport = :24436' | grep -F '0.0.0.0:24436' >/dev/null
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"
)
echo 'SOCKS5 rollback: Type=notify reads before READY=1 and restarts with StartLimitBurst=1: PASS'
echo 'SOCKS5 local: ExecStop exports the original public URL before the candidate starts: PASS'
echo 'SOCKS5 rollback: candidate ExecStop defers the changed URL, QR, info and file export: PASS'
echo 'SOCKS5 rollback: ExecStop synchronously stops a root unit that exports unchanged state: PASS'

# Root systemctl can use systemd's private socket. Delegated readers need the system bus.
apt-get install -y --no-install-recommends dbus
systemctl start dbus.service

# Confirm a non-root shoes can start with the candidate and again after a
# post-commit SIGHUP. The wrapper exposes the transition without logging credentials.
(
  systemctl_bin="$(command -v systemctl)"
  scenario="$(mktemp -d /usr/local/lib/socks5-hangup.XXXXXX)"
  config=/etc/shoes/config.yaml
  state=/etc/shoes/ping-rust-state.json
  profiles=/etc/shoes/profiles
  readable_profile=$profiles/SOCKS5-24432.yaml
  dropin=/etc/systemd/system/shoes.service.d/90-compat-socks5-hangup.conf
  delegated=/run/systemd/system/compat-socks5-non-root-export.service
  delegated_unit="${delegated##*/}"
  original_directory_mode="$(stat -c %a /etc/shoes)"
  original_profiles_mode="$(stat -c %a "$profiles")"
  original_profiles_owner="$(stat -c %u:%g "$profiles")"
  cp -p "$config" "$scenario/original-config"
  cp -p "$state" "$scenario/original-state"
  cp -p "$readable_profile" "$scenario/original-profile"
  trap 'rm -f "$dropin" "$delegated"; cp -p "$scenario/original-state" "$state"; chown --reference="$scenario/original-config" "$config"; chmod "$original_directory_mode" /etc/shoes; chown "$original_profiles_owner" "$profiles"; chmod "$original_profiles_mode" "$profiles"; cp -p "$scenario/original-profile" "$readable_profile"; "$systemctl_bin" daemon-reload; "$systemctl_bin" restart shoes.service; rm -rf "$scenario"' EXIT
  mkdir -p "${dropin%/*}"
  chmod 0711 /etc/shoes
  chmod 0711 "$scenario"
  chown nobody:nogroup "$config"
  mkdir "$scenario/exports" "$scenario/delegated"
  chown nobody:nogroup "$scenario/exports" "$scenario/delegated"
  "$NEW" export sing-box --profile "${ids[1]}" --server example.com \
    --output "$scenario/unchanged-expected.json" >/dev/null
  cat >"$scenario/export-unchanged" <<'SH'
#!/bin/sh
set -eu
pending=/etc/shoes/.ping-rust-socks5-secure.pending
test ! -r "$pending"
"$1" export sing-box --profile "$2" --server example.com --output "$4/unchanged.json" >/dev/null
if [ -e "$pending" ]; then
  if "$1" export sing-box --profile "$3" --server example.com \
       --output "$4/changed.json" >/dev/null 2>"$4/changed-error"; then
    # A rollback may export the restored profile. The candidate must never reach this branch.
    jq -e '[.outbounds[] | select(.type == "socks")] | length == 1 and
      (.[0] | (has("username") or has("password")) | not)' "$4/changed.json" >/dev/null
  else
    grep -Fq '请在 SOCKS5 加固结束后重试文件导出' "$4/changed-error"
    touch "$4/candidate-export-deferred"
  fi
fi
SH
  chmod 0755 "$scenario/export-unchanged"
  cat >"$scenario/check-root-start" <<'SH'
#!/bin/sh
set -eu
test -r /etc/shoes/.ping-rust-socks5-secure.pending || exit 0
if [ -e "$3/root-start-read" ]; then
  "$1" url "$2" >"$3/root-restored-url"
  exit 0
fi
for command in url qr info; do
  if "$1" "$command" "$2" >"$3/root-start-$command" 2>"$3/root-start-$command-error"; then
    touch "$3/root-start-exported"
  fi
done
touch "$3/root-start-read"
SH
  chmod 0755 "$scenario/check-root-start"
  "$NEW" url "$legacy_socks5_id" >"$scenario/root-expected-url"
  cat >"$delegated" <<EOF
[Service]
Type=oneshot
User=nobody
Group=nogroup
TimeoutStartSec=5s
ExecStart=$scenario/export-unchanged $NEW ${ids[1]} $legacy_socks5_id $scenario/delegated
EOF
  cat >"$dropin" <<EOF
[Service]
User=nobody
Group=nogroup
TimeoutStartSec=10s
ReadWritePaths=$scenario
ExecStartPre=+$systemctl_bin --quiet start $delegated_unit
ExecStartPost=$scenario/export-unchanged $NEW ${ids[1]} $legacy_socks5_id $scenario/exports
ExecStartPost=+$scenario/check-root-start $NEW $legacy_socks5_id $scenario
EOF
  python3 - "$state" <<'PY'
import os
import pwd
import struct
import sys

uid = pwd.getpwnam('nobody').pw_uid
acl = struct.pack('<I', 2) + b''.join(
    struct.pack('<HHI', tag, mode, user)
    for tag, mode, user in [(1, 6, 0xffffffff), (2, 4, uid),
                            (4, 0, 0xffffffff), (16, 4, 0xffffffff),
                            (32, 0, 0xffffffff)]
)
os.setxattr(sys.argv[1], 'system.posix_acl_access', acl, os.XATTR_CREATE)
PY
  cat >"$scenario/systemctl" <<'SH'
#!/bin/sh
set -eu
if [ "$1" = restart ] && [ ! -e "$SOCKS5_HANGUP/candidate-active" ]; then
  "$SOCKS5_SYSTEMCTL" "$@"
  for _ in $(seq 1 50); do
    ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436' && break
    sleep 0.1
  done
  ss -H -ltn 'sport = :24436' | grep -Fq '0.0.0.0:24436'
  "$SOCKS5_SYSTEMCTL" is-active --quiet shoes.service
  touch "$SOCKS5_HANGUP/candidate-active"
  exec sleep 30
fi
exec "$SOCKS5_SYSTEMCTL" "$@"
SH
  chmod 0755 "$scenario/systemctl"
  "$systemctl_bin" daemon-reload
  "$systemctl_bin" restart shoes.service
  before_pid="$("$systemctl_bin" show --property=MainPID --value shoes.service)"
  test "$(stat -c %a:%U:%G "$config")" = '600:nobody:nogroup'
  cmp -s "$scenario/exports/unchanged.json" "$scenario/unchanged-expected.json"
  cmp -s "$scenario/delegated/unchanged.json" "$scenario/unchanged-expected.json"
  rm "$scenario/exports/unchanged.json" "$scenario/delegated/unchanged.json"
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/before"
  python3 - "$NEW" "$scenario" "$systemctl_bin" <<'PY'
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

binary, root, systemctl = sys.argv[1:]
scenario = pathlib.Path(root)
directory = pathlib.Path('/etc/shoes')
config = directory / 'config.yaml'
state = directory / 'ping-rust-state.json'
pending = directory / '.ping-rust-socks5-secure.pending'
original_state = state.read_bytes()
original_config = config.read_bytes()
original_stat = config.stat()
proc = subprocess.Popen(
    [binary, 'socks5', 'secure', 'compat-socks5-legacy', '--auth', '--yes'],
    env={**os.environ, 'PATH': f'{scenario}:{os.environ["PATH"]}',
         'SOCKS5_HANGUP': root, 'SOCKS5_SYSTEMCTL': systemctl},
    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
)
try:
    marker = scenario / 'candidate-active'
    deadline = time.monotonic() + 20
    while not marker.exists() and proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    assert marker.exists(), 'non-root shoes did not start with the SOCKS5 candidate'
    assert pending.is_file() and config.read_bytes() != original_config
    assert (scenario / 'exports/unchanged.json').read_bytes() == (
        scenario / 'unchanged-expected.json').read_bytes()
    assert (scenario / 'exports/candidate-export-deferred').is_file()
    assert not (scenario / 'exports/changed.json').exists()
    assert (scenario / 'delegated/unchanged.json').read_bytes() == (
        scenario / 'unchanged-expected.json').read_bytes()
    assert (scenario / 'delegated/candidate-export-deferred').is_file()
    assert not (scenario / 'delegated/changed.json').exists()
    assert (scenario / 'root-start-read').is_file()
    assert not (scenario / 'root-start-exported').exists()
    for command in ['url', 'qr', 'info']:
        output = (scenario / f'root-start-{command}').read_bytes()
        assert b'socks5://' not in output and '配置数量：'.encode() not in output
        if command != 'info':
            assert not output
        assert '请在加固结束后重试读取' in (scenario / f'root-start-{command}-error').read_text()
    assert (config.stat().st_uid, config.stat().st_gid, config.stat().st_mode) == (
        original_stat.st_uid, original_stat.st_gid, original_stat.st_mode
    )
    # Legacy listen metadata may be backfilled, but authentication is unpublished.
    legacy = next(p for p in json.loads(state.read_bytes())['profiles']
                  if p['name'] == 'compat-socks5-legacy')
    assert legacy['credentials']['Socks5'].get('username') is None
    proc.send_signal(signal.SIGHUP)
    _, stderr = proc.communicate(timeout=30)
    assert proc.returncode == 129, (proc.returncode, stderr.decode())
    assert '收到 SIGHUP' in stderr.decode()
    assert '原配置、防火墙及服务已恢复并再次验证' in stderr.decode()
    assert not pending.exists() and state.read_bytes() == original_state
    assert config.read_bytes() == original_config
    assert (scenario / 'delegated/changed.json').is_file()
    assert (scenario / 'root-restored-url').read_bytes() == (
        scenario / 'root-expected-url').read_bytes()
finally:
    if proc.poll() is None:
        proc.kill()
        proc.wait()
PY
  echo 'SOCKS5 rollback: root ExecStartPost defers URL, QR and info before SIGHUP and reads the restored URL: PASS'
  "$systemctl_bin" is-active --quiet shoes.service
  test "$("$systemctl_bin" show --property=MainPID --value shoes.service)" != "$before_pid"
  ss -H -ltn 'sport = :24436' | grep -F '0.0.0.0:24436' >/dev/null
  test "$(stat -c %a:%U:%G "$config")" = '600:nobody:nogroup'
  find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$scenario/after"
  diff -u "$scenario/before" "$scenario/after"

  test "$(stat -c %a:%U /run/lock/ping-rust.lock)" = '600:root'
  chown root:nogroup "$profiles"
  chmod 0710 "$profiles"
  chown nobody:nogroup "$readable_profile"
  # The next restart intentionally rejects the candidate via the non-root hook.
  rm "$scenario/root-start-read"
  cat >"$scenario/start-reader" <<'SH'
#!/bin/sh
set -eu
info="$("$1" info "$2")"
printf '%s\n' "$info" | grep -Eq 'socks5://example\.com:24436#'
"$1" export sing-box --profile "$3" --server example.com --output "$4" >/dev/null
SH
  chmod 0755 "$scenario/start-reader"
  cat >>"$dropin" <<EOF
ExecStartPre=/usr/bin/test -r $readable_profile
ExecStartPost=$scenario/start-reader $NEW $legacy_socks5_id ${ids[1]} $scenario/exports/client.json
EOF
  "$systemctl_bin" daemon-reload
  "$systemctl_bin" restart shoes.service
  mv "$scenario/exports/client.json" "$scenario/expected.json"
  if "$NEW" socks5 secure "$legacy_socks5_id" --auth --yes >"$scenario/acl-rollback" 2>&1; then
    echo 'Expected the hook requiring the original URL to reject the candidate' >&2
    exit 1
  fi
  grep -Fq '原配置、防火墙及服务已恢复并再次验证' "$scenario/acl-rollback"
  "$systemctl_bin" is-active --quiet shoes.service
  test ! -e /etc/shoes/.ping-rust-socks5-secure.pending
  cmp -s "$state" "$scenario/original-state"
  cmp -s "$scenario/exports/client.json" "$scenario/expected.json"
  test "$(stat -c %a:%U:%G "$profiles")" = '710:root:nogroup'
  test "$(stat -c %a:%U:%G "$readable_profile")" = '600:nobody:nogroup'
  echo 'SOCKS5 rollback: required non-root ExecStartPost reads and exports restored state via ACL: PASS'

  # Repeat with explicit listen metadata and access to state alone. The root
  # service can read config.yaml, but its delegated start hook cannot.
  jq '(.profiles[] | select(.name == "compat-socks5-legacy") |
    .credentials.Socks5.listen) = {"address": "0.0.0.0", "legacy_public_address": "0.0.0.0"}' \
    "$state" >"$scenario/explicit-state"
  cat "$scenario/explicit-state" >"$state"
  chown root:root "$config"
  rm -f "$scenario/delegated/changed.json" "$scenario/delegated/candidate-export-deferred" \
    "$scenario/delegated/unchanged.json"
  cat >"$scenario/reject-candidate" <<'SH'
#!/bin/sh
set -eu
if "$1" url "$2" >"$3/state-only-root-url" 2>"$3/state-only-root-error"; then
  cmp -s "$3/root-expected-url" "$3/state-only-root-url"
  exit
fi
grep -Fq '请在加固结束后重试读取' "$3/state-only-root-error"
test ! -s "$3/state-only-root-url"
touch "$3/state-only-candidate-started"
exit 1
SH
  chmod 0755 "$scenario/reject-candidate"
  cat >"$dropin" <<EOF
[Service]
TimeoutStartSec=10s
ReadWritePaths=$scenario
ExecStartPre=+$systemctl_bin --quiet start $delegated_unit
ExecStartPost=$scenario/reject-candidate $NEW $legacy_socks5_id $scenario
EOF
  cat >>"$delegated" <<EOF
ExecStartPre=/usr/bin/test -r $state
ExecStartPre=/usr/bin/test ! -r $config
ExecStart=$scenario/query-unchanged $NEW ${ids[1]} $legacy_socks5_id $scenario/delegated
EOF
  cat >"$scenario/query-unchanged" <<'SH'
#!/bin/sh
set -eu
"$1" url COMPAT-SOCKS5 >"$4/query-url"
"$1" qr "$2" >"$4/query-qr"
"$1" info "$2" >"$4/query-info"
grep -Fq "$2 | compat-socks5 |" "$4/query-info"
if [ -e /etc/shoes/.ping-rust-socks5-secure.pending ] && [ ! -e "$4/changed.json" ]; then
  cp "$4/query-url" "$4/candidate-unchanged-url"
  cp "$4/query-qr" "$4/candidate-unchanged-qr"
  if "$1" url "$3" >"$4/candidate-url" 2>/dev/null; then exit 1; fi
  test ! -s "$4/candidate-url"
  if "$1" info >"$4/candidate-info" 2>/dev/null; then exit 1; fi
  if grep -q '^配置数量：' "$4/candidate-info"; then exit 1; fi
  touch "$4/candidate-queries-checked"
fi
SH
  chmod 0755 "$scenario/query-unchanged"
  "$NEW" url "${ids[1]}" >"$scenario/query-expected-url"
  "$NEW" qr "${ids[1]}" >"$scenario/query-expected-qr"
  test "$(stat -c %a:%U:%G "$config")" = '600:root:root'
  "$systemctl_bin" daemon-reload
  "$systemctl_bin" restart shoes.service
  cmp -s "$scenario/delegated/unchanged.json" "$scenario/unchanged-expected.json"
  rm "$scenario/delegated/unchanged.json"
  if "$NEW" socks5 secure "$legacy_socks5_id" --auth --yes >"$scenario/state-only-rollback" 2>&1; then
    echo 'Expected the required root hook to reject the candidate after the state-only export' >&2
    exit 1
  fi
  test -f "$scenario/state-only-candidate-started"
  test -f "$scenario/delegated/candidate-export-deferred"
  test -f "$scenario/delegated/candidate-queries-checked"
  cmp -s "$scenario/delegated/candidate-unchanged-url" "$scenario/query-expected-url"
  cmp -s "$scenario/delegated/candidate-unchanged-qr" "$scenario/query-expected-qr"
  grep -Fq '原配置、防火墙及服务已恢复并再次验证' "$scenario/state-only-rollback"
  "$systemctl_bin" is-active --quiet shoes.service
  cmp -s "$state" "$scenario/explicit-state"
  cmp -s "$config" "$scenario/original-config"
  test "$(stat -c %a:%U:%G "$config")" = '600:root:root'
  cmp -s "$scenario/delegated/unchanged.json" "$scenario/unchanged-expected.json"
  cmp -s "$scenario/delegated/query-url" "$scenario/query-expected-url"
  cmp -s "$scenario/delegated/query-qr" "$scenario/query-expected-qr"
  test -s "$scenario/delegated/changed.json"
  echo 'SOCKS5 rollback: a delegated start hook exports with access to state alone: PASS'
)
echo 'SOCKS5 rollback: post-commit SIGHUP restores configuration and the non-root service: PASS'
echo 'SOCKS5 rollback: root startup hook can synchronously delegate an ACL-backed export to a non-root unit: PASS'

# Keep both filter backends active while the normal iptables binary uses nf_tables.
(
  apt-get install -y --no-install-recommends iptables nftables
  scenario="$(mktemp -d /usr/local/lib/socks5-mixed-firewall.XXXXXX)"
  cp -a /etc/shoes "$scenario/original"
  trap 'iptables-legacy -w -D INPUT -p tcp --dport 24436 -j DROP 2>/dev/null || true; iptables-legacy -w -D INPUT -d 127.0.0.1/32 -p tcp --dport 24436 -j ACCEPT 2>/dev/null || true; iptables-legacy -w -D INPUT -d 203.0.113.8/32 -p tcp --dport 24436 -j ACCEPT 2>/dev/null || true; iptables-legacy -w -D INPUT -p tcp --dport 24436 -j ACCEPT 2>/dev/null || true; iptables-legacy -w -D INPUT -p tcp --dport 24436 -m comment --comment "SOCKS5 compat" -j ACCEPT 2>/dev/null || true; iptables-legacy -w -D INPUT -p tcp --dport 24437 -j ACCEPT 2>/dev/null || true; nft delete table ip compat_socks5 2>/dev/null || true; cp -a "$scenario/original/." /etc/shoes/; systemctl restart shoes.service; rm -rf "$scenario"' EXIT
  iptables-legacy -w -A INPUT -p tcp --dport 24436 -j ACCEPT
  iptables-legacy -w -A INPUT -p tcp --dport 24436 -m comment --comment "SOCKS5 compat" -j ACCEPT
  iptables-legacy -w -A INPUT -d 203.0.113.8/32 -p tcp --dport 24436 -j ACCEPT
  iptables-legacy -w -A INPUT -d 127.0.0.1/32 -p tcp --dport 24436 -j ACCEPT
  iptables-legacy -w -A INPUT -p tcp --dport 24436 -j DROP
  iptables-legacy -w -A INPUT -p tcp --dport 24437 -j ACCEPT
  update-alternatives --set iptables "$(command -v iptables-nft)"
  iptables --version | grep -Fq '(nf_tables)'
  nft -f - <<'NFT'
table ip compat_socks5 {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 24436 accept
    tcp dport 24436 accept comment "SOCKS5 compat"
  }
}
NFT
  "$NEW" socks5 secure "$legacy_socks5_id" --local --yes >"$scenario/result" 2>&1
  iptables-legacy -w -S INPUT >"$scenario/legacy-after"
  loopback_rule='-A INPUT -d 127.0.0.1/32 -p tcp -m tcp --dport 24436 -j ACCEPT'
  grep -Fxq -- "$loopback_rule" "$scenario/legacy-after"
  grep -Fq -- '--dport 24436 -j DROP' "$scenario/legacy-after"
  grep -Fq -- '--dport 24437 -j ACCEPT' "$scenario/legacy-after"
  if grep -Fq 'SOCKS5 compat' "$scenario/legacy-after"; then
    echo 'SOCKS5 commented legacy INPUT allow survived' >&2
    exit 1
  fi
  if grep -Fvx -- "$loopback_rule" "$scenario/legacy-after" | grep -F -- '--dport 24436 -j ACCEPT'; then
    echo 'SOCKS5 legacy INPUT allow survived with iptables-nft selected' >&2
    exit 1
  fi
  nft list chain ip compat_socks5 input >"$scenario/nft-after"
  if grep -Fq 'tcp dport 24436 accept' "$scenario/nft-after"; then
    echo 'SOCKS5 nft INPUT allow survived' >&2
    exit 1
  fi
  ss -H -ltn 'sport = :24436' | grep -Fq '127.0.0.1:24436'
)
echo 'SOCKS5 local: close both nft and legacy INPUT allows with iptables-nft selected: PASS'
echo 'SOCKS5 local: keep the loopback allow when other traffic on the port is denied: PASS'

(
  scenario="$(mktemp -d /usr/local/lib/socks5-start-export.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d/90-compat-socks5-start-export.conf
  trap 'rm -f "$dropin"; systemctl daemon-reload; rm -rf "$scenario"' EXIT
  cat >"$scenario/start-reader" <<'SH'
#!/bin/sh
set -eu
test -z "${INVOCATION_ID:-}"
"$1" export sing-box --profile "$4" --server example.com \
  --output "$2/unchanged-client.json" >/dev/null
if [ -e /etc/shoes/.ping-rust-socks5-secure.pending ]; then
  for command in info url; do
    if "$1" "$command" "$3" >"$2/$command" 2>"$2/$command-error"; then exit 1; fi
    grep -Fq '请在加固结束后重试读取' "$2/$command-error"
  done
  if grep -Eq '^配置数量：|^  URL：' "$2/info"; then exit 1; fi
  test ! -s "$2/url"
  if "$1" export sing-box --profile "$3" --server example.com \
    --output "$2/client.json" >/dev/null 2>"$2/export-error"; then exit 1; fi
  grep -Fq '请在 SOCKS5 加固结束后重试文件导出' "$2/export-error"
  test ! -e "$2/client.json"
  touch "$2/deferred-export"
else
  "$1" info "$3" >"$2/info"
  "$1" url "$3" >"$2/url"
  sed -n 's/^  URL：//p' "$2/info" >"$2/info-url"
  grep -Eq '^socks5://[^[:space:]@]+@example\.com:24436#' "$2/url"
  cmp -s "$2/info-url" "$2/url"
  "$1" export sing-box --profile "$3" --server example.com \
    --output "$2/client.json" >/dev/null
fi
SH
  chmod 0755 "$scenario/start-reader"
  cat >"$dropin" <<EOF
[Service]
TimeoutStartSec=10s
ReadWritePaths=$scenario
ExecStartPost=/usr/bin/env -i $scenario/start-reader $NEW $scenario $legacy_socks5_id ${ids[1]}
EOF
  systemctl daemon-reload
  "$NEW" export sing-box --profile "${ids[1]}" --server example.com \
    --output "$scenario/unchanged-expected.json" >/dev/null
  # Delegate state access before hardening, while keeping the writer lock private.
  python3 - "$NEW" "$legacy_socks5_id" "$WORK/socks5-start-export.txt" <<'PY'
import errno
import fcntl
import json
import os
from pathlib import Path
import pwd
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

binary, profile, secure_log = sys.argv[1:]
reader = pwd.getpwnam('nobody')
directory = Path('/etc/shoes')
state = directory / 'ping-rust-state.json'
pending = directory / '.ping-rust-socks5-secure.pending'
lock = Path('/run/lock/ping-rust.lock')
assert lock.stat().st_uid == 0 and lock.stat().st_mode & 0o777 == 0o600
directory_mode = directory.stat().st_mode & 0o7777
state_mode = state.stat().st_mode & 0o7777
acl_name = 'system.posix_acl_access'
undefined_id = 0xffffffff
acl = struct.pack('<I', 2) + b''.join(
    struct.pack('<HHI', tag, mode, uid)
    for tag, mode, uid in [(1, 6, undefined_id), (2, 4, reader.pw_uid),
                           (4, 0, undefined_id), (16, 4, undefined_id),
                           (32, 0, undefined_id)]
)
with TemporaryDirectory() as work:
    os.chown(work, reader.pw_uid, reader.pw_gid)
    output = Path(work) / 'sing-box.json'
    export = ['export', 'sing-box', '--profile', profile, '--server', 'example.com',
              '--output', str(output)]

    def as_reader(command):
        return subprocess.run([binary, *command], user=reader.pw_uid,
                              group=reader.pw_gid, extra_groups=[], timeout=10,
                              capture_output=True)

    def assert_export_blocked(original):
        result = as_reader(export)
        assert result.returncode != 0
        assert '请在 SOCKS5 加固结束后重试读取' in result.stderr.decode()
        assert output.read_bytes() == original

    def assert_menus_work():
        commands = r'''
set timeout 10
log_user 0
proc expect_pattern {pattern} {
    expect {
        -re $pattern { return $expect_out(0,string) }
        eof { error "delegated menu exited before $pattern" }
        timeout { error "delegated menu timed out before $pattern" }
    }
}
proc choose_socks5 {} {
    expect_pattern {请选择配置:}
    regexp {^([0-9]+)} [expect_pattern {[0-9]+\) SOCKS5-24436\.yaml}] unused index
    expect_pattern {请选择 \[0-[0-9]+\]: }
    send -- "$index\r"
}
spawn $env(COMPAT_MENU_BINARY)
expect_pattern {请选择 \[0-10\]: }
send -- "3\r"
choose_socks5
expect_pattern {二维码 \(QR\)}
expect_pattern {按回车返回主菜单}
send -- "\r"
expect_pattern {请选择 \[0-10\]: }
send -- "9\r"
expect_pattern {1\) 导出客户端配置}
expect_pattern {请选择 \[0-[0-9]+\]: }
send -- "1\r"
choose_socks5
expect_pattern {客户端格式:}
expect_pattern {请选择 \[0-3\]: }
send -- "2\r"
expect_pattern {VPS 公网域名或 IP}
send -- "example.com\r"
expect_pattern {"outbounds"}
expect_pattern {按回车返回主菜单}
send -- "\r"
expect_pattern {请选择 \[0-10\]: }
send -- "0\r"
expect_pattern {已退出}
expect eof
if {[lindex [wait] 3] != 0} { exit 1 }
'''
        subprocess.run(['expect', '-f', '-'], input=commands.encode(), check=True, timeout=35,
                       user=reader.pw_uid, group=reader.pw_gid, extra_groups=[],
                       env={**os.environ, 'LC_ALL': 'C.UTF-8', 'COMPAT_MENU_BINARY': binary})

    os.setxattr(state, acl_name, acl, os.XATTR_CREATE)
    try:
        os.chmod(directory, 0o711)
        with open(secure_log, 'wb') as log:
            subprocess.run([binary, 'socks5', 'secure', 'compat-socks5-legacy', '--auth', '--yes'],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        assert os.getxattr(state, acl_name) == acl
        for command in [['info', profile], ['url', profile], ['qr', profile], export]:
            result = as_reader(command)
            assert result.returncode == 0, (command[0], result.returncode)
        assert_menus_work()
        original = output.read_bytes()
        socks = next(item for item in json.loads(original)['outbounds']
                     if item['type'] == 'socks')
        assert socks['username'] and socks['password']
        # A writer can hold the state inode before publishing the pending marker.
        assert not pending.exists()
        with state.open('rb') as guarded_state:
            fcntl.flock(guarded_state, fcntl.LOCK_EX)
            assert_export_blocked(original)
        pending.touch(mode=0o600, exist_ok=False)
        try:
            with pending.open('rb') as marker:
                fcntl.flock(marker, fcntl.LOCK_EX)
                assert_export_blocked(original)
            assert_export_blocked(original)
        finally:
            pending.unlink()
    finally:
        os.chmod(directory, directory_mode)
        try:
            os.removexattr(state, acl_name)
        except OSError as error:
            if error.errno != errno.ENODATA:
                raise
        os.chmod(state, state_mode)
PY
  echo 'SOCKS5 readers: delegated state ACL survives hardening with a private lock and respects a pending transaction: PASS'
  systemctl is-active --quiet shoes.service
  cmp -s "$scenario/unchanged-client.json" "$scenario/unchanged-expected.json"
  test -f "$scenario/deferred-export"
  test ! -e "$scenario/client.json"
  "$NEW" export sing-box --profile "$legacy_socks5_id" --server example.com \
    --output "$scenario/expected.json" >/dev/null
  "$NEW" url "$legacy_socks5_id" >"$scenario/expected-url"
  "$OLD" url "$legacy_socks5_id" >"$scenario/v0.2.1-url"
  cmp -s "$scenario/v0.2.1-url" "$scenario/expected-url"
  # Once the state is published, a normal restart lets the same hook write it.
  systemctl restart shoes.service
  systemctl is-active --quiet shoes.service
  cmp -s "$scenario/url" "$scenario/expected-url"
  jq -e '[.outbounds[] | select(.type == "socks")] | length == 1 and
    (.[0] | (.username | length) > 0 and (.password | length) > 0)' "$scenario/client.json" >/dev/null
  cmp -s "$scenario/client.json" "$scenario/expected.json"
)
echo 'SOCKS5 authentication: clean-environment ExecStartPost info, URL and export agree with published credentials: PASS'

# Backup restore holds the writer lock across restart. Its startup hook waits
# for a root unit to export the restored state, then restarts the active unit.
# The helper has no ExecReload, so reload-or-restart also starts it again.
(
  scenario="$(mktemp -d /usr/local/lib/socks5-restart-export.XXXXXX)"
  dropin=/etc/systemd/system/shoes.service.d/90-compat-socks5-restart-export.conf
  helper=/run/systemd/system/compat-socks5-restart-export.service
  reload_helper=/run/systemd/system/compat-socks5-restore-reload.service
  dependency=/run/systemd/system/compat-socks5-restore-dependency.service
  nested=/run/systemd/system/compat-socks5-restore-nested-export.service
  pending=/etc/shoes/.ping-rust-socks5-secure.pending
  systemctl_bin="$(command -v systemctl)"
  umask 077
  trap '"$systemctl_bin" stop "${helper##*/}" "${reload_helper##*/}" "${dependency##*/}" "${nested##*/}" || true; rm -f "$dropin" "$helper" "$reload_helper" "$dependency" "$nested" "$pending"; "$systemctl_bin" daemon-reload; rm -rf "$scenario"' EXIT
  "$NEW" backup "$scenario/backup.tar.gz" >/dev/null
  "$NEW" export sing-box --profile "$legacy_socks5_id" --server example.com \
    --output "$scenario/expected.json" >/dev/null
  # Reproduce the on-disk state left by SIGKILL just after publishing the marker.
  jq --arg id "$legacy_socks5_id" '(.profiles[] | select(.id == $id) | .credentials.Socks5) |=
    (.username = "compat-pending-user" | .password = "compat-pending-password")' \
    /etc/shoes/ping-rust-state.json >"$scenario/pending"
  install -m 0600 "$scenario/pending" "$pending"
  if "$NEW" backup "$scenario/unfinished.tar.gz" >"$scenario/backup-result" 2>&1; then
    echo 'Expected backup to refuse an unfinished SOCKS5 transaction' >&2
    exit 1
  fi
  grep -Fq '上次 SOCKS5 加固未完成' "$scenario/backup-result"
  test ! -e "$scenario/unfinished.tar.gz"
  cmp -s "$scenario/pending" "$pending"
  cat >"$helper" <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=5s
ExecStart=$NEW export sing-box --profile $legacy_socks5_id --server example.com --output $scenario/client.json
ExecStartPost=/bin/sh -c 'echo ok >>$scenario/helper-runs'
EOF
  cat >"$reload_helper" <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=5s
ExecStart=/bin/true
ExecReload=$NEW export sing-box --profile $legacy_socks5_id --server example.com --output $scenario/reload-client.json
EOF
  cat >"$nested" <<EOF
[Service]
Type=oneshot
TimeoutStartSec=5s
ExecStart=$NEW export sing-box --profile $legacy_socks5_id --server example.com --output $scenario/nested-client.json
EOF
  cat >"$dependency" <<EOF
[Unit]
Requires=${nested##*/}
After=${nested##*/}
[Service]
Type=oneshot
ExecStart=/bin/true
EOF
  cat >"$dropin" <<EOF
[Unit]
Requires=${dependency##*/}
After=${dependency##*/}
[Service]
TimeoutStartSec=10s
ExecStartPre=$systemctl_bin --quiet restart ${helper##*/}
ExecStartPre=$systemctl_bin --quiet try-restart ${helper##*/}
ExecStartPre=$systemctl_bin --quiet reload-or-restart ${helper##*/}
ExecStartPre=$systemctl_bin --quiet reload ${reload_helper##*/}
EOF
  "$systemctl_bin" daemon-reload
  "$systemctl_bin" start "${reload_helper##*/}"
  "$NEW" restore "$scenario/backup.tar.gz" >"$scenario/result" 2>&1
  test ! -e "$pending"
  cmp -s "$scenario/expected.json" "$scenario/client.json"
  cmp -s "$scenario/expected.json" "$scenario/reload-client.json"
  cmp -s "$scenario/expected.json" "$scenario/nested-client.json"
  test "$(grep -cx ok "$scenario/helper-runs")" -eq 3
  "$systemctl_bin" is-active --quiet shoes.service
)
echo 'Backup: refuse an unfinished SOCKS5 transaction and recover from the previous archive: PASS'
echo 'Backup restore: synchronous restart, try-restart, reload-or-restart and ExecReload helpers can export restored state: PASS'
echo 'Backup restore: a two-level ordered startup dependency can export restored state: PASS'
