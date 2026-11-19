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
edit_anonymous_socks5_address() {
  # Inline Expect reads stdin and environment values using the process locale.
  # Debian's default C locale would misdecode the UTF-8 Chinese menu patterns.
  SOCKS5_EDIT_BINARY="$NEW" SOCKS5_EDIT_INDEX="$socks5_index" \
    SOCKS5_EDIT_ADDRESS="$1" SOCKS5_EDIT_RESULT="$2" \
    LC_ALL=C.UTF-8 LANG=C.UTF-8 expect <<'TCL'
set timeout 180
log_user 0
proc expect_or_fail {pattern} {
    expect {
        -re $pattern { return }
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
expect_or_fail {3\) 更改客户端公网地址}
expect_or_fail {请选择 \[0-[0-9]+\]: }
send -- "3\r"
expect_or_fail {VPS 公网域名或 IP（默认：自动检测）（输入 0 返回）：}
send -- "$env(SOCKS5_EDIT_ADDRESS)\r"
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
edit_anonymous_socks5_address "$SERVER" '先启用认证'
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-socks5-rejected"
diff -u "$WORK/hash-socks5-after" "$WORK/hash-socks5-rejected"
edit_anonymous_socks5_address 127.0.0.2 '配置更改成功。'
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
