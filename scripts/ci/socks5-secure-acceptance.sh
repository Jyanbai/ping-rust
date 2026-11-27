#!/usr/bin/env bash
# #153：在真实 systemd 上验收 `prs socks5 secure`。
# 用官方 v0.3.2 Release 在干净的 Ubuntu 24.04 runner 上创建两个公网无认证 SOCKS5 旧节点，
# 换成当前源码后实际执行 secure（--auth / --local），用 shoes.service、监听表、
# 经代理取回标记文件和 v0.2.1 info 核对同一份提交结果。
# 以 root 运行。节点凭据、分享链接和 info 输出只写进 0700 私有临时目录，不进 Actions 输出。
set -euo pipefail

old_tag=v0.3.2
compat_tag=v0.2.1
auth_node=legacy-socks-auth
auth_port=24451
local_node=legacy-socks-local
local_port=24452
asset=ping-rust-x86_64-unknown-linux-musl.tar.gz

: "${NEW_PING_RUST:?NEW_PING_RUST must point to the current build}"
. /etc/os-release
test "$ID" = ubuntu
test "$VERSION_ID" = 24.04
test "$(uname -m)" = x86_64
test ! -e /usr/local/bin/shoes
test ! -e /etc/shoes
test ! -e /etc/systemd/system/shoes.service

export NO_COLOR=1 TERM=dumb
umask 077
work="$(mktemp -d)"
chmod 0700 "$work"
summary="${GITHUB_STEP_SUMMARY:?}"
http_pid=
record() { printf '%s\n' "$*" | tee -a "$summary"; }
record "### SOCKS5 secure: $old_tag public no-auth → current source (#153)"

# 失败时只打印脱敏后的 stderr 末尾；stdout（含凭据、链接）一律不打印、不上传。
trap 'status=$?
if [[ -n "$http_pid" ]]; then kill "$http_pid" 2>/dev/null || true; fi
if (( status != 0 )); then
  record "FAILED: exit=$status; no retry performed"
  python3 - "$work" <<"PY"
import pathlib, re, sys
for path in sorted(pathlib.Path(sys.argv[1]).glob("*.stderr")):
    text = path.read_text(errors="replace")
    text = re.sub(r"(?:https?|vless|socks5h?)://\S+", "[redacted-link]", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[redacted-address]", text)
    text = re.sub(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b", "[redacted-id]", text)
    text = re.sub(r"(?i)(password|密码|用户名|username)\S*\s*[=:]\s*\S+", r"\1=[redacted]", text)
    print(path.name + ": " + text[-6000:])
PY
fi' EXIT

fetch_release() {
  local tag="$1" dir="$2" name
  mkdir -p "$dir"
  for name in "$asset" SHA256SUMS; do
    curl --fail --silent --show-error --location --retry 3 --max-time 180 \
      --proto '=https' --tlsv1.2 --output "$dir/$name" \
      "https://github.com/Jyanbai/ping-rust/releases/download/$tag/$name"
  done
  # 旧版 SHA256SUMS 可能用 "*文件名" 的二进制模式写法。
  grep -E "[[:space:]]\*?${asset//./\\.}\$" "$dir/SHA256SUMS" > "$dir/asset.sha256"
  test "$(wc -l < "$dir/asset.sha256")" -eq 1
  (cd "$dir" && sha256sum --check --strict asset.sha256 >/dev/null)
  tar -xzf "$dir/$asset" -C "$dir"
  test "$("$dir/ping-rust" --version)" = "ping-rust ${tag#v}"
}

run_command() {
  local label="$1" expected="$2" status=0
  shift 2
  "$@" </dev/null >"$work/$label.stdout" 2>"$work/$label.stderr" || status=$?
  record "$label: exit=$status"
  if [[ "$expected" == nonzero ]]; then test "$status" -ne 0
  else test "$status" -eq "$expected"; fi
}

main_pid() { systemctl show --property MainPID --value shoes.service; }

# listening <address-regex> <port>：监听表里存在本地地址匹配的 TCP 监听。
listening() {
  local table
  table="$(ss -H -lnt)"
  awk -v re="^(${1}):${2}\$" '$4 ~ re { found = 1 } END { exit !found }' <<< "$table"
}

assert_active() {
  systemctl is-active --quiet shoes.service
  test "$(main_pid)" -gt 0
}

wait_listening() {
  local _
  for _ in {1..20}; do
    if listening "$1" "$2"; then return 0; fi
    sleep 0.5
  done
  return 1
}

# probe <host> <port> [curl-config]：经 SOCKS5 访问本机 HTTP 标记文件，取回内容一致才算成功。
# 凭据只通过 0600 的 curl 配置文件传入，不出现在命令行或日志里。
probe() {
  local host="$1" port="$2" config="${3:-}" args
  args=(--silent --max-time 8 --output "$work/probe.body" --proxy "socks5://$host:$port")
  if [[ -n "$config" ]]; then args+=(--config "$config"); fi
  rm -f "$work/probe.body"
  curl "${args[@]}" http://127.0.0.1:18080/marker 2>>"$work/probe.stderr" || return 1
  [[ "$(< "$work/probe.body")" == "$marker" ]]
}

expect_probe() {
  local label="$1" expected="$2"
  shift 2
  if probe "$@"; then
    test "$expected" = ok || { record "$label: unexpectedly reachable"; return 1; }
  else
    test "$expected" = refused || { record "$label: unexpectedly unreachable"; return 1; }
  fi
  record "$label: $expected"
}

snapshot() {
  { sha256sum /etc/shoes/config.yaml /etc/shoes/ping-rust-state.json
    find /etc/shoes/profiles -maxdepth 1 -type f -exec sha256sum {} + | LC_ALL=C sort
  } > "$1"
}

# 从受管 state 取出节点的 SOCKS5 凭据，写成 curl 配置文件（0600）。
write_credentials() {
  python3 - "$1" "$2" <<'PY'
import json, sys
state = json.load(open('/etc/shoes/ping-rust-state.json'))
matches = [p for p in state['profiles'] if p.get('name') == sys.argv[1]]
assert len(matches) == 1, 'profile not found exactly once'
creds = matches[0]['credentials']['Socks5']
user, password = creds.get('username'), creds.get('password')
assert user and password, 'SOCKS5 credentials missing after secure --auth'
for value in (user, password):
    assert all(c not in value for c in ':"\\\n'), 'credential not representable in curl config'
with open(sys.argv[2], 'w') as f:
    f.write(f'proxy-user = "{user}:{password}"\n')
PY
}

# 公网可达性要用非回环地址探测。
read -r public_ip _ <<< "$(hostname -I)"
[[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$public_ip" != 127.* ]] \
  || { record 'no non-loopback IPv4 address on runner'; exit 1; }
record 'probe targets: loopback and the runner non-loopback IPv4'

marker="socks5-secure-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
mkdir -p "$work/http"
printf '%s' "$marker" > "$work/http/marker"
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work/http" \
  >"$work/http.log" 2>&1 &
http_pid=$!
for _ in {1..20}; do
  if curl --silent --max-time 2 --output /dev/null http://127.0.0.1:18080/marker; then break; fi
  sleep 0.5
done
curl --silent --fail --max-time 2 --output /dev/null http://127.0.0.1:18080/marker

# 1. 官方 v0.3.2 创建两个公网无认证旧节点。
fetch_release "$old_tag" "$work/old"
old="$work/old/ping-rust"
run_command install-old 0 "$old" install --method release
for spec in "$auth_node:$auth_port" "$local_node:$local_port"; do
  run_command "add-${spec%%:*}" 0 "$old" add socks5 --no-auth \
    --name "${spec%%:*}" --port "${spec##*:}" --server-address 127.0.0.1 --yes --plain
done
assert_active
wait_listening '0\.0\.0\.0|\*|\[::\]' "$auth_port"
wait_listening '0\.0\.0\.0|\*|\[::\]' "$local_port"
expect_probe 'legacy auth-node via public IP without credentials' ok "$public_ip" "$auth_port"
expect_probe 'legacy local-node via public IP without credentials' ok "$public_ip" "$local_port"

# 2. 换成当前源码。
install -m 0755 "$NEW_PING_RUST" /usr/local/bin/ping-rust
new=/usr/local/bin/ping-rust
assert_active

# 非交互且未指定模式必须拒绝，且不改任何文件。
snapshot "$work/before.sha256"
run_command secure-no-mode nonzero "$new" socks5 secure "$auth_node" --yes
grep -Fq '必须显式指定 --auth 或 --local' "$work/secure-no-mode.stderr"

# 3. --dry-run 不写文件、不重启服务。
pid_before="$(main_pid)"
run_command secure-dry-run 0 "$new" socks5 secure "$auth_node" --auth --dry-run
snapshot "$work/after-dry-run.sha256"
cmp -s "$work/before.sha256" "$work/after-dry-run.sha256" \
  || { record 'dry-run changed managed files'; exit 1; }
test "$(main_pid)" = "$pid_before" || { record 'dry-run restarted shoes'; exit 1; }
expect_probe 'after dry-run: auth-node still open' ok "$public_ip" "$auth_port"
record 'dry-run: managed files and MainPID unchanged'

# 4. --auth：保留公网监听，无凭据被拒，新凭据可用；另一个节点不受影响。
run_command secure-auth 0 "$new" socks5 secure "$auth_node" --auth --yes
assert_active
wait_listening '0\.0\.0\.0|\*|\[::\]' "$auth_port"
write_credentials "$auth_node" "$work/auth.curlrc"
expect_probe 'auth-node via public IP without credentials' refused "$public_ip" "$auth_port"
expect_probe 'auth-node via public IP with new credentials' ok "$public_ip" "$auth_port" "$work/auth.curlrc"
expect_probe 'local-node untouched by auth-node secure' ok "$public_ip" "$local_port"

# 5. --local：只监听回环，公网不可达，回环仍可用；已加固的认证节点保持可用。
run_command secure-local 0 "$new" socks5 secure "$local_node" --local --yes
assert_active
wait_listening '127\.0\.0\.1' "$local_port"
if listening '0\.0\.0\.0|\*|\[::\]' "$local_port"; then
  record 'local-node still has a wildcard listener'; exit 1
fi
expect_probe 'local-node via public IP' refused "$public_ip" "$local_port"
expect_probe 'local-node via loopback' ok 127.0.0.1 "$local_port"
expect_probe 'auth-node credentials survive the second restart' ok "$public_ip" "$auth_port" "$work/auth.curlrc"
expect_probe 'auth-node still rejects anonymous clients' refused "$public_ip" "$auth_port"

# 6. 再次执行：已安全的节点返回“无需修复”、退出码 0、不重启。
pid_before="$(main_pid)"
snapshot "$work/before-rerun.sha256"
run_command rerun-auth 0 "$new" socks5 secure "$auth_node" --auth --yes
run_command rerun-local 0 "$new" socks5 secure "$local_node" --local --yes
grep -Fq '无需修复' "$work/rerun-auth.stdout"
grep -Fq '无需修复' "$work/rerun-local.stdout"
snapshot "$work/after-rerun.sha256"
cmp -s "$work/before-rerun.sha256" "$work/after-rerun.sha256" \
  || { record 'rerun on secured nodes changed managed files'; exit 1; }
test "$(main_pid)" = "$pid_before" || { record 'rerun restarted shoes'; exit 1; }
record 'rerun: both nodes report no fix needed; files and MainPID unchanged'

# 7. v0.2.1 能读取加固后写出的 state（向后兼容红线）。
fetch_release "$compat_tag" "$work/compat"
run_command v021-info-auth 0 "$work/compat/ping-rust" info "$auth_node"
run_command v021-info-local 0 "$work/compat/ping-rust" info "$local_node"
grep -Fq '用户名 (username)' "$work/v021-info-auth.stdout" \
  || { record 'v0.2.1 info does not show credentials for the auth node'; exit 1; }
record 'v0.2.1 info: reads both secured profiles; auth node shows credentials'

record "SOCKS5 secure on real systemd: PASS"
