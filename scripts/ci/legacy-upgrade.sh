#!/usr/bin/env bash
# Run each scenario on its own clean Ubuntu 24.04 systemd runner.
set -euo pipefail
scenario="${1:?L1 or C2 required}"
case "$scenario" in
  L1) old_tag=v0.1.20 ;;
  C2) old_tag=v0.2.2 ;;
  *) exit 2 ;;
esac
. /etc/os-release
test "$ID" = ubuntu
test "$VERSION_ID" = 24.04
test "$(uname -m)" = x86_64
test ! -e /usr/local/bin/shoes
test ! -e /var/lib/ping-rust/shoes-install.json
test ! -e /etc/shoes
test ! -e /etc/systemd/system/shoes.service
export NO_COLOR=1 TERM=dumb
work="$(mktemp -d)"
chmod 0700 "$work"
summary="${GITHUB_STEP_SUMMARY:?}"
port=24431
unknown='无法确认当前 shoes 的安装来源'
asset=ping-rust-x86_64-unknown-linux-musl.tar.gz
record() { printf '%s\n' "$*" | tee -a "$summary"; }
record "### $scenario: $old_tag → current source"

# Keep node material in the private temporary directory, never in Actions output.
# On failure print sanitized diagnostics only; never upload runtime state/config.
trap 'status=$?; if (( status != 0 )); then
  record "FAILED: exit=$status; no retry performed"
  python3 - "$work" <<"PY"
import pathlib, re, sys
for path in sorted(pathlib.Path(sys.argv[1]).glob("*.stderr")):
    text = path.read_text(errors="replace")
    text = re.sub(r"https?://\S+|vless://\S+", "[redacted-link]", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[redacted-address]", text)
    text = re.sub(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b", "[redacted-id]", text)
    print(path.name + ": " + text[-6000:])
PY
fi' EXIT

for name in "$asset" SHA256SUMS; do
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "$work/$name" \
    "https://github.com/Jyanbai/ping-rust/releases/download/$old_tag/$name"
done
(cd "$work" && grep -F "  $asset" SHA256SUMS | sha256sum --check --strict)
tar -xzf "$work/$asset" -C "$work"
old="$work/ping-rust"
test "$("$old" --version)" = "ping-rust ${old_tag#v}"

run_command() {
  local label="$1" expected="$2" status=0
  shift 2
  "$@" >"$work/$label.stdout" 2>"$work/$label.stderr" || status=$?
  record "$label: exit=$status"
  if [[ "$expected" == nonzero ]]; then test "$status" -ne 0
  else test "$status" -eq "$expected"; fi
}
assert_runtime() {
  local label="$1" listening=false
  systemctl is-active --quiet shoes.service
  for _ in {1..20}; do
    if ss -H -lnt | awk '{print $4}' | grep -Eq "(^|:)$port$"; then
      listening=true; break
    fi
    sleep 0.5
  done
  test "$listening" = true
  record "$label: shoes=active; original TCP port $port=listening"
}
record_source() {
  local label="$1"
  if [[ -e /var/lib/ping-rust/shoes-install.json ]]; then
    python3 - "$label" "$summary" <<'PY'
import json, os, stat, sys
path = '/var/lib/ping-rust/shoes-install.json'
p = json.load(open(path))
line = f"{sys.argv[1]}: provenance=present; mode={stat.S_IMODE(os.stat(path).st_mode):04o}; source={p['source']}"
print(line)
with open(sys.argv[2], 'a') as f: f.write(line + '\n')
PY
  else record "$label: provenance=absent"; fi
}
assert_recorded() {
  python3 - <<'PY'
import hashlib, json, os, stat
path = '/var/lib/ping-rust/shoes-install.json'
assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
p = json.load(open(path))
assert p['source'] == 'github-release'
assert p['binary_sha256'] == hashlib.sha256(open('/usr/local/bin/shoes', 'rb').read()).hexdigest()
PY
  record 'provenance assertions: mode=0600; source=github-release; binary SHA-256 matches'
}
run_command install-old 0 "$old" install --method release
# The old installer may resolve the then-current upstream latest: record, do not assume.
version="$(grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?' "$work/install-old.stdout" | head -1)"
test -n "$version"
record "Actual shoes Release selected by $old_tag: $version (installer output)"
record "Initial shoes SHA-256: $(sha256sum /usr/local/bin/shoes | cut -d ' ' -f 1)"
record_source install-old
if [[ "$scenario" == L1 ]]; then test ! -e /var/lib/ping-rust/shoes-install.json
else assert_recorded; fi
run_command add-original-node 0 "$old" add reality --name legacy-reality \
  --port "$port" --server-address 127.0.0.1 --server-name www.cloudflare.com --yes --plain
assert_runtime legacy-installed
record_source legacy-installed
run_command replace-ping-rust 0 install -m 0755 "$NEW_PING_RUST" /usr/local/bin/ping-rust
assert_runtime replaced
record_source replaced
if [[ "$scenario" == L1 ]]; then
  run_command first-update nonzero /usr/local/bin/ping-rust update --method release
  grep -Fq "$unknown" "$work/first-update.stderr"
  record "first-update stderr: $unknown"
  test ! -e /var/lib/ping-rust/shoes-install.json
  record_source first-update
  assert_runtime first-update
  run_command allowed-update 0 /usr/local/bin/ping-rust update --method release --allow-downgrade
  assert_recorded
  record_source allowed-update
  assert_runtime allowed-update
  record "allowed-update stderr: unknown-guidance=$(grep -Fc "$unknown" "$work/allowed-update.stderr" || true)"
fi
run_command normal-update 0 /usr/local/bin/ping-rust update --method release
! grep -Fq "$unknown" "$work/normal-update.stderr"
! grep -Fq "$unknown" "$work/normal-update.stdout"
record 'normal-update stderr: no unknown-source guidance'
assert_recorded
record_source normal-update
assert_runtime normal-update
record "$scenario: PASS"
