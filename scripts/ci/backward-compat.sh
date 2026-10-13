#!/usr/bin/env bash
# Backward-compat acceptance: files written by the new build must be read by the
# published v0.2.1 Release binary with identical info/export output.
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
set -x
jq -e '.chain_proxy.enabled == true and (.chain_proxy.nodes | length) >= 1' /etc/shoes/ping-rust-state.json >/dev/null \
  || { echo "Chain 2.0 state missing"; jq '.chain_proxy' /etc/shoes/ping-rust-state.json | sed -E 's/"(password|uuid|private_key|key)": "[^"]*"/"\1": "<redacted>"/g'; exit 1; }
mapfile -t ids < <(jq -r '.profiles[].id' /etc/shoes/ping-rust-state.json)
test "${#ids[@]}" -eq 2
find /etc/shoes -type f -exec sha256sum {} + | sort -k2 >"$WORK/hash-before"

capture() {
  local bin="$1" out="$2"
  "$bin" info >"$out/info" 2>&1
  for id in "${ids[@]}"; do
    for fmt in clash-meta sing-box nekobox; do
      "$bin" export "$fmt" --profile "$id" --server "$SERVER" >"$out/export-$fmt-$id" 2>&1
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
diff -ru "$WORK/new" "$WORK/old"
count="$(find "$WORK/new" -type f | wc -l)"
echo "compared $count outputs: identical"

/usr/local/bin/shoes --dry-run /etc/shoes/config.yaml
echo "backward compatibility: PASS"
