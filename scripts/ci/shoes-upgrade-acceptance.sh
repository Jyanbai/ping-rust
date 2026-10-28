#!/usr/bin/env bash
# Debian 12 systemd acceptance for the v0.2.2 -> v0.3.6 migration path.
# All external release assets are pinned by version and SHA-256.
set -euo pipefail

NEW_PING_RUST="${NEW_PING_RUST:-/opt/ping-rust-current/bin/ping-rust}"
WORK="${WORK:-/tmp/ping-rust-shoes-upgrade}"
OLD_TAG=v0.2.2
OLD_ASSET=ping-rust-x86_64-unknown-linux-musl.tar.gz
OLD_ASSET_SHA256=66a8502a199c31971ab474545ecc18661c4cfd2dc1b0afe81511b33aaf04ba0b
OLD_SHOES_VERSION=0.2.7
NEW_SHOES_VERSION=0.3.6
SERVER=127.0.0.1
export NO_COLOR=1 TERM=dumb
mkdir -p "$WORK/download" "$WORK/records"

download_release() {
  local url="$1" output="$2"
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 \
    --output "$output" "$url"
}

echo '== verify and install ping-rust v0.2.2 Release'
download_release \
  "https://github.com/Jyanbai/ping-rust/releases/download/${OLD_TAG}/${OLD_ASSET}" \
  "$WORK/download/$OLD_ASSET"
download_release \
  "https://github.com/Jyanbai/ping-rust/releases/download/${OLD_TAG}/SHA256SUMS" \
  "$WORK/download/SHA256SUMS"
(cd "$WORK/download" && grep -F "  $OLD_ASSET" SHA256SUMS | sha256sum -c --strict)
echo "$OLD_ASSET_SHA256  $WORK/download/$OLD_ASSET" | sha256sum -c --strict
tar -xzf "$WORK/download/$OLD_ASSET" -C "$WORK/download"
OLD_PING_RUST="$WORK/download/ping-rust"
test -x "$OLD_PING_RUST"
"$OLD_PING_RUST" --version | grep -Fx 'ping-rust 0.2.2'

"$OLD_PING_RUST" install --method release >"$WORK/records/install-old.txt" 2>&1
grep -Fq "v${OLD_SHOES_VERSION}" "$WORK/records/install-old.txt"
"$OLD_PING_RUST" add reality \
  --name legacy-reality --port 24431 --server-address "$SERVER" \
  --server-name www.cloudflare.com --yes --plain >"$WORK/records/old-reality.txt"
"$OLD_PING_RUST" add snell \
  --name legacy-snell --port 24432 --server-address "$SERVER" \
  --yes >"$WORK/records/old-snell.txt"
reality_uri="$(head -n 1 "$WORK/records/old-reality.txt")"
expect "$(dirname "$0")/legacy-chain-menu.exp" "$OLD_PING_RUST" "$reality_uri" \
  >"$WORK/records/legacy-chain-menu.txt" 2>&1

systemctl is-active --quiet shoes.service
"$OLD_PING_RUST" info >"$WORK/records/info-old.txt"
sha256sum /etc/shoes/config.yaml /etc/shoes/ping-rust-state.json \
  >"$WORK/records/hash-before.txt"
find /etc/shoes/profiles -maxdepth 1 -type f -print0 \
  | sort -z | xargs -0 -r sha256sum >"$WORK/records/profiles-before.txt"
systemctl show --property=MainPID --value shoes.service >"$WORK/records/mainpid-before.txt"
cp /etc/shoes/config.yaml "$WORK/records/config-before.yaml"
cp /etc/shoes/ping-rust-state.json "$WORK/records/state-before.json"

echo '== replace ping-rust only; shoes remains v0.2.7'
install -m 0755 "$NEW_PING_RUST" /usr/local/bin/ping-rust
NEW=/usr/local/bin/ping-rust
"$NEW" info >"$WORK/records/info-new-with-old-shoes.txt"
grep -Fq '配置数量：2' "$WORK/records/info-new-with-old-shoes.txt"
grep -Fq 'shoes（CLI 未提供版本参数）' "$WORK/records/info-new-with-old-shoes.txt"
grep -Fq 'legacy-reality' "$WORK/records/info-new-with-old-shoes.txt"
grep -Fq 'legacy-snell' "$WORK/records/info-new-with-old-shoes.txt"
cmp /etc/shoes/config.yaml "$WORK/records/config-before.yaml"
cmp /etc/shoes/ping-rust-state.json "$WORK/records/state-before.json"
test "$(systemctl show --property=MainPID --value shoes.service)" = \
  "$(cat "$WORK/records/mainpid-before.txt")"

echo '== version mismatch: new ping-rust writes a typed candidate against old shoes'
expected_profiles=2
set +e
"$NEW" add shadowsocks --name mismatch-probe --port 24433 \
  --server-address "$SERVER" --yes --plain \
  >"$WORK/records/mismatch.txt" 2>&1
mismatch_status=$?
set -e
if [ "$mismatch_status" -eq 0 ]; then
  echo 'old shoes accepted domain_pattern; recording successful compatibility result'
  grep -Fq 'mismatch-probe' "$WORK/records/mismatch.txt"
  expected_profiles=3
else
  grep -Fq '请先升级 shoes' "$WORK/records/mismatch.txt"
  cmp /etc/shoes/config.yaml "$WORK/records/config-before.yaml"
  cmp /etc/shoes/ping-rust-state.json "$WORK/records/state-before.json"
fi
systemctl is-active --quiet shoes.service
test "$(systemctl show --property=MainPID --value shoes.service)" = \
  "$(cat "$WORK/records/mainpid-before.txt")"

echo '== transactional shoes upgrade and config migration'
"$NEW" update --method release >"$WORK/records/update.txt" 2>&1
grep -Fq "v${NEW_SHOES_VERSION}" "$WORK/records/update.txt"
systemctl is-active --quiet shoes.service
"$NEW" info >"$WORK/records/info-after.txt"
grep -Fq 'legacy-reality' "$WORK/records/info-after.txt"
grep -Fq 'legacy-snell' "$WORK/records/info-after.txt"
grep -Fq 'domain_pattern:' /etc/shoes/config.yaml
! grep -Fq "masks: '*.example.test'" /etc/shoes/config.yaml
/usr/local/bin/shoes --dry-run /etc/shoes/config.yaml
grep -Fq "配置数量：${expected_profiles}" "$WORK/records/info-after.txt"
expected_ports='24431|24432'
if [ "$expected_profiles" -eq 3 ]; then expected_ports='24431|24432|24433'; fi
test "$(ss -H -lnt | awk '{print $4}' | grep -Ec ":(${expected_ports})$")" -eq "$expected_profiles"

sha256sum /etc/shoes/config.yaml /etc/shoes/ping-rust-state.json \
  >"$WORK/records/hash-after.txt"
find /etc/shoes/profiles -maxdepth 1 -type f -print0 \
  | sort -z | xargs -0 -r sha256sum >"$WORK/records/profiles-after.txt"
systemctl show --property=MainPID --value shoes.service >"$WORK/records/mainpid-after.txt"
echo 'upgrade migration: PASS'
