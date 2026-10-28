#!/usr/bin/env bash
# External client acceptance for shoes v0.3.6. Every downloaded binary is
# pinned to a release and checked before execution. Snell results are recorded
# per cipher because Mihomo's schema only exposes the AES-128-GCM variant.
set -u -o pipefail

PING_RUST="${PING_RUST:-target/release/ping-rust}"
WORK="${WORK:-$RUNNER_TEMP/ping-rust-external-clients}"
SHOES_SHA256=d09a9f5915ae8c3fc933bd86c025f2d8878d45e1dee8f0e2bb404c920de8c707
XRAY_26_TAG=v26.6.27
XRAY_26_SHA256=b3e5902d06d6282fe53cfa2fc426058b9aeaa429b2c812e20887cd47f26d08bf
XRAY_MIN_TAG=v25.5.16
XRAY_MIN_SHA256=7679da6a3bb9dc2b3ce82d7f9f64ac1bb0e4bd6c3b9a0926613e5fc88abef25a
MIHOMO_TAG=v1.19.33
MIHOMO_SHA256=8ec92e7b2fdc6b853ba00156bab7e4e965c8b0d843b8c4ac8ab98795f02ad524
export NO_COLOR=1 TERM=dumb
mkdir -p "$WORK/bin" "$WORK/logs" "$WORK/http"
printf 'external client acceptance\n' >"$WORK/http/marker"

download_checked() {
  local url="$1" expected="$2" archive="$3"
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 \
    --output "$archive" "$url"
  echo "$expected  $archive" | sha256sum --check --strict
}

download_checked \
  "https://github.com/cfal/shoes/releases/download/v0.3.6/shoes-x86_64-unknown-linux-musl.tar.gz" \
  "$SHOES_SHA256" "$WORK/bin/shoes.tar.gz"
tar -xzf "$WORK/bin/shoes.tar.gz" -C "$WORK/bin"
SHOES="$WORK/bin/shoes"
test -x "$SHOES"

download_checked \
  "https://github.com/XTLS/Xray-core/releases/download/${XRAY_26_TAG}/Xray-linux-64.zip" \
  "$XRAY_26_SHA256" "$WORK/bin/xray-26.zip"
unzip -oq "$WORK/bin/xray-26.zip" xray -d "$WORK/bin/xray-26"
XRAY_26="$WORK/bin/xray-26/xray"
chmod 0755 "$XRAY_26"

download_checked \
  "https://github.com/XTLS/Xray-core/releases/download/${XRAY_MIN_TAG}/Xray-linux-64.zip" \
  "$XRAY_MIN_SHA256" "$WORK/bin/xray-min.zip"
unzip -oq "$WORK/bin/xray-min.zip" xray -d "$WORK/bin/xray-min"
XRAY_MIN="$WORK/bin/xray-min/xray"
chmod 0755 "$XRAY_MIN"

download_checked \
  "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_TAG}/mihomo-linux-amd64-v1-v1.19.33.gz" \
  "$MIHOMO_SHA256" "$WORK/bin/mihomo.gz"
gzip -dc "$WORK/bin/mihomo.gz" >"$WORK/bin/mihomo"
chmod 0755 "$WORK/bin/mihomo"
MIHOMO="$WORK/bin/mihomo"
sudo install -m 0755 "$SHOES" /usr/local/bin/shoes

python3 -m http.server 18080 --bind 127.0.0.1 --directory "$WORK/http" \
  >"$WORK/logs/http.log" 2>&1 &
HTTP_PID=$!
cleanup() {
  kill "$HTTP_PID" 2>/dev/null || true
  for pid in ${ACTIVE_PIDS:-}; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

wait_tcp() {
  local port="$1"
  for _ in $(seq 1 50); do
    if ss -H -lnt | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then return 0; fi
    sleep 0.1
  done
  return 1
}

run_reality() {
  local xray="$1" label="$2" sni="$3" port="$4"
  local prefix="$WORK/logs/reality-${label}"
  local config="$WORK/reality-${label}.yaml"
  local generated="$WORK/logs/reality-${label}.txt"
  "$PING_RUST" generate reality --name "reality-${label}" --port "$port" \
    --server-name "$sni" --dest "${sni}:443" --output "$config" \
    >"$generated" 2>&1 || return 1
  local uuid public_key short_id
  uuid="$(awk -F'：' '/^UUID：/ {print $2; exit}' "$generated")"
  public_key="$(awk -F'：' '/^Reality 公钥：/ {print $2; exit}' "$generated")"
  short_id="$(awk -F'：' '/^Short ID：/ {print $2; exit}' "$generated")"
  test -n "$uuid" -a -n "$public_key" -a -n "$short_id"

  "$SHOES" "$config" >"${prefix}-shoes.log" 2>&1 &
  local shoes_pid=$!
  ACTIVE_PIDS="$shoes_pid"
  wait_tcp "$port" || { kill "$shoes_pid" 2>/dev/null || true; return 1; }
  cat >"${prefix}-xray.json" <<JSON
{
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": 18081, "protocol": "socks", "settings": {"udp": false}}],
  "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": ${port}, "users": [{"id": "${uuid}", "encryption": "none", "flow": "xtls-rprx-vision"}]}]}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "${sni}", "fingerprint": "chrome", "password": "${public_key}", "publicKey": "${public_key}", "shortId": "${short_id}"}}}]
}
JSON
  "$xray" run -c "${prefix}-xray.json" >"${prefix}-xray.log" 2>&1 &
  local xray_pid=$!
  ACTIVE_PIDS="$shoes_pid $xray_pid"
  wait_tcp 18081 || { kill "$shoes_pid" "$xray_pid" 2>/dev/null || true; return 1; }
  curl --noproxy '' --fail --silent --show-error --max-time 10 \
    --proxy socks5h://127.0.0.1:18081 http://127.0.0.1:18080/marker \
    >"${prefix}-response.txt" 2>&1
  local result=$?
  if [ "$result" -eq 0 ]; then
    grep -Fxq 'external client acceptance' "${prefix}-response.txt"
    result=$?
  fi
  kill "$shoes_pid" "$xray_pid" 2>/dev/null || true
  ACTIVE_PIDS=""
  return "$result"
}

echo "xray ${XRAY_26_TAG}: $($XRAY_26 version 2>&1 | head -n 1)"
echo "xray ${XRAY_MIN_TAG}: $($XRAY_MIN version 2>&1 | head -n 1)"
legacy_fixture="$(cd "$(dirname "$0")/../../tests/fixtures/yaml/chain-v2" && pwd)/config.yaml"
"$SHOES" --dry-run "$legacy_fixture" >"$WORK/logs/v036-legacy-config-dry-run.txt" 2>&1 || true
cat >"$WORK/uuid-invalid.yaml" <<'YAML'
- address: 0.0.0.0:24431
  protocol:
    type: tls
    reality_targets:
      www.cloudflare.com:
        private_key: 5g9uB-7WdKRYFMta-oV8qJXELSzg1u5IpwdkRYFM5AA
        short_ids: [bcd85ab63e74bc5e]
        dest: www.cloudflare.com:443
        max_time_diff: 60000
        vision: true
        protocol:
          type: vless
          user_id: 85296b07-fa5c-63a7-d8f2-cdef418defa3
          udp_enabled: true
YAML
"$SHOES" --dry-run "$WORK/uuid-invalid.yaml" >"$WORK/logs/v036-invalid-uuid-dry-run.txt" 2>&1 || true
reality_results=()
snis=(www.amazon.com www.ebay.com www.paypal.com www.cloudflare.com dash.cloudflare.com aws.amazon.com)
index=0
for sni in "${snis[@]}"; do
  index=$((index + 1))
  port=$((25000 + index))
  if run_reality "$XRAY_26" "$index" "$sni" "$port"; then result=PASS; else result=FAIL; fi
  reality_results+=("${sni}=${result}")
  echo "reality xray ${XRAY_26_TAG} ${sni}: ${result}"
done
if run_reality "$XRAY_MIN" minimum www.cloudflare.com 25020; then
  minimum_result=PASS
  echo "reality xray ${XRAY_MIN_TAG} www.cloudflare.com: PASS"
else
  minimum_result=FAIL
  echo "reality xray ${XRAY_MIN_TAG} www.cloudflare.com: FAIL"
fi

snell_results=()
for cipher in aes-128-gcm aes-256-gcm chacha20-ietf-poly1305; do
  port=$((25100 + ${#snell_results[@]}))
  config="$WORK/snell-${cipher}.yaml"
  generated="$WORK/logs/snell-${cipher}.txt"
  password="snell-${cipher//[^a-z0-9]/-}-fixed-password"
  if [ "$cipher" = aes-128-gcm ]; then
    # Exercise the product's own Clash Meta exporter for the AES case.  The
    # other two ciphers are intentionally hand-written below because Mihomo's
    # Snell schema cannot represent their cipher choice.
    sudo rm -rf /etc/shoes
    sudo mkdir -p /etc/shoes
    if ! sudo "$PING_RUST" generate snell --name "snell-${cipher}" --port "$port" \
      --cipher "$cipher" --password "$password" --no-udp \
      --output /etc/shoes/config.yaml >"$generated" 2>&1; then
      snell_results+=("${cipher}=FAIL(generate)")
      continue
    fi
    sudo systemctl stop shoes.service 2>/dev/null || true
    sudo systemctl reset-failed shoes.service 2>/dev/null || true
    profile_id="$(sudo python3 -c 'import json; print(json.load(open("/etc/shoes/ping-rust-state.json"))["profiles"][0]["id"])')"
    if ! sudo "$PING_RUST" export clash-meta --profile "$profile_id" \
      --server 127.0.0.1 --output "$WORK/mihomo-${cipher}.yaml" \
      >>"$generated" 2>&1; then
      snell_results+=("${cipher}=FAIL(export)")
      continue
    fi
    sudo cp /etc/shoes/config.yaml "$config"
    sudo chmod a+r "$config" "$WORK/mihomo-${cipher}.yaml"
    cat >>"$WORK/mihomo-${cipher}.yaml" <<YAML
mixed-port: 18090
mode: global
log-level: info
proxy-groups:
  - name: GLOBAL
    type: select
    proxies: [snell-${cipher}]
YAML
  elif ! "$PING_RUST" generate snell --name "snell-${cipher}" --port "$port" \
      --cipher "$cipher" --password "$password" --no-udp --output "$config" \
      >"$generated" 2>&1; then
    snell_results+=("${cipher}=FAIL(generate)")
    continue
  fi
  "$SHOES" "$config" >"$WORK/logs/snell-${cipher}-shoes.log" 2>&1 &
  shoes_pid=$!
  ACTIVE_PIDS="$shoes_pid"
  wait_tcp "$port" || { kill "$shoes_pid" 2>/dev/null || true; snell_results+=("${cipher}=FAIL(server)"); continue; }
  if [ "$cipher" != aes-128-gcm ]; then
    cat >"$WORK/mihomo-${cipher}.yaml" <<YAML
mixed-port: 18090
mode: global
log-level: info
proxies:
  - name: snell-${cipher}
    type: snell
    server: 127.0.0.1
    port: ${port}
    psk: ${password}
    version: 3
    udp: false
proxy-groups:
  - name: GLOBAL
    type: select
    proxies: [snell-${cipher}]
YAML
  fi
  cp "$WORK/mihomo-${cipher}.yaml" "$WORK/logs/snell-${cipher}-client.yaml"
  "$MIHOMO" -f "$WORK/mihomo-${cipher}.yaml" >"$WORK/logs/snell-${cipher}-mihomo.log" 2>&1 &
  mihomo_pid=$!
  ACTIVE_PIDS="$shoes_pid $mihomo_pid"
  if wait_tcp 18090 && curl --noproxy '' --fail --silent --show-error --max-time 10 \
      --proxy http://127.0.0.1:18090 http://127.0.0.1:18080/marker \
      >"$WORK/logs/snell-${cipher}-response.txt" 2>&1 \
      && grep -Fxq 'external client acceptance' "$WORK/logs/snell-${cipher}-response.txt"; then
    result=PASS
  else
    result=FAIL
  fi
  kill "$shoes_pid" "$mihomo_pid" 2>/dev/null || true
  ACTIVE_PIDS=""
  snell_results+=("${cipher}=${result}")
  echo "snell mihomo ${MIHOMO_TAG} ${cipher}: ${result}"
done

printf '%s\n' "${reality_results[@]}" >"$WORK/logs/reality-summary.txt"
printf '%s\n' "${snell_results[@]}" >"$WORK/logs/snell-summary.txt"
chmod -R a+rX "$WORK"
echo 'external client acceptance complete'
if printf '%s\n' "${reality_results[@]}" | grep -Fq '=FAIL' || [ "$minimum_result" != PASS ]; then
  exit 1
fi
