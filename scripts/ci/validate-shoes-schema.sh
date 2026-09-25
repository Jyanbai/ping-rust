#!/usr/bin/env bash
set -euo pipefail

echo '::group::Validate and exercise chain proxy with fixed shoes revision'
(
shoes --dry-run examples/chain-proxy.yaml
shoes --dry-run examples/chain-e2e-upstream.yaml
shoes --dry-run examples/chain-e2e-downstream.yaml
shoes --dry-run examples/chain-e2e-client.yaml
shoes --dry-run examples/socks5.yaml
shoes --dry-run examples/socks5-no-udp.yaml
shoes --dry-run examples/socks5-no-auth.yaml
shoes --dry-run examples/snell.yaml
cargo test --locked --test chain_proxy_e2e -- --nocapture
cargo test --locked pinned_schema_accepts_full_v2_rule_shape -- --nocapture
cargo test --locked --test chain_v2_e2e -- --nocapture
)
echo '::endgroup::'

echo '::group::Generate and validate every protocol'
(
set -euo pipefail
bin="${PING_RUST_BIN:-$PWD/target/debug/ping-rust}"
out="$PWD/target/shoes-validation"
mkdir -p "$out"

"$bin" generate reality --output "$out/reality.yaml" \
  --port 1443 --server-name www.cloudflare.com \
  --dest www.cloudflare.com:443 >/dev/null
"$bin" generate hysteria2 --output "$out/hysteria2.yaml" \
  --port 2443 --server-name hy2.example.com --quic-endpoints 1 >/dev/null
"$bin" generate tuic --output "$out/tuic.yaml" \
  --port 3443 --server-name tuic.example.com --zero-rtt >/dev/null
"$bin" generate shadowsocks --output "$out/shadowsocks.yaml" \
  --port 4388 >/dev/null
"$bin" generate shadowsocks --shadowtls \
  --output "$out/shadowsocks-shadowtls.yaml" --port 4389 \
  --server-name www.cloudflare.com \
  --password AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
  --shadowtls-password shadowtls-e2e-password >/dev/null
"$bin" generate anytls --output "$out/anytls.yaml" \
  --port 5443 --server-name anytls.example.com \
  --user alice:anytls-test-password \
  --padding stop=8 --padding 0=30-30 --padding 1=50-100 \
  --fallback 127.0.0.1:80 >/dev/null
"$bin" generate vless-tls --output "$out/vless-tls.yaml" \
  --port 6443 --server-name vless-tls.example.com >/dev/null
"$bin" generate vless-ws-tls --output "$out/vless-ws-tls.yaml" \
  --port 6444 --server-name vless-ws.example.com \
  --websocket-path /vless >/dev/null
"$bin" generate trojan-tls --output "$out/trojan-tls.yaml" \
  --port 6445 --server-name trojan.example.com >/dev/null
"$bin" generate trojan-reality --output "$out/trojan-reality.yaml" \
  --port 6446 --server-name www.cloudflare.com \
  --dest www.cloudflare.com:443 >/dev/null
"$bin" generate vmess-ws-tls --output "$out/vmess-ws-tls.yaml" \
  --port 6447 --server-name vmess.example.com \
  --websocket-path /vmess >/dev/null
"$bin" generate snell --output "$out/snell.yaml" \
  --port 6448 --password snell-test-password >/dev/null
"$bin" generate socks5 --output "$out/socks5.yaml" \
  --port 6449 --username default --password socks5-test-password >/dev/null
"$bin" generate naiveproxy --output "$out/naiveproxy-self-signed.yaml" \
  --port 6450 --server-name naive.example.com --self-signed >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$out/naive-key.pem" -out "$out/naive-cert.pem" \
  -days 1 -subj '/CN=naive.example.com' \
  -addext 'subjectAltName=DNS:naive.example.com' >/dev/null 2>&1
"$bin" generate naiveproxy --output "$out/naiveproxy-external.yaml" \
  --port 6451 --server-name naive.example.com \
  --cert "$out/naive-cert.pem" --key "$out/naive-key.pem" \
  --username naive-e2e --password naive-e2e-pass >/dev/null
"$bin" generate naiveproxy --output "$out/naiveproxy-no-padding.yaml" \
  --port 6452 --server-name naive.example.com \
  --cert "$out/naive-cert.pem" --key "$out/naive-key.pem" \
  --no-padding >/dev/null
mkdir -p "$out/naive-static"
"$bin" generate naiveproxy --output "$out/naiveproxy-fallback.yaml" \
  --port 6453 --server-name naive.example.com \
  --cert "$out/naive-cert.pem" --key "$out/naive-key.pem" \
  --fallback "$out/naive-static" >/dev/null

for config in \
  reality hysteria2 tuic shadowsocks shadowsocks-shadowtls anytls \
  vless-tls vless-ws-tls trojan-tls trojan-reality vmess-ws-tls snell socks5 \
  naiveproxy-self-signed naiveproxy-external naiveproxy-no-padding \
  naiveproxy-fallback; do
  shoes --dry-run "$out/$config.yaml"
done
cat \
  "$out/reality.yaml" \
  "$out/hysteria2.yaml" \
  "$out/tuic.yaml" \
  "$out/shadowsocks.yaml" \
  "$out/shadowsocks-shadowtls.yaml" \
  "$out/anytls.yaml" \
  "$out/vless-tls.yaml" \
  "$out/vless-ws-tls.yaml" \
  "$out/trojan-tls.yaml" \
  "$out/trojan-reality.yaml" \
  "$out/vmess-ws-tls.yaml" \
  "$out/snell.yaml" \
  "$out/socks5.yaml" \
  "$out/naiveproxy-external.yaml" >"$out/all-twelve.yaml"
shoes --dry-run "$out/all-twelve.yaml"
grep -F "alpn_protocols:" "$out/naiveproxy-self-signed.yaml"
grep -F "type: naiveproxy" "$out/naiveproxy-self-signed.yaml"
grep -F "padding: false" "$out/naiveproxy-no-padding.yaml"
grep -F "fallback: $out/naive-static" "$out/naiveproxy-fallback.yaml"
sed 's/udp_enabled: false/udp_enabled: true/' \
  "$out/naiveproxy-no-padding.yaml" >"$out/naiveproxy-udp-schema.yaml"
shoes --dry-run "$out/naiveproxy-udp-schema.yaml"
)
echo '::endgroup::'

echo '::group::Start every generated listener'
(
set -euo pipefail
out="$PWD/target/shoes-validation"
shoes "$out/all-twelve.yaml" >"$out/runtime.log" 2>&1 &
shoes_pid="$!"
python3 -m http.server 18080 --bind 127.0.0.1 \
  >"$out/socks-origin.log" 2>&1 &
origin_pid="$!"
cat >"$out/shadowtls-client.yaml" <<'YAML'
- address: 127.0.0.1:10888
  protocol:
    type: socks
    udp_enabled: false
  rules:
    - masks: 0.0.0.0/0
      action: allow
      client_chains:
        address: 127.0.0.1:4389
        protocol:
          type: shadowtls
          password: shadowtls-e2e-password
          sni_hostname: www.cloudflare.com
          protocol:
            type: shadowsocks
            cipher: 2022-blake3-aes-256-gcm
            password: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            udp_enabled: false
YAML
shoes "$out/shadowtls-client.yaml" >"$out/shadowtls-client.log" 2>&1 &
shadowtls_client_pid="$!"
cat >"$out/naive-client.yaml" <<'YAML'
- address: 127.0.0.1:10889
  protocol:
    type: socks
    udp_enabled: false
  rules:
    - masks: 0.0.0.0/0
      action: allow
      client_chains:
        address: 127.0.0.1:6451
        protocol:
          type: tls
          verify: false # acceptance fixture uses a local self-signed certificate
          sni_hostname: naive.example.com
          alpn_protocols: ["h2"]
          protocol:
            type: naiveproxy
            username: naive-e2e
            password: naive-e2e-pass
            padding: true
YAML
shoes --dry-run "$out/naive-client.yaml"
shoes "$out/naive-client.yaml" >"$out/naive-client.log" 2>&1 &
naive_client_pid="$!"
trap 'kill "$shoes_pid" "$origin_pid" "$shadowtls_client_pid" "$naive_client_pid" 2>/dev/null || true' EXIT
for _ in {1..40}; do
  tcp_ports="$(ss -H -lnt | awk '{print $4}')"
  udp_ports="$(ss -H -lun | awk '{print $4}')"
  if grep -Eq '(^|:)1443$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)4388$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)4389$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)5443$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)6443$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)6444$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)6445$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)6446$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)6447$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)6448$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)6449$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)6451$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)10888$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)10889$' <<<"$tcp_ports" \
    && grep -Eq '(^|:)2443$' <<<"$udp_ports" \
    && grep -Eq '(^|:)3443$' <<<"$udp_ports"; then
    curl --fail --silent --show-error \
      --socks5-hostname 127.0.0.1:6449 \
      --proxy-user default:socks5-test-password \
      http://127.0.0.1:18080/ >/dev/null
    curl --fail --silent --show-error \
      --socks5-hostname 127.0.0.1:10888 \
      http://127.0.0.1:18080/ >/dev/null
    curl --fail --silent --show-error \
      --socks5-hostname 127.0.0.1:10889 \
      http://127.0.0.1:18080/ >/dev/null
    exit 0
  fi
  sleep 0.25
done
cat "$out/runtime.log" >&2
cat "$out/shadowtls-client.log" >&2
cat "$out/naive-client.log" >&2
exit 1
)
echo '::endgroup::'

echo '::group::Validate all Shadowsocks ciphers and Reality plus AnyTLS'
(
set -euo pipefail
bin="$PWD/target/debug/ping-rust"
out="$PWD/target/shoes-validation"
ciphers=(
  aes-128-gcm
  aes-256-gcm
  chacha20-ietf-poly1305
  2022-blake3-aes-128-gcm
  2022-blake3-aes-256-gcm
  2022-blake3-chacha20-ietf-poly1305
)
passwords=(
  legacy-aes-128-password
  legacy-aes-256-password
  legacy-chacha-password
  AAAAAAAAAAAAAAAAAAAAAA==
  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
)
for index in "${!ciphers[@]}"; do
  config="$out/ss-$index.yaml"
  "$bin" generate shadowsocks --output "$config" \
    --port "$((6000 + index))" \
    --cipher "${ciphers[$index]}" \
    --password "${passwords[$index]}" >/dev/null
  shoes --dry-run "$config"
done

"$bin" generate shadowsocks --shadowtls \
  --output "$out/ss-shadowtls-default.yaml" --port 6200 \
  --server-name www.cloudflare.com >/dev/null
"$bin" generate shadowsocks --shadowtls \
  --output "$out/ss-shadowtls-aes128.yaml" --port 6201 \
  --server-name www.cloudflare.com \
  --cipher 2022-blake3-aes-128-gcm >/dev/null
"$bin" generate shadowsocks --shadowtls \
  --output "$out/ss-shadowtls-handshake.yaml" --port 6202 \
  --server-name www.cloudflare.com \
  --handshake www.example.com:443 >/dev/null
for config in "$out"/ss-shadowtls-*.yaml; do
  shoes --dry-run "$config"
  grep -F "shadowtls_targets:" "$config"
  grep -F "type: shadowsocks" "$config"
  grep -F "udp_enabled: false" "$config"
done

snell_ciphers=(aes-128-gcm aes-256-gcm chacha20-ietf-poly1305)
for index in "${!snell_ciphers[@]}"; do
  config="$out/snell-$index.yaml"
  "$bin" generate snell --output "$config" \
    --port "$((6100 + index))" \
    --cipher "${snell_ciphers[$index]}" \
    --password "snell-password-$index" >/dev/null
  shoes --dry-run "$config"
done
"$bin" generate snell --output "$out/snell-no-udp.yaml" \
  --port 6103 --cipher chacha20-ietf-poly1305 \
  --password snell-no-udp-password --no-udp >/dev/null
shoes --dry-run "$out/snell-no-udp.yaml"
grep -F "udp_enabled: false" "$out/snell-no-udp.yaml"
if "$bin" generate snell --output "$out/snell-invalid.yaml" \
  --port 6110 --cipher 2022-blake3-aes-256-gcm >"$out/snell-invalid.log" 2>&1; then
  echo "Snell unexpectedly accepted a 2022 cipher" >&2
  exit 1
fi
grep -F "Snell v3 不支持加密方式" "$out/snell-invalid.log"

"$bin" generate socks5 --output "$out/socks5-auth-udp.yaml" \
  --port 6120 --username alice --password socks-secret --udp >/dev/null
"$bin" generate socks5 --output "$out/socks5-auth-tcp.yaml" \
  --port 6121 --username alice --password socks-secret --no-udp >/dev/null
"$bin" generate socks5 --output "$out/socks5-no-auth.yaml" \
  --port 6122 --no-auth >/dev/null
for config in "$out"/socks5-{auth-udp,auth-tcp,no-auth}.yaml; do
  shoes --dry-run "$config"
done
grep -F "udp_enabled: true" "$out/socks5-auth-udp.yaml"
grep -F "udp_enabled: false" "$out/socks5-auth-tcp.yaml"
if grep -Eq 'username:|password:' "$out/socks5-no-auth.yaml"; then
  echo "SOCKS5 no-auth fixture unexpectedly contains credentials" >&2
  exit 1
fi

"$bin" generate anytls --output "$out/anytls-reality.yaml" \
  --port 7443 --anytls-mode reality \
  --server-name www.cloudflare.com \
  --dest www.cloudflare.com:443 \
  --user advanced:anytls-reality-password >/dev/null
shoes --dry-run "$out/anytls-reality.yaml"
)
echo '::endgroup::'
