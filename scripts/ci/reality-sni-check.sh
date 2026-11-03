#!/usr/bin/env bash
# Reality SNI candidate check (issue #62). For every domain in the candidate
# list: TLS 1.3 + h2 + certificate, no cross-host redirect, not on Cloudflare,
# shoes v0.3.6 Reality end-to-end with Xray (chrome fingerprint), camouflage
# certificate on unauthenticated connections, and ShadowTLS v3 end-to-end with
# Mihomo through ping-rust's own Clash Meta export. ASN, CNAME and a simulated
# mainland resolution are recorded as annotations only. Every downloaded binary
# is pinned to a release and checked before execution.
set -euo pipefail

PING_RUST="${PING_RUST:-target/release/ping-rust}"
CANDIDATES="${CANDIDATES:-data/reality-sni-candidates.txt}"
WORK="${WORK:-$RUNNER_TEMP/reality-sni-check}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
SHOES_SHA256=d09a9f5915ae8c3fc933bd86c025f2d8878d45e1dee8f0e2bb404c920de8c707
XRAY_TAG=v26.6.27
XRAY_SHA256=b3e5902d06d6282fe53cfa2fc426058b9aeaa429b2c812e20887cd47f26d08bf
MIHOMO_TAG=v1.19.33
MIHOMO_SHA256=8ec92e7b2fdc6b853ba00156bab7e4e965c8b0d843b8c4ac8ab98795f02ad524
# Browser-like User-Agent so redirect behaviour matches what browsers see.
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
# A mainland China network, used only as the EDNS client subnet when simulating
# mainland resolution (annotation only).
ECS_SUBNET=114.114.114.0/24
LOG="$WORK/logs"
export NO_COLOR=1 TERM=dumb
mkdir -p "$WORK/bin" "$LOG" "$WORK/http"
printf 'reality sni check\n' >"$WORK/http/marker"

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
sudo install -m 0755 "$SHOES" /usr/local/bin/shoes

download_checked \
  "https://github.com/XTLS/Xray-core/releases/download/${XRAY_TAG}/Xray-linux-64.zip" \
  "$XRAY_SHA256" "$WORK/bin/xray.zip"
unzip -oq "$WORK/bin/xray.zip" xray -d "$WORK/bin/xray"
XRAY="$WORK/bin/xray/xray"
chmod 0755 "$XRAY"

download_checked \
  "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_TAG}/mihomo-linux-amd64-v1-${MIHOMO_TAG}.gz" \
  "$MIHOMO_SHA256" "$WORK/bin/mihomo.gz"
gzip -dc "$WORK/bin/mihomo.gz" >"$WORK/bin/mihomo"
chmod 0755 "$WORK/bin/mihomo"
MIHOMO="$WORK/bin/mihomo"

python3 -m http.server 18080 --bind 127.0.0.1 --directory "$WORK/http" \
  >"$LOG/http.log" 2>&1 &
HTTP_PID=$!
ACTIVE_PIDS=""
cleanup() {
  kill "$HTTP_PID" 2>/dev/null || true
  for pid in $ACTIVE_PIDS; do kill "$pid" 2>/dev/null || true; done
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

stop_active() {
  for pid in $ACTIVE_PIDS; do kill "$pid" 2>/dev/null || true; done
  for pid in $ACTIVE_PIDS; do wait "$pid" 2>/dev/null || true; done
  ACTIVE_PIDS=""
}

reverse_ipv4() {
  local IFS=.
  # shellcheck disable=SC2086
  set -- $1
  printf '%s.%s.%s.%s' "$4" "$3" "$2" "$1"
}

# Prints "ASN|CC" for an IPv4 address via Team Cymru's DNS interface.
ip_origin() {
  local txt
  txt="$(dig +short +time=3 +tries=2 TXT "$(reverse_ipv4 "$1").origin.asn.cymru.com" 2>/dev/null \
    | head -n 1 | tr -d '"')" || true
  [ -n "$txt" ] || return 0
  awk -F' *[|] *' '{printf "%s|%s", $1, $3}' <<<"$txt"
}

asn_name() {
  dig +short +time=3 +tries=2 TXT "AS$1.asn.cymru.com" 2>/dev/null \
    | head -n 1 | tr -d '"' | awk -F' *[|] *' '{print $NF}' || true
}

is_ipv4() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

mark() {
  if [ "$1" = PASS ]; then printf '✅'; else printf '❌'; fi
}

# Sets TLS13, H2 and CERT to PASS/FAIL.
check_tls() {
  local d="$1" out
  out="$(timeout 15 openssl s_client -connect "${d}:443" -servername "$d" \
    -tls1_3 -alpn h2 -verify_return_error -verify_hostname "$d" </dev/null 2>&1)" || true
  printf '%s\n' "$out" >"$LOG/${d}-openssl.txt"
  if grep -Eq '^New, TLSv1\.3|Protocol *: *TLSv1\.3' <<<"$out"; then TLS13=PASS; else TLS13=FAIL; fi
  if grep -q '^ALPN protocol: h2$' <<<"$out"; then H2=PASS; else H2=FAIL; fi
  if grep -q 'Verify return code: 0 (ok)' <<<"$out"; then CERT=PASS; else CERT=FAIL; fi
}

# Sets REDIRECT and CF_HEADER to PASS/FAIL and HTTP_CODE.
check_http() {
  local d="$1" result redirect host
  result="$(curl --noproxy '' --silent --show-error --output /dev/null \
    --dump-header "$LOG/${d}-headers.txt" --max-time 15 --user-agent "$UA" \
    --write-out '%{http_code} %{redirect_url}' "https://${d}/" 2>"$LOG/${d}-curl.txt")" \
    || result="000 "
  HTTP_CODE="${result%% *}"
  redirect="${result#* }"
  REDIRECT=PASS
  if [[ "$HTTP_CODE" == 3* ]]; then
    host="$(sed -E 's#^[A-Za-z][A-Za-z0-9+.-]*://([^/:?#]+).*#\1#' <<<"$redirect" | tr 'A-Z' 'a-z')"
    if [ "$host" != "$d" ]; then REDIRECT=FAIL; fi
  elif [ "$HTTP_CODE" = 000 ]; then
    REDIRECT=FAIL
  fi
  CF_HEADER=PASS
  if grep -Eiq '^(cf-ray:|server: *cloudflare)' "$LOG/${d}-headers.txt" 2>/dev/null; then
    CF_HEADER=FAIL
  fi
}

# Sets ASN_INFO, CNAMES and CF_ASN (PASS/FAIL), MAINLAND (是/否/未知).
check_dns() {
  local d="$1" answers ip origin asn first_asn="" ecs_ips cc any_cn=0 any_ip=0
  answers="$(dig +short +time=3 +tries=2 A "$d" 2>/dev/null)" || true
  printf '%s\n' "$answers" >"$LOG/${d}-dns.txt"
  CNAMES="$(grep -v -E '^[0-9.]+$' <<<"$answers" | sed 's/\.$//' | paste -sd ' ' - || true)"
  CF_ASN=PASS
  while read -r ip; do
    is_ipv4 "$ip" || continue
    origin="$(ip_origin "$ip")"
    asn="${origin%%|*}"
    [ -n "$first_asn" ] || first_asn="$asn"
    if [ "$asn" = 13335 ]; then CF_ASN=FAIL; fi
  done <<<"$answers"
  if [ -n "$first_asn" ]; then
    ASN_INFO="AS${first_asn} $(asn_name "$first_asn")"
  else
    ASN_INFO="未知"
  fi

  ecs_ips="$(dig @8.8.8.8 +short +time=3 +tries=2 +subnet="$ECS_SUBNET" A "$d" 2>/dev/null)" || true
  printf '%s\n' "$ecs_ips" >"$LOG/${d}-dns-ecs.txt"
  while read -r ip; do
    is_ipv4 "$ip" || continue
    any_ip=1
    origin="$(ip_origin "$ip")"
    cc="${origin#*|}"
    if [ "$cc" = CN ]; then any_cn=1; fi
  done <<<"$ecs_ips"
  if [ "$any_cn" = 1 ]; then MAINLAND="是"; elif [ "$any_ip" = 1 ]; then MAINLAND="否"; else MAINLAND="未知"; fi
}

# Sets REALITY and CAMOUFLAGE to PASS/FAIL.
check_reality() {
  local d="$1" index="$2" port="$3"
  local prefix="$LOG/${d}-reality" config="$WORK/reality-${index}.yaml"
  local uuid public_key short_id shoes_pid xray_pid
  REALITY=FAIL
  CAMOUFLAGE=FAIL
  "$PING_RUST" generate reality --name "sni-reality-${index}" --port "$port" \
    --server-name "$d" --dest "${d}:443" --output "$config" \
    >"${prefix}-generate.txt" 2>&1 || return 0
  uuid="$(awk -F'：' '/^UUID：/ {print $2; exit}' "${prefix}-generate.txt")"
  public_key="$(awk -F'：' '/^Reality 公钥：/ {print $2; exit}' "${prefix}-generate.txt")"
  short_id="$(awk -F'：' '/^Short ID：/ {print $2; exit}' "${prefix}-generate.txt")"
  if [ -z "$uuid" ] || [ -z "$public_key" ] || [ -z "$short_id" ]; then return 0; fi

  "$SHOES" "$config" >"${prefix}-shoes.log" 2>&1 &
  shoes_pid=$!
  ACTIVE_PIDS="$shoes_pid"
  if ! wait_tcp "$port"; then stop_active; return 0; fi

  # Unauthenticated connection: shoes must pass it through to the real site,
  # so the default certificate verification has to succeed.
  if curl --noproxy '' --silent --show-error --output /dev/null --max-time 15 \
      --resolve "${d}:${port}:127.0.0.1" "https://${d}:${port}/" \
      >"${prefix}-camouflage.txt" 2>&1; then
    CAMOUFLAGE=PASS
  fi

  cat >"${prefix}-xray.json" <<JSON
{
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": 18081, "protocol": "socks", "settings": {"udp": false}}],
  "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": ${port}, "users": [{"id": "${uuid}", "encryption": "none", "flow": "xtls-rprx-vision"}]}]}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "${d}", "fingerprint": "chrome", "password": "${public_key}", "publicKey": "${public_key}", "shortId": "${short_id}"}}}]
}
JSON
  "$XRAY" run -c "${prefix}-xray.json" >"${prefix}-xray.log" 2>&1 &
  xray_pid=$!
  ACTIVE_PIDS="$shoes_pid $xray_pid"
  if wait_tcp 18081 && curl --noproxy '' --fail --silent --show-error --max-time 15 \
      --proxy socks5h://127.0.0.1:18081 http://127.0.0.1:18080/marker \
      >"${prefix}-response.txt" 2>&1 \
      && grep -Fxq 'reality sni check' "${prefix}-response.txt"; then
    REALITY=PASS
  fi
  stop_active
}

# Sets SHADOWTLS to PASS/FAIL. Uses ping-rust's own Clash Meta export so the
# client side is what users would get.
check_shadowtls() {
  local d="$1" index="$2" port="$3"
  local name="sni-shadowtls-${index}" prefix="$LOG/${d}-shadowtls"
  local config="$WORK/shadowtls-${index}.yaml" client="$WORK/mihomo-${index}.yaml"
  local profile_id shoes_pid mihomo_pid
  SHADOWTLS=FAIL
  sudo rm -rf /etc/shoes
  sudo mkdir -p /etc/shoes
  sudo "$PING_RUST" generate shadowsocks --shadowtls --name "$name" --port "$port" \
    --server-name "$d" --handshake "${d}:443" --output /etc/shoes/config.yaml \
    >"${prefix}-generate.txt" 2>&1 || return 0
  sudo systemctl stop shoes.service 2>/dev/null || true
  sudo systemctl reset-failed shoes.service 2>/dev/null || true
  profile_id="$(sudo python3 -c 'import json; print(json.load(open("/etc/shoes/ping-rust-state.json"))["profiles"][0]["id"])')" \
    || return 0
  sudo "$PING_RUST" export clash-meta --profile "$profile_id" --server 127.0.0.1 \
    --output "$client" >>"${prefix}-generate.txt" 2>&1 || return 0
  sudo cp /etc/shoes/config.yaml "$config"
  sudo chown "$(id -u):$(id -g)" "$config" "$client"
  cat >>"$client" <<YAML
mixed-port: 18090
mode: global
log-level: info
proxy-groups:
  - name: GLOBAL
    type: select
    proxies: [${name}]
YAML

  "$SHOES" "$config" >"${prefix}-shoes.log" 2>&1 &
  shoes_pid=$!
  ACTIVE_PIDS="$shoes_pid"
  if ! wait_tcp "$port"; then stop_active; return 0; fi
  "$MIHOMO" -f "$client" >"${prefix}-mihomo.log" 2>&1 &
  mihomo_pid=$!
  ACTIVE_PIDS="$shoes_pid $mihomo_pid"
  if wait_tcp 18090 && curl --noproxy '' --fail --silent --show-error --max-time 15 \
      --proxy http://127.0.0.1:18090 http://127.0.0.1:18080/marker \
      >"${prefix}-response.txt" 2>&1 \
      && grep -Fxq 'reality sni check' "${prefix}-response.txt"; then
    SHADOWTLS=PASS
  fi
  stop_active
}

domain_re='^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
mapfile -t domains < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$CANDIDATES" | grep -v '^$' || true)
if [ "${#domains[@]}" -eq 0 ]; then
  echo "error: ${CANDIDATES} 里没有域名" >&2
  exit 1
fi
if dups="$(printf '%s\n' "${domains[@]}" | sort | uniq -d)" && [ -n "$dups" ]; then
  echo "error: ${CANDIDATES} 有重复域名：${dups}" >&2
  exit 1
fi

echo "shoes v0.3.6, xray ${XRAY_TAG}: $($XRAY version 2>&1 | head -n 1), mihomo ${MIHOMO_TAG}"
rows=()
failed=0
index=0
for d in "${domains[@]}"; do
  index=$((index + 1))
  TLS13=FAIL H2=FAIL CERT=FAIL REDIRECT=FAIL CF_HEADER=FAIL CF_ASN=FAIL
  REALITY=FAIL CAMOUFLAGE=FAIL SHADOWTLS=FAIL HTTP_CODE=000
  ASN_INFO="-" CNAMES="" MAINLAND="-"
  reasons=()
  if [[ ! "$d" =~ $domain_re ]]; then
    reasons+=("域名格式无效")
  else
    check_dns "$d"
    check_tls "$d"
    check_http "$d"
    check_reality "$d" "$index" $((26000 + index))
    check_shadowtls "$d" "$index" $((26100 + index))
    [ "$TLS13" = PASS ] || reasons+=("不支持 TLS 1.3")
    [ "$H2" = PASS ] || reasons+=("未协商出 h2")
    [ "$CERT" = PASS ] || reasons+=("证书校验失败")
    [ "$REDIRECT" = PASS ] || reasons+=("跳转到其他主机或请求失败（HTTP ${HTTP_CODE}）")
    { [ "$CF_HEADER" = PASS ] && [ "$CF_ASN" = PASS ]; } || reasons+=("在 Cloudflare 上")
    [ "$REALITY" = PASS ] || reasons+=("Reality 端到端失败")
    [ "$CAMOUFLAGE" = PASS ] || reasons+=("伪装证书校验失败")
    [ "$SHADOWTLS" = PASS ] || reasons+=("ShadowTLS 端到端失败")
  fi
  if [ "${#reasons[@]}" -eq 0 ]; then
    verdict="通过"
  else
    verdict="不通过"
    failed=$((failed + 1))
  fi
  cf=PASS
  { [ "$CF_HEADER" = PASS ] && [ "$CF_ASN" = PASS ]; } || cf=FAIL
  reason_text=""
  for reason in "${reasons[@]}"; do reason_text="${reason_text:+${reason_text}；}${reason}"; done
  rows+=("| ${d} | ${ASN_INFO} | ${CNAMES:--} | $(mark "$TLS13") | $(mark "$H2") | $(mark "$CERT") | $(mark "$REDIRECT") | $(mark "$cf") | $(mark "$REALITY") | $(mark "$CAMOUFLAGE") | $(mark "$SHADOWTLS") | ${MAINLAND} | ${verdict} | ${reason_text:--} |")
  echo "${d}: ${verdict}${reason_text:+（${reason_text}）}"
done

{
  echo "## Reality SNI 候选实测"
  echo
  echo "shoes v0.3.6；Xray ${XRAY_TAG}（fingerprint chrome）；Mihomo ${MIHOMO_TAG}。共 ${#domains[@]} 个，不通过 ${failed} 个。"
  echo
  echo "| 域名 | ASN/组织 | CNAME | TLS1.3 | h2 | 证书 | 跳转 | Cloudflare | Reality 端到端 | 伪装 | ShadowTLS 端到端 | 大陆解析 | 结论 | 失败原因 |"
  echo "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
  printf '%s\n' "${rows[@]}"
  echo
  echo "大陆解析：用大陆网段做 ECS 向公共 DNS 查询，结果里有大陆地址记为“是”。只作标注，不影响结论。"
} | tee "$LOG/summary.md" >>"$SUMMARY"

sudo chmod -R a+rX "$WORK"
if [ "$failed" -gt 0 ]; then
  echo "error: ${failed} 个候选不通过" >&2
  exit 1
fi
echo 'reality sni check complete'
