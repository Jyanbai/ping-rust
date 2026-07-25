#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPOSITORY="Jyanbai/ping-rust"
readonly PROGRAM="ping-rust"
# 与 src/self_update.rs 的 MAX_CHECKSUM_SIZE / MAX_ARCHIVE_SIZE 保持一致。
readonly MAX_CHECKSUM_SIZE=65536
readonly MAX_ARCHIVE_SIZE=67108864
# 新版 Stage-0 依赖二进制 install-self；公开 latest 至少需达到该协议版本。
# CI 从本常量解析，勿在 workflow 中硬编码副本。
readonly MIN_INSTALL_SELF_VERSION=0.1.16
VERSION="latest"
INSTALL_DIR="${PING_RUST_INSTALL_DIR:-/usr/local/bin}"
QUIET=0
BOOTSTRAP=1
TEMP_DIR=""
USE_SUDO=0

usage() {
  cat <<'EOF'
安装 ping-rust 的 GitHub Release 预编译静态二进制。

用法：
  install.sh [选项]

选项：
  --version <版本>       安装指定版本，例如 v0.1.16；默认 latest
  --install-dir <目录>   安装目录；默认 /usr/local/bin
  --quiet                只显示错误和最终结果
  --no-bootstrap         只安装管理工具，不自动部署默认 Reality
  -h, --help             显示帮助

环境变量：
  PING_RUST_INSTALL_DIR  默认安装目录
EOF
}

log() {
  [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"
}

die() {
  printf '错误：%s\n' "$*" >&2
  exit 1
}

cleanup() {
  [ -z "$TEMP_DIR" ] || [ ! -d "$TEMP_DIR" ] || rm -rf -- "$TEMP_DIR"
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "缺少必需命令：$1"
}

# 按完整 path component 拒绝 ".."，不误伤 "..name"，也不 canonicalize。
validate_install_dir() {
  local path="$1"
  local rest component
  case "$path" in
    /*) ;;
    *) die "安装目录必须是绝对路径：$path" ;;
  esac
  [ "$path" != / ] || die "安装目录不能是根目录 /"
  rest="${path#/}"
  while [ -n "$rest" ]; do
    component="${rest%%/*}"
    [ "$component" != .. ] || die "安装目录不能包含父目录组件 ..：$path"
    if [ "$rest" = "$component" ]; then
      break
    fi
    rest="${rest#*/}"
  done
}

# 有界下载：
# - 保留 --max-filesize：Content-Length 已知或 curl >= 8.4 时可早拒绝（exit 63）。
# - curl < 8.4 且缺少 Content-Length 时 --max-filesize 对进行中下载无效；
#   因此 curl 写 stdout，经 GNU head -c $((max_size+1)) 再落盘，硬限制目标最多
#   max_size+1 字节，避免 /tmp 被未知长度响应写满。
# - 落盘后 stat 复核；exit 63 或 actual > max_size 均报“超过大小上限”。
download_bounded() {
  local url="$1"
  local dest="$2"
  local max_size="$3"
  local label="$4"
  local actual curl_status head_status
  local -a pipe_status

  # 临时关闭 errexit 以捕获 PIPESTATUS；pipefail 保持开启。
  set +e
  curl "${CURL_OPTIONS[@]}" --max-filesize "$max_size" \
    "$url" | head -c "$((max_size + 1))" >"$dest"
  pipe_status=("${PIPESTATUS[@]}")
  set -e
  curl_status="${pipe_status[0]:-1}"
  head_status="${pipe_status[1]:-1}"

  actual="$(stat -c%s -- "$dest" 2>/dev/null)" \
    || die "无法读取已下载${label}的大小：${dest}"

  # curl 63：--max-filesize 早拒绝；actual > max_size：head 截断后的硬限制复核。
  # 超限时 curl 可能因 SIGPIPE 得到 141，仍以大小为准，不得误报成网络错误。
  if [ "$curl_status" -eq 63 ] || [ "$actual" -gt "$max_size" ]; then
    die "${label}超过大小上限（${max_size} 字节）：实际 ${actual} 字节"
  fi
  if [ "$curl_status" -ne 0 ] || [ "$head_status" -ne 0 ]; then
    die "下载${label}失败：${url}"
  fi
}

privileged() {
  if [ "$USE_SUDO" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

prepare_install_dir() {
  if mkdir -p -- "$INSTALL_DIR" 2>/dev/null \
    && [ -w "$INSTALL_DIR" ] && [ -x "$INSTALL_DIR" ]; then
    return
  fi
  need sudo
  sudo mkdir -p -- "$INSTALL_DIR" || die "无法创建安装目录 $INSTALL_DIR。"
  USE_SUDO=1
}

normalize_version() {
  [ "$VERSION" = latest ] && return
  VERSION="${VERSION#v}"
  case "$VERSION" in *[!0-9A-Za-z.+-]*) die "版本格式无效：$VERSION" ;; esac
  printf '%s' "$VERSION" | grep -Eq \
    '^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.-]+)?$' \
    || die "版本格式无效：$VERSION（示例：v0.1.16）"
  VERSION="v$VERSION"
}

validate_version() {
  local actual="$1" expected=""
  case "$actual" in *$'\n'* | *$'\r'*) die "二进制版本输出必须只有一行。" ;; esac
  if [ "$VERSION" = latest ]; then
    printf '%s\n' "$actual" | grep -Eq \
      '^ping-rust [0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.-]+)?$' \
      || die "二进制版本输出无效：$actual"
  else
    expected="ping-rust ${VERSION#v}"
    [ "$actual" = "$expected" ] \
      || die "二进制版本不匹配：期望 $expected，实际 $actual"
  fi
}

detect_target() {
  [ "$(uname -s)" = Linux ] || die "仅支持 Linux。"
  case "$(uname -m)" in
    x86_64 | amd64) printf '%s' x86_64-unknown-linux-musl ;;
    aarch64 | arm64) printf '%s' aarch64-unknown-linux-musl ;;
    *) die "不支持的 CPU 架构：$(uname -m)（仅支持 x86_64 和 aarch64）" ;;
  esac
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) [ "$#" -ge 2 ] || die "--version 需要一个值"; VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --install-dir) [ "$#" -ge 2 ] || die "--install-dir 需要一个值"; INSTALL_DIR="$2"; shift 2 ;;
    --install-dir=*) INSTALL_DIR="${1#*=}"; shift ;;
    --quiet) QUIET=1; shift ;;
    --no-bootstrap) BOOTSTRAP=0; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "未知参数：$1（使用 --help 查看帮助）" ;;
  esac
done

validate_install_dir "$INSTALL_DIR"
# head：GNU coreutils（Ubuntu/Debian/Rocky/Alma 均提供 head -c）。
for command in chmod curl grep head mkdir mktemp rm sha256sum stat tar uname; do
  need "$command"
done
normalize_version

TARGET="$(detect_target)"
ASSET="${PROGRAM}-${TARGET}.tar.gz"
if [ "$VERSION" = latest ]; then
  DOWNLOAD_BASE="https://github.com/${REPOSITORY}/releases/latest/download"
else
  DOWNLOAD_BASE="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
fi
TEMP_DIR="$(mktemp -d)"
trap cleanup EXIT INT TERM
CURL_OPTIONS=(
  --proto '=https' --tlsv1.2 --fail --location --silent --show-error
  --retry 3 --retry-delay 1
)

log "正在下载 ${PROGRAM} ${VERSION} (${TARGET})..."
download_bounded \
  "${DOWNLOAD_BASE}/${ASSET}" \
  "${TEMP_DIR}/${ASSET}" \
  "$MAX_ARCHIVE_SIZE" \
  "发布归档"
download_bounded \
  "${DOWNLOAD_BASE}/SHA256SUMS" \
  "${TEMP_DIR}/SHA256SUMS" \
  "$MAX_CHECKSUM_SIZE" \
  "SHA256SUMS"
(
  cd "$TEMP_DIR"
  checksum_line="$(grep -E "^[0-9a-fA-F]{64}  ${ASSET}$" SHA256SUMS || true)"
  [ "$(printf '%s\n' "$checksum_line" | grep -c .)" -eq 1 ] \
    || die "SHA256SUMS 中 ${ASSET} 的条目缺失或重复。"
  printf '%s\n' "$checksum_line" | sha256sum --check --status - \
    || die "SHA-256 校验失败；文件不会被执行。"
)
log "SHA-256 校验通过。"

mkdir -p "${TEMP_DIR}/unpacked"
[ "$(tar -tzf "${TEMP_DIR}/${ASSET}")" = "$PROGRAM" ] \
  || die "发布归档只能包含根目录普通文件 ${PROGRAM}。"
tar -xzf "${TEMP_DIR}/${ASSET}" -C "${TEMP_DIR}/unpacked"
DOWNLOADED="${TEMP_DIR}/unpacked/${PROGRAM}"
[ -f "$DOWNLOADED" ] && [ ! -L "$DOWNLOADED" ] \
  || die "发布归档中缺少普通文件 ${PROGRAM}。"
chmod 0755 "$DOWNLOADED"
DOWNLOADED_VERSION="$("$DOWNLOADED" --version)" \
  || die "下载的二进制无法在当前系统运行。"
validate_version "$DOWNLOADED_VERSION"

prepare_install_dir
install_args=(install-self --install-dir "$INSTALL_DIR")
[ "$QUIET" -eq 0 ] || install_args+=(--quiet)
[ "$BOOTSTRAP" -eq 1 ] || install_args+=(--no-bootstrap)
"$DOWNLOADED" install-self --help >/dev/null 2>&1 \
  || die "下载的二进制不支持 install-self（需要 >= ${MIN_INSTALL_SELF_VERSION}）；请使用对应 tag 内的 install.sh（v0.1.15 及更早版本见该 tag 的旧脚本）。"
privileged "$DOWNLOADED" "${install_args[@]}" \
  || die "Rust 安装阶段失败；已校验文件未能完成安装。"
