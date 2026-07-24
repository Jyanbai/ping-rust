#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPOSITORY="Jyanbai/ping-rust"
readonly PROGRAM="ping-rust"
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

case "$INSTALL_DIR" in /*) ;; *) die "安装目录必须是绝对路径：$INSTALL_DIR" ;; esac
[ "$INSTALL_DIR" != / ] || die "安装目录不能是根目录 /"
for command in chmod curl grep mkdir mktemp rm sha256sum tar uname; do need "$command"; done
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
curl "${CURL_OPTIONS[@]}" "${DOWNLOAD_BASE}/${ASSET}" -o "${TEMP_DIR}/${ASSET}" \
  || die "下载二进制失败：${DOWNLOAD_BASE}/${ASSET}"
curl "${CURL_OPTIONS[@]}" "${DOWNLOAD_BASE}/SHA256SUMS" -o "${TEMP_DIR}/SHA256SUMS" \
  || die "下载 SHA256SUMS 失败。"
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
  || die "该版本不支持新版安装协议；请使用对应 tag 内的 install.sh。"
privileged "$DOWNLOADED" "${install_args[@]}" \
  || die "Rust 安装阶段失败；已校验文件未能完成安装。"
