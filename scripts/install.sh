#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPOSITORY="Jyanbai/ping-rust"
readonly PROGRAM="ping-rust"
readonly SHORT_COMMAND="sb"

VERSION="latest"
INSTALL_DIR="${PING_RUST_INSTALL_DIR:-/usr/local/bin}"
QUIET=0
TEMP_DIR=""
STAGED_PATH=""
USE_SUDO=0

usage() {
  cat <<'EOF'
安装 ping-rust 的 GitHub Release 预编译静态二进制。

用法：
  install.sh [选项]

选项：
  --version <版本>       安装指定版本，例如 v0.1.2；默认 latest
  --install-dir <目录>   安装目录；默认 /usr/local/bin
  --quiet                只显示错误和最终结果
  -h, --help             显示帮助

环境变量：
  PING_RUST_INSTALL_DIR  默认安装目录
EOF
}

log() {
  if [ "${QUIET}" -eq 0 ]; then
    printf '%s\n' "$*"
  fi
}

die() {
  printf '错误：%s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [ -n "${STAGED_PATH}" ]; then
    privileged rm -f -- "${STAGED_PATH}" >/dev/null 2>&1 || true
  fi
  if [ -n "${TEMP_DIR}" ] && [ -d "${TEMP_DIR}" ]; then
    rm -rf -- "${TEMP_DIR}"
  fi
}

privileged() {
  if [ "${USE_SUDO}" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

prepare_install_dir() {
  if mkdir -p -- "${INSTALL_DIR}" 2>/dev/null \
    && [ -w "${INSTALL_DIR}" ] \
    && [ -x "${INSTALL_DIR}" ]; then
    USE_SUDO=0
    return
  fi

  command -v sudo >/dev/null 2>&1 \
    || die "安装到 ${INSTALL_DIR} 需要 root 权限，但系统没有 sudo；请以 root 运行。"
  sudo mkdir -p -- "${INSTALL_DIR}" \
    || die "无法创建安装目录 ${INSTALL_DIR}。"
  USE_SUDO=1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "缺少必需命令：$1"
}

normalize_version() {
  if [ "${VERSION}" = "latest" ]; then
    return
  fi

  VERSION="${VERSION#v}"
  case "${VERSION}" in
    *[!0-9A-Za-z.+-]*) die "版本格式无效：${VERSION}" ;;
  esac
  printf '%s' "${VERSION}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.-]+)?$' \
    || die "版本格式无效：${VERSION}（示例：v0.1.0）"
  VERSION="v${VERSION}"
}

detect_target() {
  [ "$(uname -s)" = "Linux" ] || die "仅支持 Linux。"
  case "$(uname -m)" in
    x86_64 | amd64) printf '%s' "x86_64-unknown-linux-musl" ;;
    aarch64 | arm64) printf '%s' "aarch64-unknown-linux-musl" ;;
    *) die "不支持的 CPU 架构：$(uname -m)（仅支持 x86_64 和 aarch64）" ;;
  esac
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || die "--version 需要一个值"
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#*=}"
      shift
      ;;
    --install-dir)
      [ "$#" -ge 2 ] || die "--install-dir 需要一个值"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --install-dir=*)
      INSTALL_DIR="${1#*=}"
      shift
      ;;
    --quiet)
      QUIET=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "未知参数：$1（使用 --help 查看帮助）" ;;
  esac
done

case "${INSTALL_DIR}" in
  /*) ;;
  *) die "安装目录必须是绝对路径：${INSTALL_DIR}" ;;
esac
[ "${INSTALL_DIR}" != "/" ] || die "安装目录不能是根目录 /"

require_command curl
require_command grep
require_command install
require_command mktemp
require_command ln
require_command readlink
require_command sha256sum
require_command tar
require_command uname
normalize_version

TARGET="$(detect_target)"
ASSET="${PROGRAM}-${TARGET}.tar.gz"
if [ "${VERSION}" = "latest" ]; then
  DOWNLOAD_BASE="https://github.com/${REPOSITORY}/releases/latest/download"
else
  DOWNLOAD_BASE="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
fi

TEMP_DIR="$(mktemp -d)"
trap cleanup EXIT INT TERM

log "正在下载 ${PROGRAM} ${VERSION} (${TARGET})..."
CURL_OPTIONS=(
  --proto '=https'
  --tlsv1.2
  --fail
  --location
  --silent
  --show-error
  --retry 3
  --retry-delay 1
)
curl "${CURL_OPTIONS[@]}" "${DOWNLOAD_BASE}/${ASSET}" -o "${TEMP_DIR}/${ASSET}" \
  || die "下载二进制失败；请确认版本存在且 GitHub 可访问：${DOWNLOAD_BASE}/${ASSET}"
curl "${CURL_OPTIONS[@]}" "${DOWNLOAD_BASE}/SHA256SUMS" -o "${TEMP_DIR}/SHA256SUMS" \
  || die "下载 SHA256SUMS 失败。"

(
  cd "${TEMP_DIR}"
  checksum_line="$(grep -E "^[0-9a-fA-F]{64}  ${ASSET}$" SHA256SUMS || true)"
  [ -n "${checksum_line}" ] || die "SHA256SUMS 中没有 ${ASSET}。"
  printf '%s\n' "${checksum_line}" | sha256sum --check --status - \
    || die "SHA-256 校验失败；文件不会被安装。"
)
log "SHA-256 校验通过。"

mkdir -p "${TEMP_DIR}/unpacked"
[ "$(tar -tzf "${TEMP_DIR}/${ASSET}")" = "${PROGRAM}" ] \
  || die "发布归档内容不符合预期。"
tar -xzf "${TEMP_DIR}/${ASSET}" -C "${TEMP_DIR}/unpacked"
[ -f "${TEMP_DIR}/unpacked/${PROGRAM}" ] || die "发布归档中缺少 ${PROGRAM}。"
chmod 0755 "${TEMP_DIR}/unpacked/${PROGRAM}"
"${TEMP_DIR}/unpacked/${PROGRAM}" --version >/dev/null \
  || die "下载的二进制无法在当前系统运行。"

prepare_install_dir
STAGED_PATH="$(privileged mktemp "${INSTALL_DIR}/.${PROGRAM}.install.XXXXXX")"
privileged install -m 0755 "${TEMP_DIR}/unpacked/${PROGRAM}" "${STAGED_PATH}"
privileged mv -f -- "${STAGED_PATH}" "${INSTALL_DIR}/${PROGRAM}"
STAGED_PATH=""

install_short_command() {
  local alias_path="${INSTALL_DIR}/${SHORT_COMMAND}"
  local existing_target=""
  if [ -L "${alias_path}" ]; then
    existing_target="$(readlink -- "${alias_path}")"
    case "${existing_target}" in
      "${PROGRAM}" | "${INSTALL_DIR}/${PROGRAM}") return 0 ;;
      *)
        printf '警告：保留已有符号链接 %s -> %s；请使用 %s。\n' \
          "${alias_path}" "${existing_target}" "${PROGRAM}" >&2
        return 1
        ;;
    esac
  fi
  if [ -e "${alias_path}" ]; then
    printf '警告：保留已有命令 %s；请使用 %s。\n' \
      "${alias_path}" "${PROGRAM}" >&2
    return 1
  fi
  privileged ln -s -- "${PROGRAM}" "${alias_path}"
}

if install_short_command; then
  RUN_COMMAND="${SHORT_COMMAND}"
else
  RUN_COMMAND="${PROGRAM}"
fi

INSTALLED_VERSION="$("${INSTALL_DIR}/${PROGRAM}" --version)" \
  || die "安装后的版本验证失败。"
printf '安装成功：%s\n' "${INSTALLED_VERSION}"
printf '运行：sudo %s\n' "${RUN_COMMAND}"
