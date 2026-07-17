#!/usr/bin/env bash
set -eu

if ! command -v cargo >/dev/null 2>&1; then
  echo "错误：未找到 cargo。请先从 https://rustup.rs 安装稳定版 Rust。" >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  exec cargo install ping-rust --locked
fi

exec cargo install ping-rust "$@"
