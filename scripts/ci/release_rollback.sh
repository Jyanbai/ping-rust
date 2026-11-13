#!/usr/bin/env bash
set -euo pipefail

# Called for an attempted publication without completed public acceptance,
# including cancelled runs and requests whose response was lost.
draft="$(gh release view "${GITHUB_REF_NAME}" --json isDraft --jq '.isDraft')"
case "$draft" in
  true) echo 'Release 已是 draft，无需回退。' ;;
  false)
    echo '::error::公开验收未完成，正在将 Release 撤回 draft'
    gh release edit "${GITHUB_REF_NAME}" --draft=true
    ;;
  *) echo '::error::无法确认远端 Release 状态，需要人工处理' >&2; exit 1 ;;
esac
