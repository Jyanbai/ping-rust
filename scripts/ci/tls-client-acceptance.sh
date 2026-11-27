#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
exec python3 -B "$(dirname -- "$0")/tls_client_acceptance.py" "$@" </dev/null
