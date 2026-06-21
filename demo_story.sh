#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
PYTHON_BIN="${PYTHON:-python3}"

"$PYTHON_BIN" -m pip install -e '.[dashboard]'
"$PYTHON_BIN" -m redteamci.cli dashboard
