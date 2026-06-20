#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
PYTHON_BIN="${PYTHON:-python3}"

"$PYTHON_BIN" -m redteamci.cli reset
"$PYTHON_BIN" -m redteamci.cli run --expect-fail --summary before.json
"$PYTHON_BIN" -m redteamci.cli fix pi-003 --use-fixture --apply
"$PYTHON_BIN" -m redteamci.cli rerun --expect-pass --summary after.json
"$PYTHON_BIN" -m redteamci.cli report --before before.json --after after.json

if "$PYTHON_BIN" -m streamlit --version >/dev/null 2>&1; then
  "$PYTHON_BIN" -m streamlit run redteamci/dashboard.py
else
  echo "Streamlit is not installed. Install with: pip install -e '.[dashboard]'"
fi
