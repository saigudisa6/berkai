#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
PYTHON_BIN="${PYTHON:-python3}"

cp guardrails.unsafe.yml guardrails.yml
"$PYTHON_BIN" -m redteamci.cli run --offline || true
"$PYTHON_BIN" -m redteamci.cli fix pi-003 --use-fixture
"$PYTHON_BIN" -m redteamci.cli rerun --offline

if "$PYTHON_BIN" -m streamlit --version >/dev/null 2>&1; then
  "$PYTHON_BIN" -m streamlit run redteamci/dashboard.py
else
  echo "Streamlit is not installed. Install with: pip install -e '.[dashboard]'"
fi
