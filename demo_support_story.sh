#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
PYTHON_BIN="${PYTHON:-python3}"

"$PYTHON_BIN" -m redteamci.cli story support --step full
"$PYTHON_BIN" -m redteamci.cli story support --step trace --phase red --attack generated-refund-001
"$PYTHON_BIN" -m redteamci.cli story support --step trace --phase green --attack generated-refund-001

if "$PYTHON_BIN" -m streamlit --version >/dev/null 2>&1; then
  "$PYTHON_BIN" -m streamlit run redteamci/dashboard.py
else
  echo "Streamlit is not installed. Install with: pip install -e '.[dashboard]'"
fi
