#!/usr/bin/env bash
# Run the automated test-suite (uses pytest if installed, otherwise the built-in unittest runner).
source "$(dirname "$0")/common.sh"
[ -n "$PY" ] || { echo "python3 not found."; exit 1; }
if "$PY" -c "import pytest" 2>/dev/null; then exec "$PY" -m pytest -v
else
  echo "(pytest not installed - using unittest. For the HTTP API tests also run: $PY -m pip install -r requirements-dev.txt)"
  exec "$PY" -m unittest discover -s tests -v
fi
