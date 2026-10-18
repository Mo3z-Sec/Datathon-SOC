#!/usr/bin/env bash
# One-time (and safe to re-run) setup: virtualenv, dependencies, .env with random tokens.
#   scripts/setup.sh                          normal install with pip
#   scripts/setup.sh --system-site-packages   reuse OS packages (e.g. python3-fastapi installed with apt)
#   scripts/setup.sh --seed                   also load simulated demo data
source "$(dirname "$0")/common.sh"
SITE=""; SEED=0
for a in "$@"; do case "$a" in --system-site-packages) SITE="--system-site-packages";; --seed) SEED=1;; *) echo "Unknown option $a"; exit 2;; esac; done
BOOT="$(command -v python3 || true)"
[ -n "$BOOT" ] || { echo "python3 not found. Install it first (Ubuntu: sudo apt install -y python3 python3-venv)."; exit 1; }
"$BOOT" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || { echo "Python 3.9 or newer is required."; exit 1; }

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "[1/4] Creating virtual environment (.venv) ..."
  "$BOOT" -m venv $SITE "$ROOT/.venv" || { echo "venv failed. On Ubuntu run: sudo apt install -y python3-venv   then re-run this script."; exit 1; }
else echo "[1/4] Virtual environment already exists."; fi
PY="$ROOT/.venv/bin/python"

echo "[2/4] Installing dependencies (a few minutes on s390x if packages must be built) ..."
"$PY" -m pip install --upgrade pip >/dev/null 2>&1 || true
"$PY" -m pip install --prefer-binary -r "$ROOT/requirements.txt" || {
  echo; echo "pip could not install the dependencies. Options:"
  echo "  * Ubuntu/Debian:  sudo apt install -y python3-fastapi python3-uvicorn python3-pydantic"
  echo "                    rm -rf .venv && scripts/setup.sh --system-site-packages"
  echo "  * See README.md > Troubleshooting."; exit 1; }

echo "[3/4] Creating .env with random access tokens ..."
"$PY" -m soc.cli init-env
mkdir -p "$ROOT/data" "$ROOT/run" "$ROOT/logs"; chmod 700 "$ROOT/data" 2>/dev/null || true

echo "[4/4] Checking the installation ..."
"$PY" -c "import fastapi, uvicorn, pydantic, sqlite3; print('dependencies OK: fastapi', fastapi.__version__)"
"$PY" -m soc.cli check-config >/dev/null && echo "configuration OK"
[ "$SEED" = 1 ] && "$PY" -m soc.cli seed | head -n 3
echo
echo "Setup finished. Next:  scripts/start.sh"
echo "Your tokens are in .env  (view with: grep TOKEN .env). Keep that file private."
