#!/usr/bin/env bash
# Shared helpers for the control scripts (sourced, not run directly).
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
RUN_DIR="$ROOT/run"; LOG_DIR="$ROOT/logs"; PID_FILE="$RUN_DIR/soc.pid"; LOG_FILE="$LOG_DIR/soc.log"
mkdir -p "$RUN_DIR" "$LOG_DIR"

# Which Python: $SOC_PYTHON, else the project virtualenv, else python3 on PATH.
if [ -n "${SOC_PYTHON:-}" ]; then PY="$SOC_PYTHON"
elif [ -x "$ROOT/.venv/bin/python" ]; then PY="$ROOT/.venv/bin/python"
else PY="$(command -v python3 || true)"; fi

# env_value KEY [DEFAULT]: value from the environment, else from .env, else DEFAULT.
env_value() {
  local key="$1" def="${2:-}" val="${!1:-}"
  if [ -z "$val" ] && [ -f "$ROOT/.env" ]; then
    val="$(grep -E "^${key}=" "$ROOT/.env" | tail -n1 | cut -d= -f2- | sed -e "s/^['\"]//" -e "s/['\"]\$//")"
  fi
  echo "${val:-$def}"
}

HOST="$(env_value SOC_HOST 127.0.0.1)"; PORT="$(env_value SOC_PORT 8000)"
CHECK_HOST="$HOST"; [ "$HOST" = "0.0.0.0" ] && CHECK_HOST="127.0.0.1"

is_running() { [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; }

health() {
  if command -v curl >/dev/null 2>&1; then curl -fsS -m 3 "http://${CHECK_HOST}:${PORT}/api/health" 2>/dev/null
  else "$PY" -c "import urllib.request,sys; sys.stdout.write(urllib.request.urlopen('http://${CHECK_HOST}:${PORT}/api/health', timeout=3).read().decode())" 2>/dev/null; fi
}
