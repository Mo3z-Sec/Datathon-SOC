#!/usr/bin/env bash
# Start the app in the background (PID in run/soc.pid, log in logs/soc.log).
source "$(dirname "$0")/common.sh"
[ -n "$PY" ] || { echo "python3 not found."; exit 1; }
[ -f "$ROOT/.env" ] || { echo "No .env found. Run scripts/setup.sh first."; exit 1; }
if is_running; then echo "Already running (PID $(cat "$PID_FILE")) on http://${HOST}:${PORT}"; exit 0; fi
rm -f "$PID_FILE"
"$PY" -m soc.cli check-config >/dev/null || { echo "Configuration problem (see message above). Fix .env and retry."; exit 1; }
echo "Starting Hospital SOC on http://${HOST}:${PORT} ..."
nohup "$PY" -m uvicorn soc.asgi:app --host "$HOST" --port "$PORT" >> "$LOG_FILE" 2>&1 < /dev/null &
echo $! > "$PID_FILE"
for _ in $(seq 1 40); do
  if health >/dev/null; then echo "Started (PID $(cat "$PID_FILE")). Log file: $LOG_FILE"; exit 0; fi
  is_running || break
  sleep 0.5
done
echo "FAILED to start. Last log lines:"; tail -n 25 "$LOG_FILE"; rm -f "$PID_FILE"; exit 1
