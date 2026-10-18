#!/usr/bin/env bash
# Stop the background app gracefully (forces it after 10 seconds).
source "$(dirname "$0")/common.sh"
if ! is_running; then echo "Not running."; rm -f "$PID_FILE"; exit 0; fi
PID="$(cat "$PID_FILE")"; echo "Stopping PID $PID ..."; kill "$PID"
for _ in $(seq 1 20); do
  kill -0 "$PID" 2>/dev/null || { rm -f "$PID_FILE"; echo "Stopped."; exit 0; }
  sleep 0.5
done
echo "Did not stop in time; forcing."; kill -9 "$PID" 2>/dev/null; rm -f "$PID_FILE"; echo "Stopped."
