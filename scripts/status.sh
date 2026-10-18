#!/usr/bin/env bash
# Show whether the app is running and answering.
source "$(dirname "$0")/common.sh"
if is_running; then echo "Process : running (PID $(cat "$PID_FILE"))"; else echo "Process : not running"; fi
if OUT="$(health)"; then echo "Health  : $OUT"; echo "Address : http://${HOST}:${PORT}"; else echo "Health  : no answer on http://${CHECK_HOST}:${PORT}"; exit 1; fi
