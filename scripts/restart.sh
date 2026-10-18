#!/usr/bin/env bash
# Stop (if running) then start again, e.g. after editing .env.
D="$(cd "$(dirname "$0")" && pwd)"
"$D/stop.sh"; exec "$D/start.sh"
