#!/usr/bin/env bash
# Prints the facts that decide which install route to use. Safe: read-only, changes nothing.
source "$(dirname "$0")/common.sh"
line() { printf '%s\n' "------------------------------------------------------------"; }
echo "Hospital SOC - environment check"; line
echo "Host name      : $(hostname 2>/dev/null)"
echo "Kernel / arch  : $(uname -sr) / $(uname -m)"
ARCH="$(uname -m)"
case "$ARCH" in
  s390x)  echo "                 -> IBM Z / LinuxONE (s390x, big-endian). Pure-Python app: supported.";;
  x86_64|aarch64) echo "                 -> Not s390x. The app still runs; the instructions are identical.";;
  *) echo "                 -> Unusual architecture; pure-Python code should still work.";;
esac
if [ -r /etc/os-release ]; then . /etc/os-release; echo "Operating sys. : ${PRETTY_NAME:-unknown}"; echo "Package family : ${ID_LIKE:-$ID}"; fi
echo "CPU cores      : $(nproc 2>/dev/null || echo '?')"
if [ -r /proc/meminfo ]; then
  MEM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo); AV_MB=$(awk '/MemAvailable/ {printf "%d", $2/1024}' /proc/meminfo)
  echo "Memory         : ${MEM_MB} MB total, ${AV_MB} MB available $( [ "$MEM_MB" -lt 1024 ] && echo '(WARNING: under 1 GB)')"
fi
echo "Disk (project) : $(df -h "$ROOT" | awk 'NR==2 {print $4 " free on " $6}')"
line
echo "Python         : ${PY:-NOT FOUND} $([ -n "$PY" ] && "$PY" --version 2>&1)"
if [ -n "$PY" ]; then
  "$PY" - <<'PYEOF'
import sys, sqlite3
ok = sys.version_info >= (3, 9)
print("Python >= 3.9  :", "yes" if ok else "NO - upgrade Python (needs 3.9+)")
print("SQLite library :", sqlite3.sqlite_version, "(needs 3.24+):", "yes" if tuple(map(int, sqlite3.sqlite_version.split("."))) >= (3, 24) else "NO")
for mod in ("venv", "ensurepip"):
    try: __import__(mod); print(f"module {mod:<9}: present")
    except ImportError: print(f"module {mod:<9}: MISSING -> sudo apt install python3-venv  (Ubuntu) / sudo dnf install python3 (RHEL)")
for mod in ("fastapi", "uvicorn", "pydantic"):
    try: m = __import__(mod); print(f"package {mod:<9}: {getattr(m, '__version__', 'installed')}")
    except ImportError: print(f"package {mod:<9}: not installed yet (scripts/setup.sh installs it)")
PYEOF
fi
line
for tool in docker podman "docker compose" curl git; do
  if command -v ${tool%% *} >/dev/null 2>&1; then echo "$tool: $(${tool} --version 2>&1 | head -n1)"; else echo "$tool: not installed"; fi
done
line
if command -v ss >/dev/null 2>&1; then
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":${PORT}\$"; then echo "Port ${PORT}: IN USE (change SOC_PORT in .env or stop the other program)"; else echo "Port ${PORT}: free"; fi
fi
if [ -f "$ROOT/.env" ]; then echo ".env           : present"; else echo ".env           : missing (scripts/setup.sh creates it)"; fi
if is_running; then echo "App            : running (PID $(cat "$PID_FILE"))"; else echo "App            : not running"; fi
