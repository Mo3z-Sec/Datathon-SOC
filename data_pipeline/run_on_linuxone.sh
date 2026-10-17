#!/usr/bin/env bash
# Nour's full data pipeline on IBM LinuxONE (Ubuntu 24.04, s390x).
# Works without passwordless sudo: uses installed system packages as-is.
set -uo pipefail

cd "$(dirname "$0")" 2>/dev/null || true

echo "==> host: $(hostname) | arch: $(uname -m)"
echo "==> python: $(python3 --version)"

if sudo -n true 2>/dev/null; then
  echo "==> passwordless sudo available -> installing any missing packages"
  sudo apt-get update || true
  sudo apt-get install -y python3-pandas python3-numpy python3-sklearn \
      python3-matplotlib python3-seaborn python3-requests python3-openpyxl || true
else
  echo "==> sudo requires a password -> skipping apt, using installed system packages"
fi

echo "==> checking required imports"
if ! python3 -c 'import pandas, numpy, sklearn, matplotlib, requests; print("  all required modules present")'; then
  echo "==> a required module is missing -> pip install (user site, no sudo)"
  python3 -m pip install --user -r requirements.txt
fi

run_step () {
  echo
  echo "==> $1"
  if python3 "$2"; then
    echo "    OK: $1"
  else
    echo "    FAILED (continuing): $1"
  fi
}

run_step "download datasets (~1 GB)" download_data.py
run_step "clean + split" pipeline.py
run_step "hospital asset table (simulated)" make_assets.py
run_step "privacy demo (hash/mask IPs)" privacy.py
run_step "accuracy proof (original vs hashed vs masked)" accuracy_test.py
run_step "threat intel (OpenPhish/URLhaus)" threat_intel.py

echo
echo "==> outputs:"
ls -lh outputs 2>/dev/null || echo "  no outputs dir yet"
echo
echo "==> Screenshot this for the judges: the pipeline runs on LinuxONE s390x."
