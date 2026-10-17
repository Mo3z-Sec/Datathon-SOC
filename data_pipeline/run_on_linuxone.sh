#!/usr/bin/env bash
# Run Nour's full data pipeline on IBM LinuxONE (Ubuntu 24.04, s390x).
# Usage:  bash run_on_linuxone.sh
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Installing system packages (on s390x, apt is safer than pip)"
sudo apt-get update
# apt first; if any package name is missing, fall back to pip below.
sudo apt-get install -y \
  python3 python3-pip python3-venv \
  python3-pandas python3-numpy python3-sklearn \
  python3-matplotlib python3-seaborn \
  python3-requests python3-openpyxl python3-dotenv \
  || echo "WARN: some apt packages unavailable, will try pip for the rest"

echo "==> Verifying imports"
if ! python3 - <<'PY'
import pandas, numpy, sklearn, matplotlib, seaborn, requests
print("pandas", pandas.__version__, "| numpy", numpy.__version__, "| sklearn", sklearn.__version__)
PY
then
  echo "==> Falling back to pip"
  python3 -m pip install --user -r requirements.txt
fi

echo "==> Downloading datasets (public data; ~1 GB)"
python3 download_data.py

echo "==> Cleaning + splitting"
python3 pipeline.py

echo "==> Hospital asset table (simulated)"
python3 make_assets.py

echo "==> Privacy demo (HMAC hashing / masking)"
python3 privacy.py

echo "==> Accuracy proof (original vs hashed vs masked)"
python3 accuracy_test.py

echo "==> Threat intel (OpenPhish/URLhaus)"
python3 threat_intel.py

echo ""
echo "==> Done. Outputs:"
ls -lh outputs
echo ""
echo "Screenshot this run for the judges (it proves the pipeline runs on LinuxONE s390x)."
