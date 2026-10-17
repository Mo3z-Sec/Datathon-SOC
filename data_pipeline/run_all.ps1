Set-Location $PSScriptRoot
Write-Host "Installing packages..."
pip install -r requirements.txt
Write-Host "Downloading data..."
python download_data.py
Write-Host "Pipeline (UNSW + CICIDS + hospital layer)..."
python pipeline.py
Write-Host "Hospital asset table..."
python make_assets.py
Write-Host "Privacy demo + accuracy test..."
python privacy.py
python accuracy_test.py
python threat_intel.py
Write-Host "Done. See outputs/ and README_nour.md"
dir outputs | Format-Table Name, Length, LastWriteTime
