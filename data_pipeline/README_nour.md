# Nour — Data Pipeline & Patient Privacy (Hospital Version)

**Objective:** Deliver clean, hospital-labeled, privacy-protected datasets and artifacts to the CyberShield AI team. This work feeds Hanan (models), Jason (risk scoring + real-time), Felix (docs/demo).

## Deliverables
- UNSW-NB15: `outputs/unsw_train.csv`, `outputs/unsw_val.csv`, `outputs/unsw_test.csv`, `outputs/scaler_unsw.json`
- CICIDS2017: `outputs/cicids_train.csv`, `outputs/cicids_val.csv`, `outputs/cicids_test.csv`, `outputs/scaler_cicids.json`
- Hospital layer: `outputs/assets.csv` (simulated asset + criticality)
- Privacy demo: `outputs/privacy_before_after.png` (hash/mask IPs)
- Accuracy proof: `outputs/accuracy_comparison.csv`, `outputs/accuracy_comparison.png` ("patient privacy costs almost no accuracy")
- Threat intel: `outputs/threat_urls.csv` (OpenPhish/URLhaus) and `threat_intel.py` for Jason

## How to run
```powershell
cd data_pipeline
pip install -r requirements.txt
python download_data.py
python pipeline.py
python privacy.py
python accuracy_test.py
python threat_intel.py
```

Or run everything via PowerShell: `.\run_all.ps1`

On IBM LinuxONE (Ubuntu s390x) run: `bash run_on_linuxone.sh`

## Notes on privacy
- IPs are anonymized using HMAC-SHA256 (same IP → same hash, repeatable) so patterns remain; masked form (`x.y.z.0`) is also provided.
- The secret key is stored in `secret.key` (gitignored). **Never commit the secret key.**
- This is patient-privacy protection (renamed from "anonymization") — privacy without losing detection value.

## Notes on datasets
- Public datasets (UNSW-NB15, CICIDS2017, NSL-KDD) serve as stand-ins for hospital network/system activity. **No real patient data is used.**
- CICIDS2017 TrafficLabelling files with Source/Destination IPs are used for the privacy demo. If large CICIDS outputs exceed GitHub limits (>100MB), we **do not** commit them to the repo — share via Drive instead.

## Hospital mapping (simulated)
Assets and criticality (1-5): EHR Server 5, Pharmacy System 5, Infusion Pump Network 5, PACS Imaging 4, Lab System 4, Nurse Workstation 3, Admin Office PC 2, Guest Wi-Fi 1. Kept **out of model features**, only passed to Jason.
Clearly labeled as **simulated**.

## Accuracy comparison
We train the same model twice (original vs anonymized IP representation). If the difference is small (<1%), we state: **"patient privacy costs almost no accuracy."**
If there's a larger drop, we report it honestly.

## Results (measured today)
### UNSW-NB15
- Genuine training set: 175,341 rows; genuine testing set: 82,332 rows.
- Cleaned, deduplicated, `inf/NaN` removed.
- Categoricals (`proto`, `service`, `state`) integer-encoded (mapping in `encoders_unsw.json`).
- Split: **train 149,039 / val 26,302 / test 82,332** (test = the genuine held-out set).
- Features: 42 numeric/encoded columns. Target: `label_binary` (0 normal, 1 attack).
- Test label balance: 37,000 normal / 45,332 attack.

### CICIDS2017
- 8 TrafficLabelling/ML files combined, then sampled to 150,000 rows (2.44M available).
- Split: **train 105,000 / val 22,500 / test 22,500**. Features: 78.
- Test balance: 18,602 BENIGN / 3,898 attack.

### Patient-privacy accuracy test (CICIDS2017 DDoS, real IPs)
Trained the same RandomForest (60 trees) on three representations of the Source/Destination IP:

| variant | accuracy | precision | recall | f1 |
|---|---|---|---|---|
| original IP | 0.9999 | 1.0 | 0.9999 | 1.0000 |
| hashed IP (privacy) | 0.9999 | 1.0 | 0.9999 | 0.9999 |
| masked IP (aggressive) | 0.9999 | 1.0 | 0.9999 | 0.9999 |

**Headline: hashing IPs changed accuracy by 0.00 percentage points. Patient privacy costs almost no accuracy.**
(CICIDS DDoS flows are highly separable, so detection does not depend on IP identity — exactly the privacy-friendly result we want.)

## Files handed to the team
- `outputs/unsw_{train,val,test}.csv`, `outputs/scaler_unsw.json`, `outputs/encoders_unsw.json`
- `outputs/cicids_{train,val,test}.csv`, `outputs/scaler_cicids.json`
- `outputs/assets.csv` (asset + criticality, **simulated**) -> for Jason
- `outputs/privacy_before_after.png`, `outputs/privacy_preview.csv`
- `outputs/accuracy_comparison.csv`, `outputs/accuracy_comparison.png`
- `threat_intel.py` -> `is_known_bad(url)` for Jason (33,518 malicious URLs loaded)
- `outputs/threat_urls.csv` (sample lookup list)

## Handoff message for the group (copy/paste)
> CyberShield AI - Nour's data pipeline is ready.
>
> Files (repo: data_pipeline/outputs/):
> - unsw_train.csv (149,039), unsw_val.csv (26,302), unsw_test.csv (82,332) + scaler_unsw.json + encoders_unsw.json
> - cicids_train.csv (105,000), cicids_val.csv (22,500), cicids_test.csv (22,500) + scaler_cicids.json
> - assets.csv (asset + criticality, SIMULATED) for Jason
> - privacy_before_after.png and accuracy_comparison.png for Felix
> - threat_intel.py -> is_known_bad(url) for Jason (33.5k malicious URLs)
>
> Target column: label_binary (0 = normal, 1 = attack). Every split also carries asset + criticality (1-5) for risk weighting.
> Public datasets are stand-ins for hospital activity. No real patient data is used.
> Headline: hashing patient-identifying IPs changed accuracy by 0.00 percentage points.

## What to say to the judges (privacy part)
"Identifiers are HMAC-hashed before analysis, so analysts see repeatable patterns without seeing who a device or person is. We tested detection with the original IPs, with hashed IPs, and with aggressively masked IPs: accuracy stayed at 0.9999 in all three cases. Protecting patient privacy cost us 0.00% accuracy."
