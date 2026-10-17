# Handoff message (copy / paste into the group)

> **CyberShield AI — Nour's part is done and running on LinuxONE.**
>
> **PR open (please review/merge):** https://github.com/Mo3z-Sec/Datathon-SOC/pull/1
> Branch `nour/data-pipeline` → `main`. It's conflict-free and mergeable now.
>
> **What's in it**
> 1. `data_pipeline/` — clean UNSW-NB15 (train 149,039 / val 26,302 / test 82,332) + `scaler_unsw.json` + `encoders_unsw.json`; clean CICIDS2017 (105,000 / 22,500 / 22,500) + `scaler_cicids.json`; simulated hospital `assets.csv` (asset + criticality 1–5); patient-privacy hashing/masking; `threat_intel.is_known_bad(url)` (OpenPhish/URLhaus).
> 2. **Integration scaffolding** so our parts actually connect: `shared/CONTRACT.md` + `shared/schema.py` + `shared/sample_alerts.csv`, plus folders `models/ engine/ dashboard/ deploy/` and `INTEGRATION.md`.
>
> **Verified on LinuxONE** (host `neurospark-datathon`, Ubuntu 24.04, **s390x**, 7.8 GB RAM):
> `bash data_pipeline/run_on_linuxone.sh` → **6/6 steps OK**, same splits, same accuracy as local.
> Proof file: `data_pipeline/outputs/linuxone_proof.txt`.
>
> **The one rule everyone needs:** every part emits the same 9 columns —
> `timestamp, asset, criticality, src_ip_hashed, network_score, anomaly_score, threat_flag, risk_score, recommended_action`
> Only Jason writes `risk_score` + `recommended_action`. Rules: `shared/CONTRACT.md`.
>
> **What I need from each person**
> - **Hanan / Bardia** → put your model in `models/`, emit `network_score` / `anomaly_score` (0–1) + your feature-order JSON.
> - **Jason** → implement the fusion with `shared/schema.py` (`compute_risk_score`), write `engine/alerts.csv`.
> - **Felix** → build the Streamlit dashboard against `shared/sample_alerts.csv` **today** (it's already valid). Attachments for the report: `privacy_before_after.png`, `accuracy_comparison.png`, `linuxone_proof.txt`.
> - **Moe** → merge the PR; we still need the container/response-sim in `deploy/`.
>
> **Headline for the judges:** *hashing patient-identifying IPs changed detection accuracy by 0.00 percentage points — patient privacy costs almost no accuracy.*

---

## Local files for Felix / the report

| file | purpose |
|---|---|
| `data_pipeline/outputs/linuxone_proof.txt` | screenshot: full LinuxONE run evidence |
| `data_pipeline/outputs/privacy_before_after.png` | IP hashing/masking before/after |
| `data_pipeline/outputs/accuracy_comparison.png` | original vs hashed vs masked accuracy |
| `data_pipeline/outputs/accuracy_comparison.csv` | the numbers behind the headline |

## Open it in one line (Windows)

```powershell
notepad "C:\Users\Nourm\Desktop\AI Secured Innovation without Exposure\data_pipeline\outputs\linuxone_proof.txt"
```
Or show the live run log on the VM (screenshot this instead):
```powershell
ssh linuxone
cat ~/Datathon-SOC/run.log
```
