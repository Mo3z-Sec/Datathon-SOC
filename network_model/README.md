# Network Threat Detection Model

Part of **CyberShield AI** by **NeuroSpark** · IBM Z Datathon 2026 · Event code **SSF2026**

This module detects malicious network traffic in real time. It scores each network flow with a risk score (0-100) and a yes/no attack flag. It was trained and evaluated on **IBM LinuxONE (s390x)** using **IBM Snap ML**.

Two detectors are provided because the two public datasets use different feature formats:

| Detector | Dataset | Input format | Covers |
|---|---|---|---|
| `NetworkDetector` | UNSW-NB15 | 34 flow features | DoS, reconnaissance (port scan), exploits, fuzzers, generic, analysis, backdoor/shellcode/worms |
| `CicidsDetector` | CIC-IDS2017 | 78 CICFlowMeter features | **Brute force (FTP/SSH)**, DoS/DDoS, port scan, web attacks, botnet |

## Platform

| Item | Value |
|---|---|
| Platform | IBM LinuxONE Community Cloud, Ubuntu, `s390x` |
| Resources | 3 vCPU, 7.8 GB RAM |
| Python | 3.12.3 |
| ML libraries | IBM Snap ML 1.17.2, scikit-learn 1.4.1, pandas 2.1.4 |
| Accelerator | Snap ML ran in **CPU-only mode** (NNPA was not used) |

## Results

All numbers below are measured on the **held-out test set**, run on LinuxONE. Raw output files are in [`results/`](results/).

### UNSW-NB15 (82,332 test flows), Snap ML Random Forest, threshold 0.8

| Metric | Result |
|---|---|
| Accuracy | 92.4% |
| Precision | 95.9% |
| Recall | 90.0% |
| False positive rate | 4.7% |

Detection rate per attack group (Normal row = share of normal traffic wrongly flagged):

| Group | Detected | Test flows |
|---|---|---|
| Generic | 99.5% | 18,871 |
| Port scan / Recon | 97.3% | 3,496 |
| DoS / DDoS | 95.9% | 4,089 |
| Analysis | 95.1% | 677 |
| Exploits | 93.4% | 11,132 |
| Malware-like (Backdoor, Shellcode, Worms) | 88.0% | 1,005 |
| Fuzzers | 45.6% | 6,062 |
| *Normal (false alarms)* | *4.7%* | *37,000* |

**Sensitivity trade-off.** The default threshold (0.5) flags almost every attack but also 28.5% of normal traffic, which would flood a security team with false alarms. We chose the threshold on the **validation** set (the first value where validation false positives fell below 2%), then reported test results without re-tuning.

| Threshold | False positive rate | Recall | Precision | Accuracy |
|---|---|---|---|---|
| 0.5 (default) | 28.5% | 97.8% | 80.8% | 86.0% |
| 0.7 (high sensitivity) | 12.8% | 93.6% | 89.9% | 90.7% |
| **0.8 (chosen, balanced)** | **4.7%** | **90.0%** | **95.9%** | **92.4%** |
| 0.9 (low noise) | 1.5% | 85.8% | 98.6% | 91.5% |

The cost of the stricter threshold is visible: Fuzzers detection drops from about 87% (at 0.5) to 46%. Operators can pick 0.7 / 0.8 / 0.9 at run time.

### CIC-IDS2017 (66,658 test flows), Snap ML Random Forest, threshold 0.5

| Metric | Result |
|---|---|
| Accuracy | 99.80% |
| Precision | 99.85% |
| Recall | 99.64% |
| False positive rate | 0.10% |
| Training time | 9.9 s |
| Inference | 0.0017 ms per flow |

| Group | Detected | Test flows |
|---|---|---|
| **Brute force (FTP-Patator, SSH-Patator)** | **99.9%** | 1,830 |
| **DoS / DDoS** | **99.9%** | 12,000 |
| **Port scan** | **100%** | 12,000 |
| Web attacks | 98.1% | 428 |
| Malware-like (botnet) | 83.9% | 390 |
| *Normal (false alarms)* | *0.10%* | *40,000* |

(A tenth group of 10 flows from very rare classes is omitted; it is too small to interpret.)

### Snap ML vs scikit-learn on IBM Z (UNSW-NB15, default threshold)

| | scikit-learn | IBM Snap ML |
|---|---|---|
| Training time | 6.7 s | 5.2 s |
| Inference | 0.0028 ms/flow | 0.0019 ms/flow |
| Test accuracy | 86.5% | 86.0% |
| Test recall | 97.5% | 97.8% |

Snap ML was about 22% faster to train and 32% faster at inference with comparable accuracy. This is a single run on a small dataset, so treat the speed-up as indicative.

## How to use

```python
import pandas as pd
from network_detector import NetworkDetector      # UNSW-NB15 format
from cicids_detector import CicidsDetector        # CIC-IDS2017 format

df = pd.read_csv("flows.csv", keep_default_na=False)
out = NetworkDetector("cybershield_network_model.joblib").predict(df)
# out["risk_score"]  0-100
# out["is_attack"]   1 = attack, 0 = normal

# change sensitivity at run time:
out = NetworkDetector("cybershield_network_model.joblib").predict(df, threshold=0.7)
```

The two detectors need **different input columns**, so a flow must be in the format of the detector that scores it. Use `keep_default_na=False` when reading UNSW-NB15 CSVs (the service value `"-"` and others must not become missing values).

## Files

```
network_model/
  notebooks/01_explore.ipynb      data exploration and laptop baseline
  src/
    train_snap.py                 scikit-learn vs Snap ML comparison + threshold sweep (UNSW-NB15)
    final_eval.py                 final UNSW-NB15 model, test report, saves the model bundle
    network_detector.py           loader/scorer for the UNSW-NB15 model
    prep_cicids.py                merges and cleans CIC-IDS2017, builds a balanced sample
    train_cicids.py               trains and evaluates the CIC-IDS2017 model
    cicids_detector.py            loader/scorer for the CIC-IDS2017 model
    cicids_smoke_test.py          quick check that the loader works
  results/                        raw output text files from the LinuxONE runs
```

Datasets and trained model files (`*.joblib`) are not stored in the repository (see `.gitignore`).

## Reproduce

1. Download the datasets (see below). Convert the UNSW-NB15 Parquet files to CSV on a machine with pyarrow (pyarrow has no prebuilt s390x wheel):
   `python -c "import pandas as pd; pd.read_parquet('UNSW_NB15_training-set.parquet').to_csv('unsw_train.csv', index=False); pd.read_parquet('UNSW_NB15_testing-set.parquet').to_csv('unsw_test.csv', index=False)"`
2. `python prep_cicids.py` (put the CIC-IDS2017 `MachineLearningCVE` CSVs in `data/cicids/`) to create `cicids_sample.csv`.
3. Copy the CSVs to the LinuxONE VM, create an environment with `python3 -m venv --system-site-packages venv2`, `pip install snapml`, and install pandas/scikit-learn from Ubuntu packages (`python3-pandas python3-sklearn`).
4. Run `python final_eval.py` and `python train_cicids.py`.

## Privacy

Both datasets are public, lab-generated network captures and contain no real personal data. The models use only flow statistics (durations, packet and byte counts, flags), not payloads.

## Limitations

- **CIC-IDS2017 scores are optimistic.** The train/validation/test split is random inside the same capture days, so flows from the same attack session appear in both train and test. 99.8% accuracy should not be read as expected real-world performance. The UNSW-NB15 result (92.4%, 4.7% false alarms) is the more realistic estimate.
- **UNSW-NB15 has a distribution gap** between its official training and test files (validation 95% vs test 87% at the default threshold). This is a known property of the dataset.
- **Fuzzers are detected poorly** (45.6%) at the chosen threshold. Lower thresholds recover them at the cost of more false alarms.
- **"Malware-like" means different things in the two datasets:** Backdoor/Shellcode/Worms in UNSW-NB15, botnet in CIC-IDS2017. Neither dataset contains ransomware, so we make no ransomware claims.
- **Brute force** is covered only by the CIC-IDS2017 detector (FTP and SSH), with fewer examples (9,150 flows) than DoS or port scan.
- Snap ML ran on CPU only. We did not use the NNPA accelerator.

## Datasets and libraries

- UNSW-NB15: Moustafa and Slay, "UNSW-NB15: a comprehensive data set for network intrusion detection systems", MilCIS 2015. *(add the link you downloaded the pre-split files from)*
- CIC-IDS2017 (`MachineLearningCSV.zip`, Canadian Institute for Cybersecurity): Sharafaldin, Habibi Lashkari and Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018.
- Libraries: IBM Snap ML, scikit-learn, pandas, NumPy, joblib.
