# Network Threat Detection Model

Part of **CyberShield AI** by **NeuroSpark** · IBM Z Datathon 2026 · Event code **SSF2026**

This module scores network flows for attack likelihood. It was trained and evaluated on **IBM LinuxONE (s390x)** with **IBM Snap ML**, and it plugs into the team pipeline through the contract in [`../shared/CONTRACT.md`](../shared/CONTRACT.md): it produces `network_score`, a float from 0.0 to 1.0. Fusion into `risk_score` and the recommended action is done by the engine, not here.

## Quick start (for the engine)

```python
import sys
sys.path.insert(0, "models")                  # repo folder with network_score.py
from network_score import score, score_batch
import pandas as pd

df = pd.read_csv("data_pipeline/outputs/unsw_test.csv")   # Nour's processed split
network_score = score_batch(df)               # numpy array in [0.0, 1.0], one value per row
one = score(df.iloc[0].to_dict())             # a single flow -> float in [0.0, 1.0]
```

- **Input:** a row of Nour's processed UNSW-NB15 split (`data_pipeline/outputs/unsw_*.csv`): the 42 z-scored feature columns listed in `models/model_features_unsw.json` (same order as `scaler_unsw.json -> columns`). Extra columns (`asset`, `criticality`, `label_binary`) are ignored.
- **Output:** `network_score`, the model's predicted probability that the flow is an attack. If scoring fails for any reason, `score()` returns `0.0` (the contract rule), with a warning.
- **Environment:** run it on the LinuxONE VM in `venv2` (`source ~/cybershield/venv2/bin/activate`). The model is a pickle trained there with IBM Snap ML. We did not test loading it on other platforms.
- The raw probability is **not calibrated**. A score above 0.5 does not mean a 50% chance of an attack, so thresholds belong in the engine (see the sensitivity table below).

## Platform

| Item | Value |
|---|---|
| Platform | IBM LinuxONE Community Cloud, Ubuntu, `s390x` |
| Resources | 3 vCPU, 7.8 GB RAM |
| Python | 3.12.3 |
| ML libraries | IBM Snap ML 1.17.2, scikit-learn 1.4.1, pandas 2.1.4 |
| Accelerator | Snap ML ran in **CPU-only mode** (NNPA was not used) |

## Results

Everything below is measured on a **held-out test set**, run on LinuxONE. Raw outputs are in [`results/`](results/).

### 1. Integrated model (contract version), UNSW-NB15 processed split

Trained on the team pipeline's processed data: 149,039 train / 26,302 validation / 82,332 test flows, 42 features. IBM Snap ML Random Forest (100 trees).

| Metric | Result |
|---|---|
| Test AUC | 0.982 |
| Training time | 6.1 s |
| Inference | 0.0019 ms per flow |

Sensitivity trade-off on the test set (the engine can choose where to cut):

| Threshold | False positive rate | Recall | Precision | Accuracy |
|---|---|---|---|---|
| 0.5 | 27.3% | 98.7% | 81.6% | 87.1% |
| 0.7 (high sensitivity) | 13.6% | 95.0% | 89.6% | 91.2% |
| **0.8 (reference)** | **6.7%** | **91.8%** | **94.4%** | **92.5%** |
| 0.9 (low noise) | 2.0% | 87.1% | 98.2% | 92.0% |
| 0.95 | 0.7% | 81.2% | 99.3% | 89.3% |

**Reference threshold 0.8** was chosen on the **validation** set (the first value where validation false positives fell below 2%; validation FPR was 1.6%) and then reported on test without re-tuning. At the default 0.5 about 1 in 4 normal flows would raise a false alarm, which is too noisy for a security team. The price of 0.8 is about 7 points of recall compared with 0.5.

### 2. Per-attack results, raw UNSW-NB15 run

Nour's processed CSVs do not carry the attack type, so the per-attack breakdown comes from our earlier run on the raw UNSW-NB15 files (34 features, 82,332 test flows, threshold 0.8). That run reached 92.4% accuracy, 95.9% precision, 90.0% recall and 4.7% false positives.

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

The stricter threshold has a visible cost: Fuzzers detection falls from about 87% at threshold 0.5 to 46% at 0.8.

### 3. Brute force, DDoS and port scan on CIC-IDS2017

UNSW-NB15 has no brute-force class, so a second model was trained on CIC-IDS2017 (78 CICFlowMeter features, balanced sample of 333,288 flows, 66,658 test flows, threshold 0.5).

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

This model is a standalone result. It is not wired into the contract entry point, which covers the UNSW-NB15 format only. (A tenth group of 10 flows from very rare classes is omitted because it is too small to interpret.)

### 4. Snap ML vs scikit-learn on IBM Z (raw UNSW-NB15, default threshold)

| | scikit-learn | IBM Snap ML |
|---|---|---|
| Training time | 6.7 s | 5.2 s |
| Inference | 0.0028 ms/flow | 0.0019 ms/flow |
| Test accuracy | 86.5% | 86.0% |
| Test recall | 97.5% | 97.8% |

Snap ML was about 22% faster to train and 32% faster at inference with comparable accuracy. This is a single run on a small dataset, so treat the speed-up as indicative.

## Files

```
models/                              (integration folder, used by the engine)
  network_score.py                   score(flow) / score_batch(df) -> network_score in [0, 1]
  train_contract.py                  trains the contract model on data_pipeline/outputs/unsw_*.csv
  model_unsw.pkl                     trained Snap ML model bundle (model, features, reference threshold)
  model_features_unsw.json           exact feature order, matches scaler_unsw.json columns

network_model/                       (evidence and standalone experiments)
  notebooks/01_explore.ipynb         data exploration and laptop baseline
  src/
    train_snap.py                    scikit-learn vs Snap ML comparison and threshold sweep (raw UNSW-NB15)
    final_eval.py                    per-attack evaluation on raw UNSW-NB15
    prep_cicids.py                   merges and cleans CIC-IDS2017, builds a balanced sample
    train_cicids.py                  trains and evaluates the CIC-IDS2017 model
    network_detector.py              standalone scorer for the raw UNSW-NB15 model
    cicids_detector.py               standalone scorer for the CIC-IDS2017 model
    cicids_smoke_test.py             quick loader check
  results/                           raw output files from the LinuxONE runs
```

The standalone `network_detector.py` and `cicids_detector.py` print a `risk_score` column scaled 0 to 100. That is only a scaled probability for our own experiments. It is **not** the contract's `risk_score`, which only the engine writes. The engine should use `models/network_score.py`.

## Reproduce

1. On the LinuxONE VM, create the environment: `python3 -m venv --system-site-packages venv2`, `source venv2/bin/activate`, `pip install snapml` (pandas and scikit-learn come from the Ubuntu packages `python3-pandas python3-sklearn`).
2. Put `models/train_contract.py`, `models/network_score.py`, `scaler_unsw.json` and the three `unsw_*.csv` files from `data_pipeline/outputs/` in one folder.
3. `python train_contract.py` trains the model and writes `model_unsw.pkl` and `model_features_unsw.json`. It also prints the threshold table and confirms the feature list matches `scaler_unsw.json`.
4. `python network_score.py unsw_test.csv` self-tests the entry point (scores inside 0 to 1, accuracy equal to the training run).

For the raw-data and CIC-IDS2017 experiments, see `network_model/src/`. pyarrow has no prebuilt s390x wheel, so convert Parquet files to CSV on another machine first.

## Privacy

Both datasets are public, lab-generated network captures and contain no real personal data. The models use only flow statistics (durations, packet and byte counts, flags, window sizes), never IP addresses or payloads. IP hashing and masking are handled upstream by the data pipeline.

## Limitations

- **CIC-IDS2017 scores are optimistic.** The train/validation/test split is random inside the same capture days, so flows from the same attack session appear on both sides. 99.8% accuracy should not be read as expected real-world performance. The UNSW-NB15 results (about 92% accuracy, 5 to 7% false alarms) are the more realistic estimate.
- **UNSW-NB15 has a distribution gap** between its training and test files (68% attacks in train vs 55% in test), which is why test scores are lower than validation scores at the same threshold.
- **Fuzzers are detected poorly** (45.6%) at threshold 0.8. Lower thresholds recover them at the cost of more false alarms.
- **Per-attack results exist only for the raw-data run.** The integrated model uses Nour's processed split, which has no attack type column, so we report only its binary results.
- **"Malware-like" means different things in the two datasets:** Backdoor, Shellcode and Worms in UNSW-NB15, botnet in CIC-IDS2017. Neither dataset contains ransomware, so we make no ransomware claims.
- **Brute force** is covered only by the standalone CIC-IDS2017 model, with fewer examples (9,150 flows) than DoS or port scan.
- Snap ML ran on CPU only. We did not use the NNPA accelerator.

## Datasets and libraries

- UNSW-NB15: Moustafa and Slay, "UNSW-NB15: a comprehensive data set for network intrusion detection systems", MilCIS 2015. Pre-split Parquet files from Kaggle: https://www.kaggle.com/datasets/dhoogla/unswnb15
- CIC-IDS2017 (`MachineLearningCSV.zip`, Canadian Institute for Cybersecurity): Sharafaldin, Habibi Lashkari and Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018.
- Libraries: IBM Snap ML, scikit-learn, pandas, NumPy, joblib.