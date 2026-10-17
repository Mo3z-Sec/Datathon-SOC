# models/

Owner: **Hanan**

Put trained models and their entry points here.

## Hanan — network detection
- Trained model (e.g. `model_unsw.pkl` / `model_unsw.json`).
- `model_features_unsw.json` — the **exact** feature order used at training time
  (must match `data_pipeline/outputs/scaler_unsw.json` -> `columns`).
- `score(flow) -> float` returning `network_score` in 0.0–1.0.

## Bardia — log anomaly
- Trained anomaly model + `score(log) -> float` returning `anomaly_score` 0.0–1.0.

## Contract
Output columns are defined in [`../shared/CONTRACT.md`](../shared/CONTRACT.md).
Do **not** produce `risk_score` — that is Jason's job in `../engine/`.
