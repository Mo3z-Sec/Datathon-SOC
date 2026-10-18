"""Contract entry point: score(flow) -> network_score in [0.0, 1.0].

`flow` is one row of Nour's processed UNSW-NB15 split (data_pipeline/outputs/unsw_*.csv):
a dict, pandas Series or DataFrame with the 42 feature columns of model_features_unsw.json.
Extra columns (asset, criticality, label_binary) are ignored.
Run on the LinuxONE VM in venv2 (the model was trained there with IBM Snap ML).
"""
import os
import warnings

import joblib
import numpy as np
import pandas as pd

_HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(_HERE, "model_unsw.pkl")
_bundle = None


def _load():
    global _bundle
    if _bundle is None:
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


def score_batch(df):
    b = _load()
    X = np.nan_to_num(df[b["features"]].values.astype(np.float32))
    return np.clip(b["model"].predict_proba(X)[:, 1], 0.0, 1.0)


def score(flow):
    """One row -> float. A DataFrame -> array. On any failure returns 0.0 (contract rule)."""
    try:
        if isinstance(flow, pd.DataFrame):
            return score_batch(flow)
        if isinstance(flow, pd.Series):
            flow = flow.to_dict()
        return float(score_batch(pd.DataFrame([flow]))[0])
    except Exception as e:
        warnings.warn(f"network_score failed, using 0.0: {e}")
        return np.zeros(len(flow)) if isinstance(flow, pd.DataFrame) else 0.0


if __name__ == "__main__":
    import sys
    df = pd.read_csv(sys.argv[1] if len(sys.argv) > 1 else "unsw_test.csv")
    s = score_batch(df)
    b = _load()
    print("scores: min %.3f, max %.3f (must be inside 0..1)" % (s.min(), s.max()))
    if "label_binary" in df.columns:
        acc = ((s >= b["threshold"]).astype(int) == df["label_binary"].values).mean()
        print("accuracy at saved threshold %.2f: %.4f (expected %.4f)" % (b["threshold"], acc, b["ref_test_acc"]))
    print("single row score:", round(score(df.iloc[0].to_dict()), 4), "| same row in batch:", round(float(s[0]), 4))