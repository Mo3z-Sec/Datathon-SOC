"""Contract entry point: score(flow) -> network_score in [0.0, 1.0].

`flow` is one row of Nour's processed UNSW-NB15 split (data_pipeline/outputs/unsw_*.csv):
a dict, pandas Series or DataFrame with the 42 feature columns of model_features_unsw.json.
Extra columns (asset, criticality, label_binary) are ignored.
Run on the LinuxONE VM in venv2 (the model was trained there with IBM Snap ML).
"""
import json
import os
import warnings

import joblib
import numpy as np
import pandas as pd

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
MODEL_PATH = os.path.join(_HERE, "model_unsw.pkl")          # IBM Snap ML model (needs `snapml`)
FEATURES_PATH = os.path.join(_HERE, "model_features_unsw.json")
TRAIN_CSV = os.path.join(_ROOT, "data_pipeline", "outputs", "unsw_train.csv")
VAL_CSV = os.path.join(_ROOT, "data_pipeline", "outputs", "unsw_val.csv")
TEST_CSV = os.path.join(_ROOT, "data_pipeline", "outputs", "unsw_test.csv")
FALLBACK_PATH = os.path.join(_ROOT, "data", "model_unsw_sklearn.joblib")   # gitignored cache
_bundle = None


def _train_sklearn_fallback():
    """Same data, same 42 features, same threshold rule as train_contract.py, but scikit-learn.

    Used only when `snapml` is not installed (any laptop that is not the LinuxONE VM). Takes
    ~20-60 s once, then is cached in data/ and reloaded instantly.
    """
    from sklearn.ensemble import RandomForestClassifier

    features = json.load(open(FEATURES_PATH))
    tr, va, te = (pd.read_csv(p) for p in (TRAIN_CSV, VAL_CSV, TEST_CSV))
    f32 = lambda d: np.nan_to_num(d[features].values.astype(np.float32))
    model = RandomForestClassifier(n_estimators=60, min_samples_leaf=3, n_jobs=-1, random_state=42)
    model.fit(f32(tr), tr["label_binary"].values)
    pva, pte = model.predict_proba(f32(va))[:, 1], model.predict_proba(f32(te))[:, 1]
    yva, yte = va["label_binary"].values, te["label_binary"].values
    chosen = 0.5
    for thr in (0.3, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95):       # first threshold with val FPR < 2%
        if ((pva >= thr) & (yva == 0)).sum() / max((yva == 0).sum(), 1) < 0.02:
            chosen = thr
            break
    acc = float(((pte >= chosen).astype(int) == yte).mean())
    b = dict(model=model, features=features, threshold=chosen, ref_test_acc=acc, backend="sklearn-fallback")
    os.makedirs(os.path.dirname(FALLBACK_PATH), exist_ok=True)
    joblib.dump(b, FALLBACK_PATH, compress=3)
    return b


def _load():
    """Snap ML model if `snapml` is importable (LinuxONE), otherwise the scikit-learn fallback."""
    global _bundle
    if _bundle is not None:
        return _bundle
    try:
        _bundle = joblib.load(MODEL_PATH)
        _bundle.setdefault("backend", "snapml")
        return _bundle
    except ImportError:
        pass                                                  # snapml missing -> fallback below
    try:
        _bundle = joblib.load(FALLBACK_PATH)
    except Exception:                                         # missing, or saved by another sklearn version
        _bundle = _train_sklearn_fallback()
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
