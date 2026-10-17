import joblib
import numpy as np
import pandas as pd


class NetworkDetector:
    """Loads the trained UNSW-NB15 Snap ML model and scores raw flow records.

    Read input CSVs with pd.read_csv(..., keep_default_na=False).
    """

    def __init__(self, path="cybershield_network_model.joblib"):
        b = joblib.load(path)
        self.model = b["model"]
        self.enc = b["encoder"]
        self.features = b["features"]
        self.cat_cols = b["cat_cols"]
        self.threshold = b["threshold"]

    def score(self, df):
        X = df[self.features].copy()
        X[self.cat_cols] = self.enc.transform(X[self.cat_cols])
        return self.model.predict_proba(X.values.astype(np.float32))[:, 1]

    def predict(self, df, threshold=None):
        thr = self.threshold if threshold is None else threshold
        p = self.score(df)
        return pd.DataFrame(
            {"risk_score": (p * 100).round(1), "is_attack": (p >= thr).astype(int)},
            index=df.index,
        )