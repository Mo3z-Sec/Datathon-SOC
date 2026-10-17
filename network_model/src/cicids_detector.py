import joblib
import numpy as np
import pandas as pd


class CicidsDetector:
    """Scores CICFlowMeter flow records (CIC-IDS2017 feature format).

    Detects brute force (FTP/SSH), DoS/DDoS, port scans, web attacks, botnet.
    """

    def __init__(self, path="cicids_model.joblib"):
        b = joblib.load(path)
        self.model = b["model"]
        self.features = b["features"]
        self.threshold = b["threshold"]

    def _prep(self, df):
        df = df.copy()
        df.columns = df.columns.str.strip()
        X = df[self.features].replace([np.inf, -np.inf], np.nan).fillna(0)
        return X.values.astype(np.float32)

    def score(self, df):
        return self.model.predict_proba(self._prep(df))[:, 1]

    def predict(self, df, threshold=None):
        thr = self.threshold if threshold is None else threshold
        p = self.score(df)
        return pd.DataFrame(
            {"risk_score": (p * 100).round(1), "is_attack": (p >= thr).astype(int)},
            index=df.index,
        )