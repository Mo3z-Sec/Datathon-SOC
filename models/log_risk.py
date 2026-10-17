#!/usr/bin/env python3
"""Interface for Jason's real-time engine: score one HDFS block (or log window).

    from log_risk import LogRiskModel
    m = LogRiskModel("results/log_model_pca.joblib")
    m.score_events([3, 3, 5, 7, 7, 7, 2, 1])      # list of event IDs seen for a block
    m.score_counts({"E3": 2, "E5": 1})            # or a dict / array of event counts

Returns:
    {"score": 0.0-1.0, "level": "NORMAL|WARNING|CRITICAL", "raw": float,
     "threshold_raw": float, "timestamp": ISO-8601 UTC,
     "top_events": [{"event_id": int, "residual": float}, ...]}      # PCA model only

Risk scale (piecewise linear on the raw anomaly score):
    0.25 = WARNING threshold  (high-recall point, catches almost every anomaly)
    0.50 = CRITICAL threshold (balanced point, best F1)
    1.00 = a clearly anomalous block
`top_events` lists the event types the model could not explain, so an analyst (or the
dashboard) can show *why* a block was flagged. Look up the text in hdfs_templates.csv.
residual > 0: the block has MORE of this event than the model expects.
residual < 0: the block is MISSING events the model expects (e.g. truncated write).
(Values are in log1p-count units: a hint for analysts, not an exact count.)

Works with both bundles: results/log_model_pca.joblib (default, recommended) and the
older Isolation Forest results/log_model.joblib.
"""
import datetime as dt

import joblib
import numpy as np

WARNING_AT = 0.25
CRITICAL_AT = 0.5
DEFAULT_MODEL = "results/log_model_pca.joblib"


class LogRiskModel:
    def __init__(self, path: str = DEFAULT_MODEL):
        b = joblib.load(path)
        self.kind = b.get("kind", "iforest")      # older bundles have no "kind"
        self.model = b["model"]
        self.ev_cols = b["ev_cols"]
        self.n = b["n_events"]
        self.thr = b["threshold"]
        if "anchors" in b:
            self.anchors, self.levels = b["anchors"], b["levels"]
        else:                                      # Isolation Forest bundle: lo / threshold / hi
            lo, hi = b["score_lo"], b["score_hi"]
            self.anchors = [lo, (lo + self.thr) / 2, self.thr, hi]
            self.levels = [0.0, 0.25, 0.5, 1.0]

    def _raw(self, x: np.ndarray):
        """Return (raw anomaly score, per-event residuals or None) for log1p counts x."""
        row = x.reshape(1, -1)
        if self.kind == "pca":
            recon = self.model.inverse_transform(self.model.transform(row))
            resid = (row - recon)[0]
            # The score keeps the raw residual (thresholds were tuned on it). For the
            # explanation, counts can't be negative, so clip the reconstruction at 0;
            # otherwise absent events get phantom positive residuals.
            shown = (row - np.maximum(recon, 0.0))[0]
            return float(np.mean(resid * resid)), shown
        return float(-self.model.score_samples(row)[0]), None

    def _result(self, vec: np.ndarray) -> dict:
        raw, resid = self._raw(np.log1p(vec))
        risk = float(np.interp(raw, self.anchors, self.levels))
        level = "CRITICAL" if risk >= CRITICAL_AT else "WARNING" if risk >= WARNING_AT else "NORMAL"
        out = {"score": round(risk, 4), "level": level, "raw": raw,
               "threshold_raw": self.thr,
               "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}
        if resid is not None:
            top = np.argsort(-np.abs(resid))[:3]
            out["top_events"] = [{"event_id": int(i) + 1, "residual": round(float(resid[i]), 4)}
                                 for i in top if abs(resid[i]) > 1e-9]
        return out

    def score_events(self, event_ids) -> dict:
        v = np.zeros(self.n, dtype=np.float64)
        for e in event_ids:
            if 1 <= int(e) <= self.n:
                v[int(e) - 1] += 1
        return self._result(v)

    def score_counts(self, counts) -> dict:
        if isinstance(counts, dict):
            v = np.array([counts.get(c, 0) for c in self.ev_cols], dtype=np.float64)
        else:
            v = np.asarray(counts, dtype=np.float64)
        return self._result(v)


if __name__ == "__main__":
    import sys
    m = LogRiskModel(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODEL)
    print(m.score_events([1, 2, 3, 3, 4, 5]))
