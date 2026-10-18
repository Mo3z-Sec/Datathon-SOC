"""Log-anomaly wiring: Bardia's LogRiskModel  ->  `anomaly_score` for SOC alerts.

Bardia's model (log_risk.py, unchanged) scores one *window of event counts*: PCA is fitted on
normal windows and the reconstruction error is mapped to a 0..1 risk (0.25 = WARNING,
0.5 = CRITICAL). This file supplies the three things his code does not:

  1. a tokenizer + windowing step that turns the SOC's hospital logs into event-count windows,
  2. a trainer that writes a bundle in exactly the format LogRiskModel loads, and
  3. `SocAnomalyScorer`, which gives every alert an anomaly_score from the windows it touches.

Why a SOC-specific bundle?  The BGL / HDFS bundles (results_bgl/log_model_bgl.joblib) were
trained on supercomputer / Hadoop event IDs. A hospital "login_failure" is not BGL event 17, so
those weights cannot score hospital logs. The *method* is Bardia's; the vocabulary is the SOC's.
The same trainer also rebuilds a BGL bundle (`python -m models.log_anomaly bgl`) so his original
use-case can be shown on real data.

    python -m models.log_anomaly soc     # (re)train models/results_soc/log_model_soc.joblib
    python -m models.log_anomaly bgl     # (re)train models/results_bgl/log_model_bgl.joblib
"""
from __future__ import annotations

import datetime as dt
import os
import sys
from collections import defaultdict

import joblib
import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, _ROOT):                       # log_risk.py uses flat imports
    if _p not in sys.path:
        sys.path.insert(0, _p)

from log_risk import CRITICAL_AT, WARNING_AT, LogRiskModel   # noqa: E402  (Bardia's code)

SOC_BUNDLE = os.path.join(_HERE, "results_soc", "log_model_soc.joblib")
BGL_BUNDLE = os.path.join(_HERE, "results_bgl", "log_model_bgl.joblib")
BGL_EVENTS = os.path.join(_HERE, "bgl_events.csv.gz")
WINDOW_S = 900                                  # SOC: 15-minute windows per asset
UNKNOWN = "__unknown__"
LEVELS = [0.0, WARNING_AT, CRITICAL_AT, 1.0]


# ------------------------------------------------------------------ tokenizer / windows ---
def token_of(log: dict) -> str:
    """event_type, plus traffic direction where the log has one (outbound vs internal matters)."""
    d = (log.get("details") or {}).get("direction")
    return f"{log['event_type']}|{d}" if d else str(log["event_type"])


def epoch_of(ts: str) -> float:
    return dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()


def soc_windows(logs, vocab, window_s=WINDOW_S):
    """{(asset, window_idx): count vector over `vocab` + UNKNOWN}, plus {(asset, idx): label}."""
    index = {t: i for i, t in enumerate(vocab)}
    unk = index[UNKNOWN]
    counts, labels = {}, defaultdict(int)
    for lg in logs:
        key = (lg["asset"], int(epoch_of(lg["timestamp"]) // window_s))
        v = counts.setdefault(key, np.zeros(len(vocab)))
        v[index.get(token_of(lg), unk)] += 1
        if lg.get("sim_scenario"):
            labels[key] = 1
    return counts, {k: labels.get(k, 0) for k in counts}


# ------------------------------------------------------------------------- fitting -------
def _raw_scores(pca, X):
    """Same quantity LogRiskModel computes: mean squared PCA reconstruction error of log1p counts."""
    Z = np.log1p(X)
    R = Z - pca.inverse_transform(pca.transform(Z))
    return (R * R).mean(axis=1)


def _make_bundle(pca, ev_cols, raw_norm, raw_val, y_val, **extra):
    """Anchors for LogRiskModel's piecewise-linear map: [lo, warning, critical, 1.0].

    critical = threshold with the best F1 on the labelled validation windows,
    warning  = the (lower) threshold that still catches ~90% of the labelled anomalies,
    lo       = median raw score of normal windows, hi = 99th percentile of anomalies.
    """
    cand = np.unique(np.quantile(raw_val, np.linspace(0.5, 0.999, 300)))
    best_f1, thr = -1.0, cand[-1]
    for t in cand:
        tp = ((raw_val >= t) & (y_val == 1)).sum()
        fp = ((raw_val >= t) & (y_val == 0)).sum()
        fn = ((raw_val < t) & (y_val == 1)).sum()
        f1 = 2 * tp / max(2 * tp + fp + fn, 1)
        if f1 > best_f1:
            best_f1, thr = f1, t
    pos = raw_val[y_val == 1]
    warn = min(float(np.quantile(pos, 0.10)), thr * 0.999)
    lo = min(float(np.median(raw_norm)), warn * 0.5)
    hi = max(float(np.quantile(pos, 0.99)), thr * 1.5)
    return dict(kind="pca", model=pca, ev_cols=list(ev_cols), n_events=len(ev_cols), threshold=float(thr),
                anchors=[float(lo), float(warn), float(thr), float(hi)], levels=LEVELS, val_f1=float(best_f1),
                **extra)


# ---------------------------------------------------------------------- SOC bundle -------
def train_soc_bundle(path=SOC_BUNDLE, assets_csv=None, verbose=True):
    """PCA fitted on benign-only simulated days; thresholds tuned on separate labelled days.

    Seeds: fit 1000-1029 (benign only) | tune 2000-2009 (benign + scenarios) | demo uses 42.
    """
    from sklearn.decomposition import PCA
    from soc.assets import load_assets
    from soc.generator import generate

    assets = load_assets(assets_csv or os.path.join(_ROOT, "data", "assets.csv"))
    day = dt.date(2026, 10, 17)

    def days(seeds, scenarios):
        return [generate(assets, seed=s, day=day, benign=300, scenarios=scenarios) for s in seeds]

    fit_days, val_days = days(range(1000, 1030), []), days(range(2000, 2010), None)
    vocab = sorted({token_of(l) for d in fit_days + val_days for l in d}) + [UNKNOWN]

    def mat(day_logs):
        X, y = [], []
        for logs in day_logs:
            c, lab = soc_windows(logs, vocab)
            X += [c[k] for k in c]
            y += [lab[k] for k in c]
        return np.array(X), np.array(y)

    Xf, _ = mat(fit_days)
    Xv, yv = mat(val_days)
    best = None
    for k in (1, 2, 3, 4, 6):                    # pick PCA size by validation F1
        pca = PCA(n_components=k, random_state=0).fit(np.log1p(Xf))
        b = _make_bundle(pca, vocab, _raw_scores(pca, Xf), _raw_scores(pca, Xv), yv,
                         source="soc-simulated", window_s=WINDOW_S)
        if verbose:
            print(f"  PCA k={k}: validation F1 = {b['val_f1']:.3f}")
        if best is None or b["val_f1"] > best["val_f1"]:
            best = b
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(best, path, compress=3)
    if verbose:
        print(f"saved {path}  (k={best['model'].n_components}, vocab={len(vocab)}, F1={best['val_f1']:.3f})")
    return best


# ---------------------------------------------------------------------- BGL bundle -------
def train_bgl_bundle(path=BGL_BUNDLE, window_s=300, verbose=True):
    """Rebuild a BGL bundle from models/bgl_events.csv.gz (ts, event_id, label), time-ordered 60/20/20."""
    import pandas as pd
    from sklearn.decomposition import PCA

    df = pd.read_csv(BGL_EVENTS)
    n_ev = int(df["event_id"].max())
    df["w"] = (df["ts"] // window_s).astype("int64")
    wins = np.sort(df["w"].unique())
    w_idx = pd.Series(np.arange(len(wins)), index=wins)
    rows, cols = w_idx.loc[df["w"].values].values, df["event_id"].values - 1
    X = np.zeros((len(wins), n_ev), dtype=np.float32)
    np.add.at(X, (rows, cols), 1)
    y = (df.groupby("w")["label"].max().reindex(wins).values > 0).astype(int)
    a, b = int(len(wins) * 0.6), int(len(wins) * 0.8)
    Xtr, ytr, Xva, yva, Xte, yte = X[:a], y[:a], X[a:b], y[a:b], X[b:], y[b:]
    pca = PCA(n_components=12, random_state=0).fit(np.log1p(Xtr[ytr == 0]))
    bundle = _make_bundle(pca, [f"E{i}" for i in range(1, n_ev + 1)], _raw_scores(pca, Xtr[ytr == 0]),
                          _raw_scores(pca, Xva), yva, source="bgl", window_s=window_s)
    raw_te = _raw_scores(pca, Xte)
    pred = raw_te >= bundle["threshold"]
    tp, fp, fn = int((pred & (yte == 1)).sum()), int((pred & (yte == 0)).sum()), int((~pred & (yte == 1)).sum())
    from sklearn.metrics import roc_auc_score
    bundle["test"] = dict(windows=int(len(yte)), anomalous=int(yte.sum()), tp=tp, fp=fp, fn=fn,
                          precision=tp / max(tp + fp, 1), recall=tp / max(tp + fn, 1),
                          auc=float(roc_auc_score(yte, raw_te)) if 0 < yte.sum() < len(yte) else None)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(bundle, path, compress=3)
    if verbose:
        print(f"saved {path}  test: {bundle['test']}")
    return bundle


# ------------------------------------------------------------------- alert scoring -------
class SocAnomalyScorer:
    """anomaly_score for alerts, from Bardia's LogRiskModel on the SOC's own log windows."""

    def __init__(self, path=SOC_BUNDLE, retrain_if_missing=True):
        try:
            self.model = LogRiskModel(path)
        except Exception:                        # missing, or pickled with another sklearn version
            if not retrain_if_missing:
                raise
            train_soc_bundle(path, verbose=False)
            self.model = LogRiskModel(path)
        self.vocab = self.model.ev_cols
        self.window_s = joblib.load(path).get("window_s", WINDOW_S)
        self.window_results = {}

    def fit_logs(self, logs):
        """Score every (asset, window) in `logs` once. Returns {(asset, idx): LogRiskModel result}."""
        counts, labels = soc_windows(logs, self.vocab, self.window_s)
        self.window_results = {k: self.model.score_counts(v) for k, v in counts.items()}
        self.window_labels = labels
        self.window_counts = counts
        return self.window_results

    def score_alert(self, alert) -> dict:
        """Worst window the alert's asset was in while the alert was active."""
        lo, hi = int(alert["first_epoch"] // self.window_s), int(alert["last_epoch"] // self.window_s)
        best = None
        for idx in range(lo, hi + 1):
            r = self.window_results.get((alert["asset"], idx))
            if r and (best is None or r["score"] > best["score"]):
                best = r
        if best is None:
            return {"score": 0.0, "level": "NORMAL", "top_events": []}
        top = [{"event": self.vocab[t["event_id"] - 1], "residual": t["residual"]} for t in best.get("top_events", [])
               if t["residual"] > 0]          # only events in EXCESS explain a flag; negatives are "missing"
        return {"score": float(best["score"]), "level": best["level"], "top_events": top}


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "soc"
    train_bgl_bundle() if which == "bgl" else train_soc_bundle()
