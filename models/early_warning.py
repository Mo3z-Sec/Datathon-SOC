#!/usr/bin/env python3
"""Early-warning layer on top of the per-window anomaly risk from log_risk.py.

A plain anomaly flag fires when a window is already bad. This module also watches the
TREND of the risk, so it can raise a WARNING while the risk is still climbing, minutes
before the first window that the dataset labels as an alert.

Rule (evaluated once per completed time window, in time order):
    smoothed_t = alpha * risk_t + (1 - alpha) * smoothed_{t-1}          (EWMA)
    rule fires if  smoothed stays >= lvl for n_consec windows in a row
               or  smoothed rose by >= slope_thr over the last slope_k windows
    level = CRITICAL  if risk_t >= 0.5                  (full anomaly threshold)
            WARNING   if the rule fires or risk_t >= 0.25
            NORMAL    otherwise
A silence longer than max_gap_windows windows resets the smoothing state.

Live use (Jason's engine) - one monitor per log stream, call once per finished window:
    from early_warning import EarlyWarningMonitor
    mon = EarlyWarningMonitor("results_bgl/log_model_bgl.joblib")
    out = mon.update(window_start_unix_ts, [event_id, event_id, ...])
    # out has the same fields as LogRiskModel.score_events() plus:
    #   "smoothed", "trend", "early_warning" (True = warning raised before the plain flag)

Offline use: run_rule(), evaluate() and chance_early_fraction() below (used by train_bgl.py).

Lead time = start of the first anomalous window of an incident MINUS the moment the
warning was issued (the END of the warning window). A warning in the window right before
the incident therefore counts as 0 lead and does not count as an early warning.

IMPORTANT when judging results: "warned in advance" is only meaningful next to the share of
time the system sits in WARNING (warning_duty) and the chance level
(chance_early_fraction). A signal that is always on warns in advance of everything.
"""
import datetime as dt
from collections import deque
from dataclasses import asdict, dataclass, fields

import numpy as np

from log_risk import CRITICAL_AT, WARNING_AT, LogRiskModel

LEVEL_NAMES = ["NORMAL", "WARNING", "CRITICAL"]


@dataclass
class EWParams:
    alpha: float = 0.5          # EWMA weight of the newest window (1.0 = no smoothing)
    lvl: float = 0.15           # smoothed-risk level that counts as "elevated"
    n_consec: int = 2           # windows in a row at/above lvl before the rule fires
    slope_thr: float = 0.0      # fire if smoothed rose by this much over slope_k windows (0 = off)
    slope_k: int = 2
    window_s: int = 300         # window length in seconds
    max_gap_windows: int = 6    # silence longer than this resets the state

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "EWParams":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in names})


BASELINE = EWParams(alpha=1.0, lvl=WARNING_AT, n_consec=1, slope_thr=0.0)   # = plain risk flag


class EarlyWarningState:
    def __init__(self, params: EWParams):
        self.p = params
        self.reset()

    def reset(self):
        self.ewma = None
        self.hist = deque(maxlen=self.p.slope_k + 1)
        self.consec = 0
        self.last_t = None

    def update(self, t: float, risk: float):
        """Feed one finished window. Returns (smoothed, trend, level 0/1/2, rule_fired)."""
        p = self.p
        if self.last_t is not None and (t - self.last_t) > p.max_gap_windows * p.window_s:
            self.reset()
        self.last_t = t
        e = risk if self.ewma is None else p.alpha * risk + (1.0 - p.alpha) * self.ewma
        self.ewma = e
        self.hist.append(e)
        slope = (e - self.hist[0]) if len(self.hist) == self.hist.maxlen else 0.0
        self.consec = self.consec + 1 if e >= p.lvl else 0
        rule = self.consec >= p.n_consec or (
            p.slope_thr > 0 and slope >= p.slope_thr and e >= 0.5 * p.lvl)
        if risk >= CRITICAL_AT:
            level = 2
        elif rule or risk >= WARNING_AT:
            level = 1
        else:
            level = 0
        return e, slope, level, rule


def run_rule(times, risk, params: EWParams):
    """Run the rule over a whole time-ordered series. Returns (smoothed, trend, level, rule)."""
    st = EarlyWarningState(params)
    t_l, r_l = np.asarray(times, dtype=float).tolist(), np.asarray(risk, dtype=float).tolist()
    n = len(r_l)
    ew, sl = np.empty(n), np.empty(n)
    lv, rl = np.empty(n, dtype=np.int8), np.empty(n, dtype=bool)
    for i in range(n):
        ew[i], sl[i], lv[i], rl[i] = st.update(t_l[i], r_l[i])
    return ew, sl, lv, rl


class EarlyWarningMonitor:
    """Streaming wrapper: LogRiskModel + early-warning rule, parameters read from the bundle."""

    def __init__(self, path: str = "results_bgl/log_model_bgl.joblib"):
        import joblib
        b = joblib.load(path)
        self.model = LogRiskModel(path)
        self.params = EWParams.from_dict(b.get("early_warning", BASELINE.to_dict()))
        self.state = EarlyWarningState(self.params)

    def reset(self):
        self.state.reset()

    def update(self, window_start_ts: float, event_ids) -> dict:
        out = self.model.score_events(event_ids)
        e, slope, level, rule = self.state.update(float(window_start_ts), out["score"])
        out["level"] = LEVEL_NAMES[level]
        out["smoothed"] = round(float(e), 4)
        out["trend"] = round(float(slope), 4)
        out["early_warning"] = bool(rule and out["score"] < WARNING_AT)
        out["window_start"] = dt.datetime.fromtimestamp(
            float(window_start_ts), dt.timezone.utc).isoformat()
        return out


# ---------------------------------------------------------------- evaluation ----------

def find_incidents(times, y, window_s, merge_gap=6):
    """Group anomalous windows into incidents. Returns [(first_idx, last_idx), ...].

    Anomalous windows less than (merge_gap + 1) windows apart belong to the same incident."""
    times = np.asarray(times, dtype=float)
    idx = np.flatnonzero(np.asarray(y).astype(bool))
    if idx.size == 0:
        return []
    breaks = np.flatnonzero(np.diff(times[idx]) > (merge_gap + 1) * window_s)
    starts = np.r_[idx[0], idx[breaks + 1]]
    ends = np.r_[idx[breaks], idx[-1]]
    return [(int(s), int(e)) for s, e in zip(starts, ends)]


def _num(x):
    return None if x is None or (isinstance(x, float) and np.isnan(x)) else float(x)


def evaluate(times, y, level, window_s, horizon_s=3600, merge_gap=6, min_lead_s=None,
             days=None, gap_windows=6, episodes=True):
    """Incident-level evaluation of an alarm signal.

    times: window start times (sorted; may contain gaps, e.g. several separate blocks);
    y: window labels; level: 0/1/2 per window; days: observation time covered (default:
    last minus first window).
    - early_warned: a WARNING/CRITICAL issued at least `min_lead_s` (default one window)
      before the incident, inside the `horizon_s` look-back, on a window that is itself normal.
    - detected: early-warned, or any warning during the incident.
    - warning_duty: share of windows in WARNING or CRITICAL (how often operators are alerted).
    - false warning episode: a run of consecutive warning windows that is not within
      [incident start - horizon, incident end + merge_gap windows] of any incident.
      Note: with very frequent incidents this count is flattering, so judge it with warning_duty.
    """
    times = np.asarray(times, dtype=float)
    y = np.asarray(y).astype(bool)
    level = np.asarray(level)
    min_lead_s = window_s if min_lead_s is None else min_lead_s
    inc = find_incidents(times, y, window_s, merge_gap)
    if days is None:
        days = (times[-1] - times[0] + window_s) / 86400.0
    days = max(float(days), 1e-9)

    leads, detected, prev_end = [], 0, -np.inf
    for s, e in inc:
        st = times[s]
        lo = np.searchsorted(times, max(st - horizon_s, prev_end + (merge_gap + 1) * window_s), "left")
        hi = np.searchsorted(times, st - window_s - min_lead_s, "right")
        lead = np.nan
        if hi > lo:
            cand = np.flatnonzero((level[lo:hi] >= 1) & ~y[lo:hi])
            if cand.size:
                lead = st - (times[lo + cand[0]] + window_s)
        leads.append(lead)
        if (not np.isnan(lead)) or (level[s:e + 1] >= 1).any():
            detected += 1
        prev_end = times[e]

    lead_min = np.array([l / 60.0 for l in leads if not np.isnan(l)])
    n_inc = len(inc)
    out = {
        "n_incidents": n_inc,
        "early_warned": int(lead_min.size),
        "early_fraction": _num(lead_min.size / n_inc) if n_inc else None,
        "detected": int(detected),
        "detected_fraction": _num(detected / n_inc) if n_inc else None,
        "lead_median_min": _num(np.median(lead_min)) if lead_min.size else None,
        "lead_mean_min": _num(np.mean(lead_min)) if lead_min.size else None,
        "lead_p25_min": _num(np.percentile(lead_min, 25)) if lead_min.size else None,
        "warning_duty": float((level >= 1).mean()),
        "days": days,
        "leads_min": [None if np.isnan(l) else round(l / 60.0, 2) for l in leads],
    }
    if not episodes:
        return out

    warn = level >= 1
    brk = np.r_[True, np.diff(times) > gap_windows * window_s]        # first window of a segment
    prev_warn = np.r_[False, warn[:-1]]
    next_warn, next_brk = np.r_[warn[1:], False], np.r_[brk[1:], True]
    r0 = np.flatnonzero(warn & ~(prev_warn & ~brk))
    r1 = np.flatnonzero(warn & ~(next_warn & ~next_brk))
    n_false = 0
    if r0.size:
        if inc:
            span_lo = np.array([times[s] - horizon_s for s, _ in inc])
            span_hi = np.array([times[e] + (merge_gap + 1) * window_s for _, e in inc])
            t0, t1 = times[r0], times[r1] + window_s
            related = ((span_lo[None, :] <= t1[:, None]) & (span_hi[None, :] >= t0[:, None])).any(axis=1)
            n_false = int((~related).sum())
        else:
            n_false = int(r0.size)
    out.update({"warning_episodes": int(r0.size), "false_episodes": n_false,
                "false_per_day": float(n_false / days)})
    return out


def chance_early_fraction(times, y, level, window_s, horizon_s=3600, merge_gap=6,
                          days=None, n_shifts=100, seed=0):
    """Early-warned share the SAME warning signal would reach with no link to the incidents.

    The level array is rotated by random amounts (keeping how much and how clustered the
    warnings are) and re-scored. Returns (mean, 95th percentile) of the early-warned fraction."""
    rng = np.random.default_rng(seed)
    level = np.asarray(level)
    n = len(level)
    lo, hi = max(1, n // 20), max(2, n - n // 20)
    vals = []
    for sh in rng.integers(lo, hi, n_shifts):
        e = evaluate(times, y, np.roll(level, int(sh)), window_s, horizon_s, merge_gap,
                     days=days, episodes=False)
        vals.append(e["early_fraction"] or 0.0)
    return float(np.mean(vals)), float(np.percentile(vals, 95))
