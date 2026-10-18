"""Network evidence for SOC alerts: trained flow model scores replayed UNSW-NB15 flows.

HONEST LABEL: the SOC simulator writes event logs, not packet captures, so there are no real flow
records for an alert. To let Hanan's model contribute a genuine `network_score`, each
network-type alert (brute force, medical-device traffic, C2) is paired with a "sensor capture":
a small sample of labelled ATTACK flows drawn from the held-out UNSW-NB15 test split. The
network_score is the MEDIAN model probability over those flows, so it reflects what the trained
model really does on real attack traffic, including its misses (e.g. Fuzzers, ~46% recall).
It is a replay for the demo, not live capture; the model's measured accuracy on random real flows is
reported separately (notebook cell 5).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import network_score as ns

NETWORK_RULES = ("BF-", "DEV-", "MAL-003")        # same rules contract.py treats as network-based


def is_network_alert(rule_id: str) -> bool:
    return rule_id.startswith(NETWORK_RULES)


class FlowReplay:
    def __init__(self, n_flows: int = 15, seed: int = 7, csv_path: str = ns.TEST_CSV):
        self.n_flows, self.seed = n_flows, seed
        df = pd.read_csv(csv_path)
        self.attacks = df[df["label_binary"] == 1].reset_index(drop=True)
        self.backend = ns._load().get("backend", "snapml")
        self.threshold = ns._load()["threshold"]

    def score_alert(self, alert_id: int) -> dict:
        rng = np.random.default_rng([self.seed, int(alert_id)])
        flows = self.attacks.iloc[rng.choice(len(self.attacks), self.n_flows, replace=False)]
        p = ns.score_batch(flows)
        return {"score": round(float(np.median(p)), 3), "flows": self.n_flows,
                "share_flagged": round(float((p >= self.threshold).mean()), 2), "backend": self.backend}
