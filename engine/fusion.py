"""Risk fusion + contract export (Jason's engine). The only place that writes risk_score.

Inputs per alert
  rule_risk       = alert score / 10. The rule engine's explainable score ALREADY includes severity,
                    evidence, corroboration, asset criticality and hospital impact (soc/scoring.py),
                    so it is NOT multiplied by the criticality weight again.
  network_score   = Hanan's flow model on replayed flows (network-type alerts only, else 0.0)
  anomaly_score   = Bardia's log model on the alert's log windows
  threat_flag     = threat intel / IOC match

Fusion
  model_risk = contract formula  0.6*network + 0.3*anomaly + 0.1*threat, x criticality weight
               (shared.schema.compute_risk_score, unchanged)
  risk_score = rule_risk + min(max(model_risk - rule_risk, 0), MAX_ML_LIFT)

Why not the plain contract blend: it assumes all three detectors observed the event. A ransomware
alert is seen by the log model only, so blending it with an empty network score capped it at ~0.3
and recommended "Monitor and log" for a 10/10 incident.
Why this instead: ML evidence can LIFT an alert (by at most MAX_ML_LIFT = 0.10, i.e. one rule-score
point) when the models corroborate the rules, but can never DEMOTE what the rules found, and can
never on its own jump an alert several response bands. That cap matters because the network_score
here comes from replayed attack flows (see models/network_evidence.py), which are ~1.0 by
construction; response (isolate / block) must stay driven by the explainable rule score.
`risk_basis` records which side decided. Thresholds/actions are shared.schema.recommended_action.
"""
from __future__ import annotations

import pandas as pd

from shared.schema import ALERT_COLUMNS, compute_risk_score, recommended_action, validate_alert_row
from soc import contract

MAX_ML_LIFT = 0.10

EXTRA_COLUMNS = ["alert_id", "rule_id", "rule_risk", "model_risk", "risk_basis",
                 "network_source", "anomaly_level", "anomaly_why"]


def threat_flag_for(alert: dict, is_known_bad=None) -> int:
    f = alert.get("facts", {}) or {}
    if f.get("ioc") == "yes" or alert["rule_id"] == "MAL-003":
        return 1
    if is_known_bad is not None:
        for k in ("url", "domain", "dst_ip", "src_ip"):
            if f.get(k) and is_known_bad(f.get(k)):
                return 1
    return 0


def fuse_risk(rule_risk, network_score, anomaly_score, threat_flag, criticality):
    model_risk = compute_risk_score(network_score, anomaly_score, threat_flag, criticality)
    lift = min(max(model_risk - rule_risk, 0.0), MAX_ML_LIFT)
    if lift > 0:
        return round(rule_risk + lift, 3), model_risk, "rule + model lift"
    return rule_risk, model_risk, "rule"


def build_alert_table(alerts, assets, hash_key, *, anomaly=None, flow_replay=None, is_known_bad=None):
    """One contract row per alert (+ provenance columns). Missing components degrade to 0.0.

    anomaly:     models.log_anomaly.SocAnomalyScorer (already fit_logs()'d) or None
    flow_replay: models.network_evidence.FlowReplay or None
    """
    from models.network_evidence import is_network_alert

    base_rows = contract.contract_rows(alerts, assets, hash_key)
    out = []
    for a, row in zip(alerts, base_rows):
        row = dict(row)
        net_src = "none"
        row["network_score"] = 0.0
        if is_network_alert(a["rule_id"]):
            if flow_replay is not None:
                r = flow_replay.score_alert(a["id"])
                row["network_score"], net_src = r["score"], f"model:{r['backend']}"
            else:
                row["network_score"], net_src = round(a["confidence"], 3), "rule-confidence (model unavailable)"
        an = anomaly.score_alert(a) if anomaly is not None else {"score": 0.0, "level": "n/a", "top_events": []}
        row["anomaly_score"] = round(an["score"], 3)
        row["threat_flag"] = threat_flag_for(a, is_known_bad)
        rule_risk = round(a["score"] / 10, 3)
        risk, model_risk, basis = fuse_risk(rule_risk, row["network_score"], row["anomaly_score"],
                                            row["threat_flag"], row["criticality"])
        row["risk_score"], row["recommended_action"] = risk, recommended_action(risk)
        row.update(alert_id=a["id"], rule_id=a["rule_id"], rule_risk=rule_risk, model_risk=model_risk,
                   risk_basis=basis, network_source=net_src, anomaly_level=an["level"],
                   anomaly_why=", ".join(t["event"] for t in an["top_events"][:2]))
        out.append(row)
    df = pd.DataFrame(out)
    problems = [p for r in out for p in validate_alert_row(r)]
    return df[ALERT_COLUMNS + EXTRA_COLUMNS], problems


def write_contract_csv(df: pd.DataFrame, path) -> None:
    """Exactly the 9 contract columns, in contract order."""
    df[ALERT_COLUMNS].to_csv(path, index=False)
