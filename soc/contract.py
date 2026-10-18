"""Export alerts in the hackathon team's shared 9-column contract (shared/CONTRACT.md).

The team contract uses risk_score 0..1, a fused network/anomaly/threat-intel input, and fixed
action texts. This SOC scores 1..10, so the mapping is indicative:
    risk_score    = score / 10
    network_score = detection confidence for network-based rules (BF-*, MAL-003, DEV-*), else 0
    anomaly_score = detection confidence for host/behaviour rules (everything else), else 0
    threat_flag   = 1 when a threat-intel indicator matched
Thresholds and action texts are copied from shared/schema.py.
"""
from __future__ import annotations

import hashlib
import hmac

ALERT_COLUMNS = ["timestamp", "asset", "criticality", "src_ip_hashed", "network_score", "anomaly_score",
                 "threat_flag", "risk_score", "recommended_action"]
ACTION_ISOLATE = "Isolate affected subnet; keep clinical systems running; escalate to on-call."
ACTION_BLOCK = "Block source and alert the analyst."
ACTION_MONITOR = "Monitor and log."
NETWORK_RULES = ("BF-", "DEV-", "MAL-003")


def recommended_action(risk: float) -> str:
    if risk >= 0.80:
        return ACTION_ISOLATE
    if risk >= 0.50:
        return ACTION_BLOCK
    return ACTION_MONITOR


def hash_value(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:12]


def contract_rows(alerts, assets, key: bytes):
    rows = []
    for a in alerts:
        is_net = a["rule_id"].startswith(NETWORK_RULES)
        asset = assets.get(a["asset"])
        risk = round(a["score"] / 10, 3)
        rows.append({
            "timestamp": a["first_seen"], "asset": a["asset"], "criticality": asset.criticality if asset else 3,
            "src_ip_hashed": hash_value(key, a.get("src_ip") or a.get("username") or a["asset"]),
            "network_score": round(a["confidence"], 3) if is_net else 0.0,
            "anomaly_score": 0.0 if is_net else round(a["confidence"], 3),
            "threat_flag": 1 if (a.get("facts", {}).get("ioc") == "yes" or a["rule_id"] == "MAL-003") else 0,
            "risk_score": risk, "recommended_action": recommended_action(risk),
        })
    return rows
