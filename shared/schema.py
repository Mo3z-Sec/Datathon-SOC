"""CyberShield AI — shared schema/contract helpers.

Import this anywhere to guarantee identical column names across the team.

    from shared.schema import ALERT_COLUMNS, validate_alert_row, compute_risk_score
"""
from __future__ import annotations

ALERT_COLUMNS = [
    "timestamp",
    "asset",
    "criticality",
    "src_ip_hashed",
    "network_score",
    "anomaly_score",
    "threat_flag",
    "risk_score",
    "recommended_action",
]

SCORE_COLUMNS = ["network_score", "anomaly_score", "risk_score"]

ACTION_ISOLATE = "Isolate affected subnet; keep clinical systems running; escalate to on-call."
ACTION_BLOCK = "Block source and alert the analyst."
ACTION_MONITOR = "Monitor and log."

RISK_FUSION = {"network_score": 0.6, "anomaly_score": 0.3, "threat_flag": 0.1}


def _clamp01(x: float) -> float:
    try:
        x = float(x)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, x))


def criticality_weight(criticality: int) -> float:
    """Map criticality 1..5 to a multiplier 0.8..1.2."""
    try:
        c = int(criticality)
    except (TypeError, ValueError):
        c = 1
    c = max(1, min(5, c))
    return round(0.7 + 0.1 * c, 3)


def compute_risk_score(
    network_score: float,
    anomaly_score: float,
    threat_flag: int,
    criticality: int,
) -> float:
    """Fuse model outputs + threat intel, weighted by asset criticality."""
    base = (
        RISK_FUSION["network_score"] * _clamp01(network_score)
        + RISK_FUSION["anomaly_score"] * _clamp01(anomaly_score)
        + RISK_FUSION["threat_flag"] * (1.0 if int(threat_flag) else 0.0)
    )
    return min(1.0, round(base * criticality_weight(criticality), 3))


def recommended_action(risk_score: float) -> str:
    if risk_score >= 0.80:
        return ACTION_ISOLATE
    if risk_score >= 0.50:
        return ACTION_BLOCK
    return ACTION_MONITOR


def validate_alert_row(row: dict) -> list[str]:
    """Return a list of problems; empty list == the row is contract-compliant."""
    problems: list[str] = []
    for col in ALERT_COLUMNS:
        if col not in row:
            problems.append(f"missing column: {col}")
    if problems:
        return problems

    for col in SCORE_COLUMNS:
        try:
            v = float(row[col])
        except (TypeError, ValueError):
            problems.append(f"{col} is not numeric: {row[col]!r}")
            continue
        if not (0.0 <= v <= 1.0):
            problems.append(f"{col} out of range 0..1: {v}")

    try:
        crit = int(row["criticality"])
        if not (1 <= crit <= 5):
            problems.append(f"criticality out of range 1..5: {crit}")
    except (TypeError, ValueError):
        problems.append(f"criticality not an int: {row['criticality']!r}")

    try:
        flag = int(row["threat_flag"])
        if flag not in (0, 1):
            problems.append(f"threat_flag must be 0 or 1: {flag}")
    except (TypeError, ValueError):
        problems.append(f"threat_flag not an int: {row['threat_flag']!r}")

    return problems


if __name__ == "__main__":
    demo = {
        "timestamp": "2026-10-17T04:05:00Z",
        "asset": "EHR Server",
        "criticality": 5,
        "src_ip_hashed": "a1b2c3d4e5f6",
        "network_score": 0.93,
        "anomaly_score": 0.41,
        "threat_flag": 1,
        "risk_score": compute_risk_score(0.93, 0.41, 1, 5),
        "recommended_action": recommended_action(compute_risk_score(0.93, 0.41, 1, 5)),
    }
    print("risk_score =", demo["risk_score"])
    print("action     =", demo["recommended_action"])
    print("problems   =", validate_alert_row(demo))
