"""Explainable 1-10 risk score.

score = severity (0-4) + evidence strength (0-1.5) + corroboration (0-1.5)
        + asset criticality (0-1.5) + hospital impact (0-1.5)      -> rounded, clamped to 1..10

Every component is returned with its points and a plain-English reason so analysts can see
exactly why an alert scored what it did. Fully deterministic.
"""
from __future__ import annotations

from .assets import Asset

SEVERITY_POINTS = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}
IMPACT_LABELS = {
    "patient_safety": "possible risk to patient safety",
    "phi": "possible exposure of patient information",
    "downtime": "possible disruption to clinical operations",
    "integrity": "possible loss of system integrity",
    "access": "possible unauthorised access",
}
FALLBACK_ASSET = Asset(asset="Unknown asset", criticality=3)


def clamp(x, lo, hi):
    return max(lo, min(hi, x))


def severity_label(score: int) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def confidence_label(conf: float) -> str:
    if conf >= 0.85:
        return "High"
    if conf >= 0.65:
        return "Medium"
    return "Low"


def impact_points(tags, asset: Asset):
    """Worst-case impact among the rule's impact tags (not summed)."""
    table = {
        "patient_safety": 1.5 if asset.patient_care else 0.75,
        "phi": 1.5 if asset.holds_phi else 0.75,
        "downtime": 1.0 if asset.patient_care else 0.5,
        "integrity": 1.0,
        "access": 0.5,
    }
    best_tag, best = None, 0.0
    for t in tags:
        if table.get(t, 0) > best:
            best_tag, best = t, table[t]
    return best_tag, best


def score_finding(finding, asset, related_rules):
    asset = asset or FALLBACK_ASSET
    sev = finding.effective_severity
    p_sev = SEVERITY_POINTS[sev]
    p_evi = round(1.5 * clamp((finding.confidence - 0.5) / 0.45, 0, 1), 2)
    p_cor = min(1.5, 0.75 * len(related_rules))
    p_crit = round((asset.criticality - 1) * 0.375, 3)
    tag, p_imp = impact_points(finding.meta["impact"], asset)

    breakdown = [
        {"factor": "Rule severity", "points": p_sev, "max": 4.0,
         "detail": f"{sev.capitalize()}-severity rule {finding.rule_id}: {finding.title}"},
        {"factor": "Evidence strength", "points": p_evi, "max": 1.5,
         "detail": f"Detection confidence {round(finding.confidence * 100)}% "
                   f"({confidence_label(finding.confidence)}) based on how far the logs exceed the rule threshold"},
        {"factor": "Corroborating activity", "points": p_cor, "max": 1.5,
         "detail": ("Other rules fired on the same asset, user or source nearby in time: "
                    + ", ".join(sorted(related_rules))) if related_rules else "No other detections linked to this one"},
        {"factor": "Asset criticality", "points": p_crit, "max": 1.5,
         "detail": f"{asset.asset} is criticality {asset.criticality}/5"
                   + (" (patient-care system)" if asset.patient_care else "")},
        {"factor": "Hospital impact", "points": p_imp, "max": 1.5,
         "detail": (f"Worst case on this asset: {IMPACT_LABELS[tag]}" if tag else "No impact flags for this rule")},
    ]
    total = round(sum(b["points"] for b in breakdown), 3)
    score = int(clamp(int(total + 0.5), 1, 10))
    return {"score": score, "total": total, "breakdown": breakdown, "label": severity_label(score)}
