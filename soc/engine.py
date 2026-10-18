"""Turns detection findings into scored alert drafts (correlation + scoring)."""
from __future__ import annotations

from .detection import RULES, CATEGORIES, DetectionConfig, iso, run_rules
from .scoring import confidence_label, score_finding

CORRELATION_WINDOW = 3600  # seconds
MAX_LOG_IDS = 300


def _linked(a, b):
    same_asset = a.asset == b.asset
    same_user = a.username and a.username == b.username
    same_ip = a.src_ip and a.src_ip == b.src_ip
    if not (same_asset or same_user or same_ip):
        return False
    return b.first_ts <= a.last_ts + CORRELATION_WINDOW and b.last_ts >= a.first_ts - CORRELATION_WINDOW


def correlate(findings):
    """Map index -> list of other findings (different rule) linked by asset/user/IP and time."""
    out = {}
    for i, a in enumerate(findings):
        out[i] = [b for j, b in enumerate(findings) if i != j and a.rule_id != b.rule_id and _linked(a, b)]
    return out


def dedup_key(f):
    return "|".join([f.rule_id, f.asset, f.username or "-", f.src_ip or "-", iso(f.first_ts)])


def build_alerts(logs, assets, cfg=None):
    """Return a list of alert draft dicts (no explanation yet), highest score first."""
    cfg = cfg or DetectionConfig()
    findings = run_rules(logs, assets, cfg)
    related = correlate(findings)
    drafts = []
    for i, f in enumerate(findings):
        rel_rules = sorted({g.rule_id for g in related[i]})
        res = score_finding(f, assets.get(f.asset), rel_rules)
        log_ids = f.log_ids
        facts = dict(f.facts)
        facts["log_count"] = len(log_ids)
        drafts.append({
            "dedup_key": dedup_key(f), "rule_id": f.rule_id, "category": f.category,
            "category_name": CATEGORIES[f.category], "title": f.title,
            "severity": res["label"], "rule_severity": f.effective_severity,
            "score": res["score"], "score_total": res["total"], "breakdown": res["breakdown"],
            "confidence": f.confidence, "confidence_label": confidence_label(f.confidence),
            "asset": f.asset, "username": f.username, "src_ip": f.src_ip,
            "first_seen": iso(f.first_ts), "last_seen": iso(f.last_ts),
            "first_epoch": f.first_ts, "last_epoch": f.last_ts,
            "log_ids": log_ids[:MAX_LOG_IDS], "evidence": f.evidence, "facts": facts,
            "mitre": f.meta["mitre"], "impact": f.meta["impact"],
            "related": [{"rule_id": r, "title": RULES[r]["title"]} for r in rel_rules],
        })
    drafts.sort(key=lambda d: (-d["score"], d["first_epoch"]))
    return drafts
