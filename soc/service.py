"""Business logic shared by the API, the CLI and the tests (no web framework in here)."""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
import secrets
from datetime import datetime, timezone

from . import contract
from .assets import load_assets
from .db import Database, OPEN_STATUSES, STATUSES, SEVERITY_ORDER
from .detection import CATEGORIES, DetectionConfig, RULES, iso, parse_ts
from .engine import build_alerts
from .explain import explain_alert
from .generator import SCENARIOS, generate

SOURCES = {"auth", "ehr", "endpoint", "network", "device", "directory"}
EVENT_RE = re.compile(r"^[a-z0-9_]{1,64}$")
LOG_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
PATIENT_RE = re.compile(r"^SIM-PT-\d{5}$")
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
MAX_EXPORT = 50000


class NotFound(LookupError):
    pass


def csv_safe(value):
    """Neutralise spreadsheet formula injection (=, +, -, @ at the start of a cell)."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True)
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def to_csv(rows, columns):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(columns)
    for r in rows:
        w.writerow([csv_safe(r.get(c)) for c in columns])
    return buf.getvalue()


def _text(raw, name, limit, required=False):
    v = raw.get(name)
    if v is None or v == "":
        if required:
            raise ValueError(f"{name} is required")
        return None
    if not isinstance(v, str):
        raise ValueError(f"{name} must be text")
    v = CTRL_RE.sub("", v)
    if len(v) > limit:
        raise ValueError(f"{name} is longer than {limit} characters")
    return v


def _ip(raw, name):
    v = _text(raw, name, 45)
    if v is None:
        return None
    try:
        return str(ipaddress.ip_address(v))
    except ValueError as exc:
        raise ValueError(f"{name} is not a valid IP address") from exc


def normalize_log(raw):
    """Validate one log. Only SIMULATED logs are accepted (hard safety rule of this build)."""
    if not isinstance(raw, dict):
        raise ValueError("log must be a JSON object")
    if raw.get("simulated") is not True:
        raise ValueError("only simulated logs are accepted (simulated must be true)")
    try:
        epoch = parse_ts(str(raw.get("timestamp")))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO 8601, e.g. 2026-10-16T09:30:00Z") from exc
    log_id = _text(raw, "log_id", 64, required=True)
    if not LOG_ID_RE.match(log_id):
        raise ValueError("log_id may contain letters, digits, '.', '_' and '-' only")
    source = _text(raw, "source", 20, required=True)
    if source not in SOURCES:
        raise ValueError(f"source must be one of {sorted(SOURCES)}")
    event = _text(raw, "event_type", 64, required=True)
    if not EVENT_RE.match(event):
        raise ValueError("event_type must be lowercase letters, digits and underscores")
    port = raw.get("dst_port")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535):
        raise ValueError("dst_port must be an integer 0..65535")
    outcome = _text(raw, "outcome", 10)
    if outcome not in (None, "success", "failure"):
        raise ValueError("outcome must be 'success' or 'failure'")
    details = raw.get("details") or {}
    if not isinstance(details, dict) or len(json.dumps(details)) > 8192:
        raise ValueError("details must be an object smaller than 8 KB")
    pid = details.get("patient_id")
    if pid is not None and not PATIENT_RE.match(str(pid)):
        raise ValueError("patient_id must look like SIM-PT-00123 (no real patient identifiers)")
    return {
        "log_id": log_id, "timestamp": iso(epoch), "_epoch": epoch, "source": source,
        "asset": _text(raw, "asset", 100, required=True), "event_type": event,
        "username": _text(raw, "username", 64), "src_ip": _ip(raw, "src_ip"), "dst_ip": _ip(raw, "dst_ip"),
        "dst_port": port, "outcome": outcome, "message": _text(raw, "message", 1000) or "",
        "details": details, "simulated": True, "sim_scenario": _text(raw, "sim_scenario", 40),
    }


def _time(value, name, end=False):
    """Parse an ISO date/time. A bare date means start of that day, or end of the day when end=True."""
    if value in (None, ""):
        return None
    try:
        return parse_ts(value if "T" in value else value + ("T23:59:59Z" if end else "T00:00:00Z"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO date/time such as 2026-10-16 or 2026-10-16T09:00:00Z") from exc


def _int(value, name, lo, hi, default):
    if value in (None, ""):
        return default
    try:
        v = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not lo <= v <= hi:
        raise ValueError(f"{name} must be between {lo} and {hi}")
    return v


def _short(value, name, limit=200):
    if value in (None, ""):
        return None
    value = str(value)
    if len(value) > limit:
        raise ValueError(f"{name} is longer than {limit} characters")
    return value


class SocService:
    def __init__(self, settings, assets=None, db=None, ai_post=None):
        self.settings = settings
        self.assets = assets if assets is not None else load_assets(settings.assets_path)
        self.db = db or Database(settings.db_path)
        self.ai_post = ai_post
        self.hash_key = hashlib.sha256(settings.analyst_token.encode() + b"|contract-export").digest()

    def cfg(self):
        return DetectionConfig(utc_offset_hours=self.settings.utc_offset_hours)

    # ------------------------------------------------------------------ logs & detection
    def ingest(self, raw_logs):
        clean, errors = [], []
        for i, raw in enumerate(raw_logs):
            try:
                clean.append(normalize_log(raw))
            except ValueError as exc:
                errors.append(f"log #{i + 1}: {exc}")
        if errors:
            raise ValueError("; ".join(errors[:5]) + (f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""))
        inserted = self.db.insert_logs(clean)
        return {"received": len(clean), "inserted": inserted, "duplicates_ignored": len(clean) - inserted}

    def run_detection(self, actor="system"):
        logs = self.db.all_logs_for_detection()
        drafts = build_alerts(logs, self.assets, self.cfg())
        created = updated = 0
        for d in drafts:
            existing = self.db.get_alert_by_key(d["dedup_key"])
            explanation = None
            if existing is None or (existing.get("explanation") or {}).get("source", "offline") == "offline":
                explanation = explain_alert(d, self.assets.get(d["asset"]), self.settings, use_ai=False)
            _, was_created = self.db.upsert_alert(d, explanation)
            created += was_created
            updated += (not was_created)
        self.db.set_meta("last_detection", iso(datetime.now(timezone.utc).timestamp()))
        self.db.audit(actor, "run_detection", f"{len(drafts)} alerts ({created} new, {updated} refreshed)")
        return {"logs_analysed": len(logs), "alerts_total": len(drafts), "created": created, "refreshed": updated}

    def simulate(self, seed=None, benign=300, scenarios=None, replace=True, actor="system"):
        if seed is None:
            seed = secrets.randbelow(99999) + 1
        if not isinstance(seed, int) or isinstance(seed, bool) or not 0 <= seed <= 2**31 - 1:
            raise ValueError("seed must be an integer between 0 and 2147483647")
        if not isinstance(benign, int) or isinstance(benign, bool) or not 0 <= benign <= 5000:
            raise ValueError("benign must be an integer between 0 and 5000")
        if scenarios is not None:
            if not isinstance(scenarios, list) or not all(isinstance(s, str) for s in scenarios):
                raise ValueError("scenarios must be a list of names")
            bad = [s for s in scenarios if s not in SCENARIOS]
            if bad:
                raise ValueError(f"unknown scenario(s) {bad}; valid: {sorted(SCENARIOS)}")
        if replace:
            self.db.reset_data()
        logs = generate(self.assets, seed=seed, benign=benign, scenarios=scenarios,
                        utc_offset_hours=self.settings.utc_offset_hours)
        ing = self.ingest(logs)
        det = self.run_detection(actor)
        self.db.set_meta("last_simulation", json.dumps({"seed": seed, "benign": benign,
                                                         "scenarios": scenarios or sorted(SCENARIOS)}))
        self.db.audit(actor, "simulate", f"seed={seed} benign={benign} replace={replace}")
        return {"seed": seed, "logs_inserted": ing["inserted"], **det}

    def reset(self, actor="system"):
        self.db.reset_data()
        self.db.audit(actor, "reset_data", "all logs, alerts and notes deleted")
        return {"ok": True}

    # ------------------------------------------------------------------ alerts
    def _alert_filters(self, p):
        f = {"q": _short(p.get("q"), "q"), "category": p.get("category") or None, "severity": p.get("severity") or None,
             "asset": _short(p.get("asset"), "asset", 100), "rule_id": _short(p.get("rule_id"), "rule_id", 20)}
        status = p.get("status") or None
        if status == "open":
            f["open_only"] = True
        elif status:
            if status not in STATUSES:
                raise ValueError(f"status must be one of {list(STATUSES) + ['open']}")
            f["status"] = status
        if f["category"] and f["category"] not in CATEGORIES:
            raise ValueError(f"category must be one of {sorted(CATEGORIES)}")
        if f["severity"] and f["severity"] not in SEVERITY_ORDER:
            raise ValueError(f"severity must be one of {list(SEVERITY_ORDER)}")
        f["min_score"] = _int(p.get("min_score"), "min_score", 1, 10, None)
        f["max_score"] = _int(p.get("max_score"), "max_score", 1, 10, None)
        f["start_epoch"], f["end_epoch"] = _time(p.get("start"), "start"), _time(p.get("end"), "end", end=True)
        return f

    def list_alerts(self, p):
        limit = _int(p.get("limit"), "limit", 1, self.settings.max_page_size, 50)
        offset = _int(p.get("offset"), "offset", 0, 10**9, 0)
        sort = p.get("sort") or "score_desc"
        if sort not in ("score_desc", "time_desc", "time_asc", "status"):
            raise ValueError("sort must be score_desc, time_desc, time_asc or status")
        items, total = self.db.query_alerts(self._alert_filters(p), sort, limit, offset)
        notes = self.db.note_counts()
        for it in items:
            it["notes"] = notes.get(it["id"], 0)
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    def alert_detail(self, alert_id):
        a = self.db.get_alert(alert_id)
        if not a:
            raise NotFound("alert not found")
        logs, _ = self.db.query_logs({"log_ids": a["log_ids"]}, limit=500, newest_first=False)
        return {"alert": a, "logs": logs, "notes": self.db.list_notes(alert_id),
                "asset": self.assets[a["asset"]].to_dict() if a["asset"] in self.assets else None}

    def set_status(self, alert_id, status, actor):
        if status not in STATUSES:
            raise ValueError(f"status must be one of {list(STATUSES)}")
        if not self.db.set_status(alert_id, status):
            raise NotFound("alert not found")
        self.db.audit(actor, "status_change", f"alert {alert_id} -> {status}")
        return {"id": alert_id, "status": status}

    def add_note(self, alert_id, text, actor):
        text = (text or "").strip()
        if not text:
            raise ValueError("note text must not be empty")
        if len(text) > 2000:
            raise ValueError("note text must be at most 2000 characters")
        note_id = self.db.add_note(alert_id, actor, CTRL_RE.sub("", text))
        if note_id is None:
            raise NotFound("alert not found")
        self.db.audit(actor, "add_note", f"alert {alert_id}")
        return {"id": note_id, "alert_id": alert_id}

    def explain(self, alert_id, actor, use_ai=True):
        a = self.db.get_alert(alert_id)
        if not a:
            raise NotFound("alert not found")
        exp = explain_alert(a, self.assets.get(a["asset"]), self.settings, use_ai=use_ai, post=self.ai_post)
        self.db.set_explanation(alert_id, exp)
        self.db.audit(actor, "explain", f"alert {alert_id} source={exp['source']}")
        return exp

    # ------------------------------------------------------------------ logs
    def _log_filters(self, p):
        f = {k: _short(p.get(k), k, 100) for k in ("source", "asset", "event_type", "username", "src_ip")}
        f["sim_scenario"] = _short(p.get("scenario"), "scenario", 40)
        f["q"] = _short(p.get("q"), "q")
        f["start_epoch"], f["end_epoch"] = _time(p.get("start"), "start"), _time(p.get("end"), "end", end=True)
        if p.get("alert_id") not in (None, ""):
            a = self.db.get_alert(_int(p.get("alert_id"), "alert_id", 1, 10**12, None))
            if not a:
                raise NotFound("alert not found")
            f["log_ids"] = a["log_ids"]
        return f

    def list_logs(self, p):
        limit = _int(p.get("limit"), "limit", 1, self.settings.max_page_size, 50)
        offset = _int(p.get("offset"), "offset", 0, 10**9, 0)
        items, total = self.db.query_logs(self._log_filters(p), limit, offset)
        return {"items": items, "total": total, "limit": limit, "offset": offset, "simulated": True}

    def filter_options(self):
        return {"sources": sorted(SOURCES), "event_types": self.db.distinct("event_type"),
                "assets": sorted(self.assets), "scenarios": sorted(SCENARIOS), "scenario_info": dict(SCENARIOS),
                "categories": [{"id": k, "name": v} for k, v in CATEGORIES.items()],
                "statuses": list(STATUSES), "severities": list(SEVERITY_ORDER),
                "rules": [{"id": k, "title": v["title"]} for k, v in RULES.items()]}

    # ------------------------------------------------------------------ exports
    LOG_COLUMNS = ["log_id", "timestamp", "source", "asset", "event_type", "username", "src_ip", "dst_ip", "dst_port",
                   "outcome", "message", "details", "simulated", "sim_scenario"]
    ALERT_COLUMNS = ["id", "rule_id", "category", "title", "severity", "score", "confidence", "status", "asset", "username",
                     "src_ip", "first_seen", "last_seen", "mitre", "evidence", "log_count"]

    def export_logs(self, p, fmt="csv"):
        items, _ = self.db.query_logs(self._log_filters(p), MAX_EXPORT, 0, newest_first=False)
        if fmt == "jsonl":
            return "\n".join(json.dumps({k: v for k, v in i.items() if k != "id"}, sort_keys=True) for i in items) + "\n"
        return to_csv(items, self.LOG_COLUMNS)

    def export_alerts(self, p):
        items, _ = self.db.query_alerts(self._alert_filters(p), "time_asc", MAX_EXPORT, 0)
        for it in items:
            it["evidence"] = " | ".join(it["evidence"])
        return to_csv(items, self.ALERT_COLUMNS)

    def export_contract(self):
        items, _ = self.db.query_alerts({}, "time_asc", MAX_EXPORT, 0)
        return to_csv(contract.contract_rows(items, self.assets, self.hash_key), contract.ALERT_COLUMNS)

    # ------------------------------------------------------------------ misc
    def stats(self):
        return self.db.stats()

    def assets_overview(self):
        alerts, _ = self.db.query_alerts({"open_only": True}, "score_desc", 5000, 0)
        agg = {}
        for a in alerts:
            s = agg.setdefault(a["asset"], {"open_alerts": 0, "max_score": 0})
            s["open_alerts"] += 1
            s["max_score"] = max(s["max_score"], a["score"])
        out = []
        for a in self.assets.values():
            d = a.to_dict()
            d.update(agg.get(a.asset, {"open_alerts": 0, "max_score": 0}))
            out.append(d)
        return sorted(out, key=lambda r: (-r["max_score"], -r["criticality"], r["asset"]))
