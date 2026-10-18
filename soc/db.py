"""SQLite storage layer (standard library only). All SQL uses bound parameters."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

STATUSES = ("new", "investigating", "contained", "resolved", "false_positive")
OPEN_STATUSES = ("new", "investigating", "contained")

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id TEXT UNIQUE NOT NULL,
    ts TEXT NOT NULL, ts_epoch REAL NOT NULL,
    source TEXT, asset TEXT, event_type TEXT, username TEXT,
    src_ip TEXT, dst_ip TEXT, dst_port INTEGER, outcome TEXT,
    message TEXT, sim_scenario TEXT, simulated INTEGER NOT NULL DEFAULT 1,
    raw TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_logs_asset ON logs(asset);
CREATE INDEX IF NOT EXISTS idx_logs_event ON logs(event_type);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key TEXT UNIQUE NOT NULL,
    rule_id TEXT NOT NULL, category TEXT NOT NULL, title TEXT NOT NULL,
    severity TEXT NOT NULL, rule_severity TEXT, score INTEGER NOT NULL, confidence REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    asset TEXT, username TEXT, src_ip TEXT,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, first_epoch REAL NOT NULL, last_epoch REAL NOT NULL,
    log_ids TEXT NOT NULL, evidence TEXT NOT NULL, breakdown TEXT NOT NULL, facts TEXT NOT NULL,
    explanation TEXT, mitre TEXT, impact TEXT, related TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(score);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    author TEXT NOT NULL, text TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

ALERT_SORT = {
    "score_desc": "score DESC, first_epoch DESC",
    "time_desc": "first_epoch DESC",
    "time_asc": "first_epoch ASC",
    "status": "CASE status WHEN 'new' THEN 0 WHEN 'investigating' THEN 1 WHEN 'contained' THEN 2 "
              "WHEN 'resolved' THEN 3 ELSE 4 END, score DESC",
}
SEVERITY_ORDER = ("critical", "high", "medium", "low")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def like(text):
    """LIKE pattern matching `text` literally anywhere (use with ESCAPE '\\')."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _j(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


class Database:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.conn() as c:
            try:
                c.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass  # some filesystems do not support WAL; the default journal is fine
            c.executescript(SCHEMA)

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    # ------------------------------------------------------------------ meta / audit
    def set_meta(self, key, value):
        with self.conn() as c:
            c.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                      (key, str(value)))

    def get_meta(self, key, default=None):
        with self.conn() as c:
            r = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default

    def audit(self, actor, action, detail=""):
        with self.conn() as c:
            c.execute("INSERT INTO audit_log(ts,actor,action,detail) VALUES(?,?,?,?)",
                      (now_iso(), actor, action, str(detail)[:500]))

    def list_audit(self, limit=100, offset=0):
        with self.conn() as c:
            total = c.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            rows = c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return {"items": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}

    # ------------------------------------------------------------------ logs
    def insert_logs(self, logs):
        """Insert normalized logs, ignoring duplicates (by log_id). Returns number inserted."""
        rows = [(l["log_id"], l["timestamp"], l["_epoch"], l["source"], l["asset"], l["event_type"], l.get("username"),
                 l.get("src_ip"), l.get("dst_ip"), l.get("dst_port"), l.get("outcome"), l.get("message", ""),
                 l.get("sim_scenario"), 1, _j({k: v for k, v in l.items() if k != "_epoch"})) for l in logs]
        with self.conn() as c:
            before = c.total_changes
            c.executemany("INSERT OR IGNORE INTO logs(log_id,ts,ts_epoch,source,asset,event_type,username,src_ip,dst_ip,"
                          "dst_port,outcome,message,sim_scenario,simulated,raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            return c.total_changes - before

    @staticmethod
    def _log_where(f):
        where, args = [], []
        for col in ("source", "asset", "event_type", "username", "src_ip", "sim_scenario"):
            if f.get(col):
                where.append(f"{col}=?")
                args.append(f[col])
        if f.get("q"):
            where.append("raw LIKE ? ESCAPE '\\'")
            args.append(like(f["q"]))
        if f.get("start_epoch") is not None:
            where.append("ts_epoch>=?")
            args.append(f["start_epoch"])
        if f.get("end_epoch") is not None:
            where.append("ts_epoch<=?")
            args.append(f["end_epoch"])
        if f.get("log_ids") is not None:
            ids = list(f["log_ids"])[:500]
            where.append("log_id IN (%s)" % ",".join("?" * len(ids)) if ids else "1=0")
            args.extend(ids)
        return (" WHERE " + " AND ".join(where)) if where else "", args

    def query_logs(self, f, limit=50, offset=0, newest_first=True):
        w, args = self._log_where(f)
        order = "DESC" if newest_first else "ASC"
        with self.conn() as c:
            total = c.execute("SELECT COUNT(*) FROM logs" + w, args).fetchone()[0]
            rows = c.execute(f"SELECT id, raw FROM logs{w} ORDER BY ts_epoch {order}, id {order} LIMIT ? OFFSET ?",
                             args + [limit, offset]).fetchall()
        return [self._log_row(r) for r in rows], total

    def all_logs_for_detection(self, limit=200000):
        with self.conn() as c:
            rows = c.execute("SELECT id, raw FROM logs ORDER BY ts_epoch, id LIMIT ?", (limit,)).fetchall()
        return [self._log_row(r) for r in rows]

    @staticmethod
    def _log_row(r):
        d = json.loads(r["raw"])
        d["id"] = r["id"]
        return d

    def count_logs(self):
        with self.conn() as c:
            return c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]

    def distinct(self, column):
        if column not in ("source", "asset", "event_type", "sim_scenario"):
            raise ValueError("unsupported column")
        with self.conn() as c:
            return [r[0] for r in c.execute(f"SELECT DISTINCT {column} FROM logs WHERE {column} IS NOT NULL ORDER BY 1")]

    # ------------------------------------------------------------------ alerts
    def get_alert_by_key(self, key):
        with self.conn() as c:
            r = c.execute("SELECT * FROM alerts WHERE dedup_key=?", (key,)).fetchone()
        return self._alert_row(r, full=True) if r else None

    def upsert_alert(self, d, explanation=None):
        """Insert a new alert or refresh an existing one (status and notes are never touched).
        `explanation` is stored only when given. Returns (id, created)."""
        now = now_iso()
        with self.conn() as c:
            existing = c.execute("SELECT id FROM alerts WHERE dedup_key=?", (d["dedup_key"],)).fetchone()
            if existing:
                c.execute("""UPDATE alerts SET severity=?, rule_severity=?, score=?, confidence=?, last_seen=?, last_epoch=?,
                             log_ids=?, evidence=?, breakdown=?, facts=?, related=?, updated_at=? WHERE id=?""",
                          (d["severity"], d["rule_severity"], d["score"], d["confidence"], d["last_seen"], d["last_epoch"],
                           _j(d["log_ids"]), _j(d["evidence"]), _j(d["breakdown"]), _j(d["facts"]), _j(d["related"]),
                           now, existing["id"]))
                if explanation is not None:
                    c.execute("UPDATE alerts SET explanation=? WHERE id=?", (_j(explanation), existing["id"]))
                return existing["id"], False
            cur = c.execute(
                """INSERT INTO alerts(dedup_key,rule_id,category,title,severity,rule_severity,score,confidence,status,asset,
                   username,src_ip,first_seen,last_seen,first_epoch,last_epoch,log_ids,evidence,breakdown,facts,explanation,
                   mitre,impact,related,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'new',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (d["dedup_key"], d["rule_id"], d["category"], d["title"], d["severity"], d["rule_severity"], d["score"],
                 d["confidence"], d["asset"], d["username"], d["src_ip"], d["first_seen"], d["last_seen"],
                 d["first_epoch"], d["last_epoch"], _j(d["log_ids"]), _j(d["evidence"]), _j(d["breakdown"]),
                 _j(d["facts"]), _j(explanation) if explanation is not None else None, d["mitre"], _j(d["impact"]),
                 _j(d["related"]), now, now))
            return cur.lastrowid, True

    @staticmethod
    def _alert_row(r, full=False):
        d = dict(r)
        for k in ("evidence", "breakdown", "facts", "explanation", "impact", "related", "log_ids"):
            d[k] = json.loads(d[k]) if d.get(k) else ([] if k != "facts" and k != "explanation" else ({} if k == "facts" else None))
        d["log_count"] = d["facts"].get("log_count", len(d["log_ids"]))
        d["confidence_label"] = "High" if d["confidence"] >= 0.85 else "Medium" if d["confidence"] >= 0.65 else "Low"
        if not full:
            d.pop("log_ids", None)
            d.pop("breakdown", None)
            d.pop("explanation", None)
        return d

    @staticmethod
    def _alert_where(f):
        where, args = [], []
        if f.get("status"):
            where.append("status=?"); args.append(f["status"])
        if f.get("open_only"):
            where.append("status IN (%s)" % ",".join("?" * len(OPEN_STATUSES))); args.extend(OPEN_STATUSES)
        for col in ("category", "severity", "asset", "rule_id"):
            if f.get(col):
                where.append(f"{col}=?"); args.append(f[col])
        if f.get("min_score") is not None:
            where.append("score>=?"); args.append(f["min_score"])
        if f.get("max_score") is not None:
            where.append("score<=?"); args.append(f["max_score"])
        if f.get("start_epoch") is not None:
            where.append("last_epoch>=?"); args.append(f["start_epoch"])
        if f.get("end_epoch") is not None:
            where.append("first_epoch<=?"); args.append(f["end_epoch"])
        if f.get("q"):
            p = like(f["q"])
            where.append("(title LIKE ? ESCAPE '\\' OR asset LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\' OR "
                         "src_ip LIKE ? ESCAPE '\\' OR rule_id LIKE ? ESCAPE '\\' OR category LIKE ? ESCAPE '\\' OR "
                         "evidence LIKE ? ESCAPE '\\')")
            args.extend([p] * 7)
        return (" WHERE " + " AND ".join(where)) if where else "", args

    def query_alerts(self, f, sort="score_desc", limit=50, offset=0):
        order = ALERT_SORT.get(sort, ALERT_SORT["score_desc"])
        w, args = self._alert_where(f)
        with self.conn() as c:
            total = c.execute("SELECT COUNT(*) FROM alerts" + w, args).fetchone()[0]
            rows = c.execute(f"SELECT * FROM alerts{w} ORDER BY {order}, id DESC LIMIT ? OFFSET ?",
                             args + [limit, offset]).fetchall()
        return [self._alert_row(r) for r in rows], total

    def get_alert(self, alert_id):
        with self.conn() as c:
            r = c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return self._alert_row(r, full=True) if r else None

    def set_status(self, alert_id, status):
        with self.conn() as c:
            cur = c.execute("UPDATE alerts SET status=?, updated_at=? WHERE id=?", (status, now_iso(), alert_id))
            return cur.rowcount > 0

    def set_explanation(self, alert_id, explanation):
        with self.conn() as c:
            c.execute("UPDATE alerts SET explanation=?, updated_at=? WHERE id=?", (_j(explanation), now_iso(), alert_id))

    def add_note(self, alert_id, author, text):
        with self.conn() as c:
            if not c.execute("SELECT 1 FROM alerts WHERE id=?", (alert_id,)).fetchone():
                return None
            cur = c.execute("INSERT INTO notes(alert_id,author,text,created_at) VALUES(?,?,?,?)",
                            (alert_id, author, text, now_iso()))
            c.execute("UPDATE alerts SET updated_at=? WHERE id=?", (now_iso(), alert_id))
            return cur.lastrowid

    def list_notes(self, alert_id):
        with self.conn() as c:
            rows = c.execute("SELECT * FROM notes WHERE alert_id=? ORDER BY id", (alert_id,)).fetchall()
        return [dict(r) for r in rows]

    def note_counts(self):
        with self.conn() as c:
            return {r[0]: r[1] for r in c.execute("SELECT alert_id, COUNT(*) FROM notes GROUP BY alert_id")}

    def reset_data(self):
        with self.conn() as c:
            c.execute("DELETE FROM notes")
            c.execute("DELETE FROM alerts")
            c.execute("DELETE FROM logs")
            c.execute("DELETE FROM meta WHERE key IN ('last_detection','last_simulation')")

    # ------------------------------------------------------------------ stats
    def stats(self):
        with self.conn() as c:
            q = lambda sql, a=(): c.execute(sql, a).fetchall()
            opens = ",".join("?" * len(OPEN_STATUSES))
            by_status = {r[0]: r[1] for r in q("SELECT status, COUNT(*) FROM alerts GROUP BY status")}
            by_sev = {r[0]: r[1] for r in q("SELECT severity, COUNT(*) FROM alerts WHERE status IN (%s) GROUP BY severity" % opens, OPEN_STATUSES)}
            by_cat = {r[0]: r[1] for r in q("SELECT category, COUNT(*) FROM alerts WHERE status IN (%s) GROUP BY category" % opens, OPEN_STATUSES)}
            open_n = c.execute("SELECT COUNT(*), AVG(score) FROM alerts WHERE status IN (%s)" % opens, OPEN_STATUSES).fetchone()
            top = q("SELECT asset, COUNT(*) AS n, MAX(score) AS top FROM alerts WHERE status IN (%s) "
                    "GROUP BY asset ORDER BY top DESC, n DESC LIMIT 8" % opens, OPEN_STATUSES)
            tl_logs = {r[0]: r[1] for r in q("SELECT substr(ts,1,13) AS h, COUNT(*) FROM logs GROUP BY h")}
            tl_alerts = {r[0]: r[1] for r in q("SELECT substr(first_seen,1,13) AS h, COUNT(*) FROM alerts GROUP BY h")}
            logs_total = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
            alerts_total = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        hours = sorted(set(tl_logs) | set(tl_alerts))[-72:]
        return {
            "simulated": True,
            "logs_total": logs_total, "alerts_total": alerts_total,
            "open_alerts": open_n[0], "avg_open_score": round(open_n[1], 1) if open_n[1] is not None else None,
            "critical_open": by_sev.get("critical", 0),
            "by_status": by_status, "by_severity_open": by_sev, "by_category_open": by_cat,
            "top_assets": [{"asset": r["asset"], "alerts": r["n"], "max_score": r["top"]} for r in top],
            "timeline": [{"hour": h + ":00:00Z", "logs": tl_logs.get(h, 0), "alerts": tl_alerts.get(h, 0)} for h in hours],
            "last_detection": self.get_meta("last_detection"), "last_simulation": self.get_meta("last_simulation"),
        }
