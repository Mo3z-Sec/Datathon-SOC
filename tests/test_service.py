import csv
import io
import json
import sqlite3
import unittest

from soc.service import NotFound, normalize_log
from soc.generator import generate
from helpers import DAY, TempDirMixin, make_service, mklog


class NormalizeTests(unittest.TestCase):
    def good(self, **kw):
        log = mklog(0, "login_failure", username="sim.u1", src_ip="10.0.0.1", outcome="failure")
        log.update(kw)
        return log

    def test_accepts_valid_log(self):
        out = normalize_log(self.good())
        self.assertTrue(out["simulated"] and out["_epoch"] > 0)

    def test_rejects_non_simulated_or_missing_flag(self):
        for bad in (self.good(simulated=False), {k: v for k, v in self.good().items() if k != "simulated"}):
            with self.assertRaises(ValueError):
                normalize_log(bad)

    def test_rejects_bad_fields(self):
        for kw in ({"src_ip": "999.1.1.1"}, {"dst_port": 70000}, {"dst_port": True}, {"timestamp": "yesterday"},
                   {"source": "toaster"}, {"event_type": "Bad Type!"}, {"outcome": "maybe"}, {"log_id": "has space"},
                   {"details": {"patient_id": "John Smith"}}, {"details": {"x": "y" * 9000}}, {"asset": ""}, {"username": "u" * 65}):
            with self.assertRaises(ValueError, msg=str(kw)):
                normalize_log(self.good(**kw))
        with self.assertRaises(ValueError):
            normalize_log("not a dict")

    def test_control_characters_are_stripped(self):
        self.assertEqual(normalize_log(self.good(message="a\x00b\x07c"))["message"], "abc")


class ServiceTests(TempDirMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.svc = make_service(self.tmp)
        self.svc.ingest(generate(self.svc.assets, seed=42, day=DAY))
        self.svc.run_detection("test")

    def test_ingest_is_idempotent(self):
        before = self.svc.db.count_logs()
        r = self.svc.ingest(generate(self.svc.assets, seed=42, day=DAY))
        self.assertEqual((r["inserted"], self.svc.db.count_logs()), (0, before))

    def test_ingest_rejects_whole_batch_on_any_bad_log(self):
        with self.assertRaises(ValueError):
            self.svc.ingest([mklog(0, "login_failure"), {"timestamp": "bad"}])

    def test_detection_is_idempotent_and_keeps_analyst_work(self):
        first = self.svc.list_alerts({"limit": "1"})["items"][0]
        self.svc.set_status(first["id"], "investigating", "analyst")
        self.svc.add_note(first["id"], "looking into it", "analyst")
        r = self.svc.run_detection("test")
        self.assertEqual((r["created"], r["refreshed"], r["alerts_total"]), (0, 20, 20))
        d = self.svc.alert_detail(first["id"])
        self.assertEqual(d["alert"]["status"], "investigating")
        self.assertEqual(len(d["notes"]), 1)
        self.assertEqual(self.svc.list_alerts({})["total"], 20)

    def test_status_update_validation_and_not_found(self):
        a = self.svc.list_alerts({"limit": "1"})["items"][0]["id"]
        for st in ("resolved", "false_positive", "contained", "investigating", "new"):
            self.assertEqual(self.svc.set_status(a, st, "analyst")["status"], st)
        with self.assertRaises(ValueError):
            self.svc.set_status(a, "deleted", "analyst")
        with self.assertRaises(NotFound):
            self.svc.set_status(9999, "resolved", "analyst")

    def test_notes_validation(self):
        a = self.svc.list_alerts({"limit": "1"})["items"][0]["id"]
        for bad in ("", "   ", "x" * 2001):
            with self.assertRaises(ValueError):
                self.svc.add_note(a, bad, "analyst")
        with self.assertRaises(NotFound):
            self.svc.add_note(9999, "hi", "analyst")
        self.svc.add_note(a, "x" * 2000, "analyst")

    def test_alert_filters(self):
        s = self.svc
        self.assertEqual(s.list_alerts({"category": "ransomware"})["total"], 3)
        self.assertEqual(s.list_alerts({"min_score": "9"})["total"], 2)
        self.assertEqual(s.list_alerts({"asset": "VPN Gateway"})["total"], 3)
        self.assertEqual(s.list_alerts({"q": "Ransom note"})["total"], 1)
        self.assertEqual(s.list_alerts({"q": "ransom"})["total"], 3)  # also matches the other ransomware alerts
        self.assertEqual(s.list_alerts({"status": "open"})["total"], 20)
        self.assertEqual(s.list_alerts({"status": "resolved"})["total"], 0)
        self.assertEqual(s.list_alerts({"severity": "critical"})["total"], 10)
        self.assertEqual(s.list_alerts({"start": "2026-10-17"})["total"], 0)
        self.assertEqual(s.list_alerts({"end": "2026-10-16"})["total"], 20)  # whole end day is included
        page1, page2 = s.list_alerts({"limit": "15"}), s.list_alerts({"limit": "15", "offset": "15"})
        self.assertEqual((len(page1["items"]), len(page2["items"]), page1["total"]), (15, 5, 20))
        self.assertEqual(s.list_alerts({"sort": "time_asc"})["items"][0]["first_epoch"] <= s.list_alerts({"sort": "time_asc"})["items"][1]["first_epoch"], True)

    def test_invalid_parameters_are_rejected(self):
        for p in ({"status": "bogus"}, {"category": "x"}, {"severity": "x"}, {"min_score": "11"}, {"min_score": "abc"},
                  {"limit": "0"}, {"limit": "100000"}, {"offset": "-1"}, {"sort": "random"}, {"start": "not-a-date"}, {"q": "x" * 201}):
            with self.assertRaises(ValueError, msg=str(p)):
                self.svc.list_alerts(p)
        for p in ({"limit": "x"}, {"end": "2026-13-45"}):
            with self.assertRaises(ValueError):
                self.svc.list_logs(p)
        with self.assertRaises(NotFound):
            self.svc.list_logs({"alert_id": "9999"})

    def test_log_filters_and_search(self):
        s = self.svc
        self.assertEqual(s.list_logs({"q": "203.0.113.45"})["total"], 15)
        self.assertEqual(s.list_logs({"q": "203.0.113.45", "event_type": "login_success"})["total"], 1)
        self.assertEqual(s.list_logs({"scenario": "ransomware"})["total"], 14)
        self.assertEqual(s.list_logs({"asset": "Lab System", "source": "endpoint"})["total"] > 0, True)
        self.assertEqual(s.list_logs({"username": "sim.clerk12"})["total"], 32)
        self.assertEqual(s.list_logs({"start": "2026-10-16", "end": "2026-10-16"})["total"], self.svc.db.count_logs())
        self.assertEqual(s.list_logs({"start": "2026-10-17"})["total"], 0)
        a = s.list_alerts({"category": "brute_force", "limit": "1"})["items"][0]["id"]
        self.assertEqual(s.list_logs({"alert_id": str(a)})["total"], s.alert_detail(a)["alert"]["log_count"])

    def test_sql_injection_attempts_are_harmless(self):
        for payload in ("'; DROP TABLE logs;--", "\" OR 1=1 --", "%", "_", "\\", "' UNION SELECT * FROM alerts --"):
            self.svc.list_logs({"q": payload})
            self.svc.list_alerts({"q": payload})
            self.svc.list_logs({"username": payload})
        self.assertGreater(self.svc.db.count_logs(), 0)
        with sqlite3.connect(self.svc.settings.db_path) as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 20)

    def test_like_wildcards_are_matched_literally(self):
        self.assertEqual(self.svc.list_logs({"q": "%"})["total"], 0)   # no raw log contains a percent sign
        self.assertEqual(self.svc.list_logs({"q": "_"})["total"] > 0, True)  # but underscores do occur ("event_type")
        self.assertEqual(self.svc.list_logs({"q": "zz_zz"})["total"], 0)

    def test_alert_detail_has_original_logs_notes_asset(self):
        a = self.svc.list_alerts({"category": "ransomware", "sort": "score_desc"})["items"][0]
        d = self.svc.alert_detail(a["id"])
        self.assertEqual(d["asset"]["asset"], "Lab System")
        self.assertEqual(len(d["logs"]), a["log_count"])
        self.assertEqual([l["timestamp"] for l in d["logs"]], sorted(l["timestamp"] for l in d["logs"]))
        self.assertTrue(all(l["simulated"] for l in d["logs"]))
        self.assertTrue(d["alert"]["explanation"]["summary"])
        with self.assertRaises(NotFound):
            self.svc.alert_detail(9999)

    def test_explain_stores_result_and_audits(self):
        a = self.svc.list_alerts({"limit": "1"})["items"][0]["id"]
        e = self.svc.explain(a, "analyst")
        self.assertEqual(e["source"], "offline")
        self.assertEqual(self.svc.alert_detail(a)["alert"]["explanation"]["source"], "offline")
        self.assertIn("explain", [r["action"] for r in self.svc.db.list_audit()["items"]])

    def test_stats(self):
        st = self.svc.stats()
        self.assertEqual((st["simulated"], st["alerts_total"], st["open_alerts"], st["critical_open"]), (True, 20, 20, 10))
        self.assertEqual(st["logs_total"], self.svc.db.count_logs())
        self.assertTrue(st["timeline"] and st["top_assets"])
        first = self.svc.list_alerts({"limit": "1"})["items"][0]["id"]
        self.svc.set_status(first, "resolved", "analyst")
        self.assertEqual(self.svc.stats()["open_alerts"], 19)

    def test_assets_overview(self):
        rows = self.svc.assets_overview()
        self.assertEqual(len(rows), 14)
        self.assertEqual(rows[0]["asset"], "Lab System")  # highest open score first
        self.assertEqual(sum(r["open_alerts"] for r in rows), 20)

    def test_audit_trail_records_actions(self):
        a = self.svc.list_alerts({"limit": "1"})["items"][0]["id"]
        self.svc.set_status(a, "resolved", "analyst")
        actions = [r["action"] for r in self.svc.db.list_audit()["items"]]
        self.assertIn("status_change", actions)
        self.assertIn("run_detection", actions)

    def test_simulate_and_reset(self):
        r = self.svc.simulate(seed=5, benign=50, scenarios=["malware"], replace=True, actor="analyst")
        self.assertEqual(r["seed"], 5)
        self.assertEqual({a["category"] for a in self.svc.list_alerts({})["items"]}, {"malware"})
        for bad in ({"seed": -1}, {"seed": "x"}, {"benign": 9999}, {"benign": True}, {"scenarios": ["nope"]}, {"scenarios": "malware"}):
            with self.assertRaises(ValueError, msg=str(bad)):
                self.svc.simulate(**bad)
        self.svc.reset("analyst")
        self.assertEqual((self.svc.db.count_logs(), self.svc.list_alerts({})["total"]), (0, 0))
        self.assertGreater(self.svc.db.list_audit()["total"], 0)  # audit trail survives a reset


class ExportTests(TempDirMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.svc = make_service(self.tmp)
        self.svc.simulate(seed=42, actor="test")

    def rows(self, text):
        return list(csv.reader(io.StringIO(text)))

    def test_log_export_csv_and_jsonl(self):
        rows = self.rows(self.svc.export_logs({}, "csv"))
        self.assertEqual(rows[0][:4], ["log_id", "timestamp", "source", "asset"])
        self.assertEqual(len(rows) - 1, self.svc.db.count_logs())
        self.assertTrue(all(r[rows[0].index("simulated")] == "True" for r in rows[1:]))
        lines = self.svc.export_logs({"scenario": "malware"}, "jsonl").strip().splitlines()
        self.assertEqual(len(lines), 14)
        self.assertTrue(all(json.loads(l)["simulated"] is True and "id" not in json.loads(l) for l in lines))

    def test_alert_export(self):
        rows = self.rows(self.svc.export_alerts({"category": "ransomware"}))
        self.assertEqual(len(rows) - 1, 3)
        self.assertEqual(rows[0], self.svc.ALERT_COLUMNS)

    def test_csv_formula_injection_is_neutralised(self):
        self.svc.reset("test")
        evil = "=HYPERLINK(\"http://evil.example\",\"x\")"
        self.svc.ingest([mklog(0, "login_failure", username=evil, src_ip="10.0.0.1", message="+cmd|' /C calc'!A0")])
        row = self.rows(self.svc.export_logs({}, "csv"))[1]
        self.assertTrue(row[5].startswith("'="))
        self.assertTrue(row[10].startswith("'+"))

    def test_contract_export_matches_team_format(self):
        rows = self.rows(self.svc.export_contract())
        self.assertEqual(rows[0], ["timestamp", "asset", "criticality", "src_ip_hashed", "network_score", "anomaly_score",
                                   "threat_flag", "risk_score", "recommended_action"])
        self.assertEqual(len(rows) - 1, 20)
        for r in rows[1:]:
            self.assertRegex(r[3], r"^[0-9a-f]{12}$")
            self.assertTrue(0 <= float(r[7]) <= 1 and 1 <= int(r[2]) <= 5 and r[6] in ("0", "1"))
            self.assertTrue(0 <= float(r[4]) <= 1 and 0 <= float(r[5]) <= 1)
            self.assertTrue(float(r[4]) == 0 or float(r[5]) == 0)
        top = max(rows[1:], key=lambda r: float(r[7]))
        self.assertTrue(top[8].startswith("Isolate"))

    def test_export_row_cap_constant_is_sane(self):
        from soc.service import MAX_EXPORT
        self.assertEqual(MAX_EXPORT, 50000)


if __name__ == "__main__":
    unittest.main()
