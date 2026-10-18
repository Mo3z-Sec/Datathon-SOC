"""HTTP-level tests using FastAPI's TestClient. Skipped automatically when fastapi/httpx are missing."""
import unittest

try:
    from fastapi.testclient import TestClient
    from soc.main import create_app
    HAVE = True
except Exception:  # pragma: no cover
    HAVE = False

from helpers import ANALYST, VIEWER, TempDirMixin, make_service

A = {"Authorization": f"Bearer {ANALYST}"}
V = {"Authorization": f"Bearer {VIEWER}"}


@unittest.skipUnless(HAVE, "fastapi + httpx are not installed (pip install -r requirements-dev.txt)")
class ApiTests(TempDirMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        svc = make_service(self.tmp)
        self.c = TestClient(create_app(svc.settings, svc))

    def seed(self):
        r = self.c.post("/api/simulate", json={"seed": 42}, headers=A)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_health_is_public_but_data_needs_a_token(self):
        self.assertEqual(self.c.get("/api/health").json()["status"], "ok")
        for path in ("/api/alerts", "/api/logs", "/api/stats", "/api/assets", "/api/me", "/api/export/logs.csv"):
            self.assertEqual(self.c.get(path).status_code, 401, path)
        self.assertEqual(self.c.get("/api/alerts", headers={"Authorization": "Bearer wrong"}).status_code, 401)
        self.assertEqual(self.c.get("/api/me", headers={"X-API-Key": ANALYST}).json()["role"], "analyst")

    def test_roles(self):
        self.assertEqual(self.c.get("/api/me", headers=A).json(), {"role": "analyst"})
        self.assertEqual(self.c.get("/api/me", headers=V).json(), {"role": "viewer"})
        self.seed()
        self.assertEqual(self.c.get("/api/alerts", headers=V).status_code, 200)
        for method, path, body in (("post", "/api/simulate", {}), ("post", "/api/detect", None), ("post", "/api/reset", {"confirm": True}),
                                   ("post", "/api/alerts/1/status", {"status": "resolved"}), ("post", "/api/alerts/1/notes", {"text": "x"}),
                                   ("post", "/api/alerts/1/explain", None), ("get", "/api/audit", None)):
            r = getattr(self.c, method)(path, headers=V, **({"json": body} if body is not None else {}))
            self.assertEqual(r.status_code, 403, path)

    def test_full_analyst_workflow(self):
        s = self.seed()
        self.assertEqual((s["seed"], s["alerts_total"]), (42, 20))
        alerts = self.c.get("/api/alerts?limit=5", headers=A).json()
        self.assertEqual((alerts["total"], len(alerts["items"])), (20, 5))
        aid = alerts["items"][0]["id"]
        d = self.c.get(f"/api/alerts/{aid}", headers=A).json()
        self.assertTrue(d["logs"] and d["alert"]["breakdown"] and d["alert"]["explanation"]["steps"])
        self.assertEqual(self.c.post(f"/api/alerts/{aid}/status", json={"status": "investigating"}, headers=A).status_code, 200)
        self.assertEqual(self.c.post(f"/api/alerts/{aid}/notes", json={"text": "Called the network team."}, headers=A).status_code, 200)
        d = self.c.get(f"/api/alerts/{aid}", headers=A).json()
        self.assertEqual((d["alert"]["status"], d["notes"][0]["text"]), ("investigating", "Called the network team."))
        self.assertEqual(self.c.post(f"/api/alerts/{aid}/explain", headers=A).json()["source"], "offline")
        self.assertEqual(self.c.get("/api/stats", headers=A).json()["open_alerts"], 20)
        self.assertEqual(self.c.post("/api/detect", headers=A).json()["created"], 0)
        self.assertGreater(self.c.get("/api/audit", headers=A).json()["total"], 3)
        self.assertEqual(len(self.c.get("/api/assets", headers=A).json()), 14)
        self.assertIn("scenario_info", self.c.get("/api/options", headers=A).json())
        cfg = self.c.get("/api/config", headers=A).json()
        self.assertEqual((cfg["simulated"], cfg["ai_enabled"], cfg["read_only_system"]), (True, False, True))

    def test_validation_errors(self):
        self.seed()
        cases = [("post", "/api/alerts/1/status", {"status": "nonsense"}), ("post", "/api/alerts/1/status", {}),
                 ("post", "/api/alerts/1/notes", {"text": "   "}), ("post", "/api/alerts/1/notes", {"text": "x" * 2001}),
                 ("post", "/api/simulate", {"seed": -5}), ("post", "/api/simulate", {"benign": 99999}),
                 ("post", "/api/simulate", {"scenarios": ["fake"]}), ("post", "/api/reset", {"confirm": False}),
                 ("post", "/api/reset", {})]
        for method, path, body in cases:
            self.assertEqual(getattr(self.c, method)(path, json=body, headers=A).status_code, 422, f"{path} {body}")
        for q in ("status=bogus", "limit=0", "limit=abc", "min_score=99", "start=garbage", "sort=hax"):
            self.assertEqual(self.c.get(f"/api/alerts?{q}", headers=A).status_code, 422, q)
        self.assertEqual(self.c.get("/api/logs?end=garbage", headers=A).status_code, 422)
        self.assertEqual(self.c.get("/api/alerts/99999", headers=A).status_code, 404)
        self.assertEqual(self.c.post("/api/alerts/99999/status", json={"status": "resolved"}, headers=A).status_code, 404)
        self.assertEqual(self.c.get("/api/alerts/not-a-number", headers=A).status_code, 422)

    def test_exports(self):
        self.seed()
        r = self.c.get("/api/export/logs.csv?scenario=ransomware", headers=V)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["content-type"].startswith("text/csv"))
        self.assertIn("attachment", r.headers["content-disposition"])
        self.assertEqual(len(r.text.strip().splitlines()) - 1, 14)
        self.assertEqual(len(self.c.get("/api/export/logs.jsonl", headers=A).text.strip().splitlines()), self.c.get("/api/logs?limit=1", headers=A).json()["total"])
        self.assertIn("rule_id", self.c.get("/api/export/alerts.csv", headers=A).text.splitlines()[0])
        self.assertIn("src_ip_hashed", self.c.get("/api/export/contract.csv", headers=A).text.splitlines()[0])

    def test_reset_requires_confirmation_and_clears_data(self):
        self.seed()
        self.assertEqual(self.c.post("/api/reset", json={"confirm": True}, headers=A).status_code, 200)
        self.assertEqual(self.c.get("/api/alerts", headers=A).json()["total"], 0)

    def test_static_files_and_security_headers(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("SIMULATED DATA", r.text)
        self.assertEqual(self.c.get("/static/app.js").status_code, 200)
        self.assertEqual(self.c.get("/static/style.css").status_code, 200)
        for h in ("x-content-type-options", "x-frame-options", "content-security-policy", "referrer-policy"):
            self.assertIn(h, r.headers)
        self.assertEqual(self.c.get("/api/stats", headers=A).headers["cache-control"], "no-store")
        for path in ("/docs", "/redoc", "/openapi.json"):
            self.assertEqual(self.c.get(path).status_code, 404, path)


if __name__ == "__main__":
    unittest.main()
