import json
import unittest

from soc.detection import RULES
from soc.engine import build_alerts
from soc.explain import GROUPS, explain_alert, offline_explanation, parse_ai_answer, build_ai_prompt
from soc.generator import generate
from helpers import DAY, TempDirMixin, assets, make_settings


class ExplainTests(TempDirMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assets = assets()
        cls.alerts = build_alerts(generate(cls.assets, seed=42, day=DAY), cls.assets)

    def test_offline_explanation_for_every_rule(self):
        seen = set()
        for a in self.alerts:
            e = offline_explanation(a, self.assets.get(a["asset"]))
            seen.add(a["rule_id"])
            self.assertGreater(len(e["summary"]), 30, a["rule_id"])
            self.assertGreater(len(e["why_it_matters"]), 20)
            self.assertEqual(set(e["steps"]), set(GROUPS))
            self.assertTrue(all(e["steps"][g] for g in GROUPS))
            self.assertEqual(e["source"], "offline")
            self.assertIn("read-only", e["disclaimer"])
            self.assertNotIn("{", e["summary"])  # no unfilled template fields
        self.assertEqual(seen, set(RULES))

    def test_device_alerts_warn_about_clinical_engineering(self):
        a = next(x for x in self.alerts if x["rule_id"] == "DEV-001")
        e = offline_explanation(a, self.assets[a["asset"]])
        self.assertTrue(any("Clinical Engineering" in s for s in e["steps"]["contain"]))

    def test_summary_mentions_real_evidence(self):
        a = next(x for x in self.alerts if x["rule_id"] == "BF-001")
        self.assertIn(a["src_ip"], offline_explanation(a)["summary"])

    def ai_reply(self, obj):
        return lambda url, headers, body, timeout: json.dumps({"content": [{"type": "text", "text": json.dumps(obj) if not isinstance(obj, str) else obj}]})

    def settings(self, **kw):
        return make_settings(self.tmp, SOC_AI_PROVIDER="anthropic", SOC_AI_API_KEY="test-key", **kw)

    def test_ai_disabled_never_calls_network(self):
        calls = []
        s = make_settings(self.tmp)
        e = explain_alert(self.alerts[0], self.assets[self.alerts[0]["asset"]], s, post=lambda *a: calls.append(a))
        self.assertEqual((e["source"], calls), ("offline", []))

    def test_ai_success_is_used_and_merged(self):
        good = {"summary": "AI says this is bad.", "why_it_matters": "Because patients.", "steps": {"investigate": ["Look at logs."]}}
        e = explain_alert(self.alerts[0], self.assets[self.alerts[0]["asset"]], self.settings(), post=self.ai_reply(good))
        self.assertEqual((e["source"], e["summary"]), ("ai", "AI says this is bad."))
        self.assertEqual(e["steps"]["investigate"], ["Look at logs."])
        self.assertTrue(e["steps"]["contain"])  # missing groups fall back to offline steps
        self.assertIn("read-only", e["disclaimer"])

    def test_ai_failures_fall_back_to_offline(self):
        a, asset = self.alerts[0], self.assets[self.alerts[0]["asset"]]
        def boom(*args):
            raise OSError("network unreachable")
        for post in (boom, self.ai_reply("this is not json"), self.ai_reply({"summary": "", "why_it_matters": "x"}),
                     lambda *args: "<html>502</html>", self.ai_reply([1, 2, 3])):
            e = explain_alert(a, asset, self.settings(), post=post)
            self.assertEqual(e["source"], "offline")
            self.assertIn("unavailable", e["ai_note"])
            self.assertGreater(len(e["summary"]), 30)

    def test_prompt_contains_summary_not_raw_logs(self):
        a = self.alerts[0]
        prompt = build_ai_prompt(a, self.assets[a["asset"]], offline_explanation(a))
        self.assertNotIn('"message"', prompt)
        self.assertNotIn("log_ids", prompt)
        self.assertIn('"data_is_simulated": true', prompt)

    def test_ai_request_shape(self):
        seen = {}
        def post(url, headers, body, timeout):
            seen.update(url=url, headers=headers, body=json.loads(body), timeout=timeout)
            return json.dumps({"content": [{"type": "text", "text": json.dumps({"summary": "s", "why_it_matters": "w"})}]})
        explain_alert(self.alerts[0], None, self.settings(SOC_AI_MODEL="some-model", SOC_AI_TIMEOUT="7"), post=post)
        self.assertTrue(seen["url"].startswith("https://api.anthropic.com/"))
        self.assertEqual((seen["headers"]["x-api-key"], seen["body"]["model"], seen["timeout"]), ("test-key", "some-model", 7.0))

    def test_parse_handles_code_fences_and_control_characters(self):
        base = offline_explanation(self.alerts[0])
        out = parse_ai_answer("```json\n" + json.dumps({"summary": "ok\x00text", "why_it_matters": "fine"}) + "\n```", base)
        self.assertEqual(out["summary"], "oktext")


if __name__ == "__main__":
    unittest.main()
