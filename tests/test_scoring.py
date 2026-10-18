import unittest

from soc.assets import Asset
from soc.detection import Finding
from soc.engine import build_alerts
from soc.generator import generate
from soc.scoring import confidence_label, score_finding, severity_label
from helpers import DAY, assets


def finding(rule="RAN-001", conf=0.95, severity=None):
    return Finding(rule_id=rule, asset="X", first_ts=0, last_ts=1, events=[], evidence=[], confidence=conf, severity=severity)


def asset(crit=3, patient_care=False, phi=False):
    return Asset(asset="X", criticality=crit, patient_care=patient_care, holds_phi=phi)


class ScoringTests(unittest.TestCase):
    def test_score_always_between_1_and_10(self):
        for rule in ("BF-001", "RAN-001", "DEV-004", "PRIV-002"):
            for crit in range(1, 6):
                for conf in (0.1, 0.5, 0.7, 0.99):
                    for rel in ([], ["A"], ["A", "B", "C"]):
                        s = score_finding(finding(rule, conf), asset(crit), rel)["score"]
                        self.assertTrue(1 <= s <= 10)

    def test_breakdown_adds_up_and_has_five_factors(self):
        r = score_finding(finding(), asset(5, True, True), ["RAN-002"])
        self.assertEqual([b["factor"] for b in r["breakdown"]],
                         ["Rule severity", "Evidence strength", "Corroborating activity", "Asset criticality", "Hospital impact"])
        self.assertAlmostEqual(sum(b["points"] for b in r["breakdown"]), r["total"], places=2)
        self.assertTrue(all(0 <= b["points"] <= b["max"] for b in r["breakdown"]))
        self.assertEqual(sum(b["max"] for b in r["breakdown"]), 10.0)

    def test_more_critical_asset_never_scores_lower(self):
        scores = [score_finding(finding("BF-003", 0.9), asset(c), [])["score"] for c in range(1, 6)]
        self.assertEqual(scores, sorted(scores))
        self.assertLess(scores[0], scores[-1])

    def test_corroboration_and_confidence_raise_score(self):
        low = score_finding(finding("EHR-001", 0.6), asset(3), [])["total"]
        self.assertGreater(score_finding(finding("EHR-001", 0.9), asset(3), [])["total"], low)
        self.assertGreater(score_finding(finding("EHR-001", 0.6), asset(3), ["A", "B"])["total"], low)

    def test_patient_care_asset_raises_impact(self):
        a = score_finding(finding("DEV-001"), asset(4, patient_care=False), [])["breakdown"][4]["points"]
        b = score_finding(finding("DEV-001"), asset(4, patient_care=True), [])["breakdown"][4]["points"]
        self.assertGreater(b, a)

    def test_ransomware_on_critical_clinical_system_is_10(self):
        self.assertEqual(score_finding(finding("RAN-001", 0.97), asset(5, True, True), ["RAN-002", "RAN-003"])["score"], 10)

    def test_trivial_event_on_guest_network_is_low(self):
        r = score_finding(finding("BF-001", 0.55), Asset(asset="Guest Wi-Fi", criticality=1), [])
        self.assertEqual(r["label"], "low")

    def test_severity_and_confidence_labels(self):
        self.assertEqual([severity_label(s) for s in (1, 3, 4, 5, 6, 7, 8, 10)],
                         ["low", "low", "medium", "medium", "high", "high", "critical", "critical"])
        self.assertEqual([confidence_label(c) for c in (0.5, 0.65, 0.85)], ["Low", "Medium", "High"])

    def test_full_day_alerts_are_consistent_and_ordered(self):
        a = assets()
        drafts = build_alerts(generate(a, seed=42, day=DAY), a)
        self.assertEqual(len(drafts), 20)
        self.assertEqual([d["score"] for d in drafts], sorted((d["score"] for d in drafts), reverse=True))
        self.assertEqual(drafts[0]["rule_id"], "RAN-001")
        self.assertTrue(all(1 <= d["score"] <= 10 and d["breakdown"] and d["evidence"] for d in drafts))
        self.assertEqual(len({d["dedup_key"] for d in drafts}), len(drafts))
        bf3 = next(d for d in drafts if d["rule_id"] == "BF-003")
        self.assertTrue({r["rule_id"] for r in bf3["related"]} >= {"BF-001", "PRIV-001"})  # chain linked through the same user


if __name__ == "__main__":
    unittest.main()
