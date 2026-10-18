import unittest

from soc.detection import DetectionConfig, burst_clusters, chain_clusters, is_internal, prepare, run_rules
from soc.generator import EXPECTED_RULES, generate
from helpers import DAY, assets, mklog


def rules_for(logs, cfg=None):
    return sorted(f.rule_id for f in run_rules(logs, assets(), cfg))


class ScenarioDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assets = assets()

    def test_each_scenario_triggers_exactly_its_rules(self):
        for name, expected in EXPECTED_RULES.items():
            logs = generate(self.assets, seed=1, day=DAY, scenarios=[name], benign=0)
            self.assertEqual(rules_for(logs), sorted(expected), name)

    def test_full_day_triggers_all_19_rules(self):
        got = {f.rule_id for f in run_rules(generate(self.assets, seed=42, day=DAY), self.assets)}
        self.assertEqual(got, {r for v in EXPECTED_RULES.values() for r in v})

    def test_benign_traffic_produces_no_alerts(self):
        for seed in (1, 7, 99, 12345):
            logs = generate(self.assets, seed=seed, day=DAY, scenarios=[], benign=2000)
            self.assertEqual(rules_for(logs), [], f"false positive with seed {seed}")

    def test_detection_is_deterministic(self):
        logs = generate(self.assets, seed=42, day=DAY)
        a = [(f.rule_id, f.first_ts, f.asset, f.confidence) for f in run_rules(logs, self.assets)]
        b = [(f.rule_id, f.first_ts, f.asset, f.confidence) for f in run_rules(list(reversed(logs)), self.assets)]
        self.assertEqual(a, b)

    def test_timezone_offset_still_detects_after_hours(self):
        logs = generate(self.assets, seed=1, day=DAY, scenarios=["ehr_access"], benign=0, utc_offset_hours=8)
        got = rules_for(logs, DetectionConfig(utc_offset_hours=8))
        self.assertIn("EHR-002", got)
        # Wrong offset: the same instants fall inside "business hours" and EHR-002 must not fire.
        self.assertNotIn("EHR-002", rules_for(logs, DetectionConfig(utc_offset_hours=-3)))


class Boundaries(unittest.TestCase):
    def fails(self, n, gap=10, **kw):
        return [mklog(i * gap, "login_failure", username="sim.u1", src_ip="203.0.113.5", outcome="failure", **kw) for i in range(n)]

    def test_brute_force_threshold(self):
        self.assertNotIn("BF-001", rules_for(self.fails(7)))
        self.assertIn("BF-001", rules_for(self.fails(8)))

    def test_brute_force_needs_to_be_inside_window(self):
        self.assertNotIn("BF-001", rules_for(self.fails(8, gap=60)))  # 8 failures over 7 minutes

    def test_spray_threshold(self):
        def spray(n):
            return [mklog(i * 30, "login_failure", username=f"sim.u{i}", src_ip="203.0.113.9", outcome="failure") for i in range(n)]
        self.assertNotIn("BF-002", rules_for(spray(5)))
        self.assertIn("BF-002", rules_for(spray(6)))

    def test_success_after_failures(self):
        logs = self.fails(5) + [mklog(60, "login_success", username="sim.u1", src_ip="203.0.113.5", outcome="success")]
        self.assertIn("BF-003", rules_for(logs))
        self.assertNotIn("BF-003", rules_for(self.fails(4) + [mklog(60, "login_success", username="sim.u1", src_ip="203.0.113.5", outcome="success")]))

    def ehr(self, n, **details):
        d = {"care_relationship": False, "vip": False, "break_glass": False}
        d.update(details)
        return [mklog(i * 5, "ehr_record_access", asset="EHR Server", source="ehr", username="sim.clerk1", hour=11,
                      details=dict(d, patient_id=f"SIM-PT-{i:05d}")) for i in range(n)]

    def test_bulk_ehr_threshold(self):
        self.assertNotIn("EHR-001", rules_for(self.ehr(19)))
        self.assertIn("EHR-001", rules_for(self.ehr(20)))

    def test_break_glass_and_care_relationship_are_not_flagged(self):
        self.assertEqual(rules_for(self.ehr(40, break_glass=True)), [])
        self.assertEqual(rules_for(self.ehr(40, care_relationship=True)), [])

    def test_vip_access_flagged_only_without_care_relationship(self):
        self.assertIn("EHR-003", rules_for(self.ehr(1, vip=True)))
        self.assertEqual(rules_for(self.ehr(1, vip=True, care_relationship=True)), [])

    def test_approved_admin_in_business_hours_is_not_flagged(self):
        def grp(actor, hour):
            return [mklog(0, "group_membership_change", asset="Domain Controller", source="directory", username=actor, hour=hour,
                          details={"target_user": "sim.admin03", "group": "Domain Admins", "action": "added"})]
        self.assertEqual(rules_for(grp("sim.admin01", 11)), [])
        self.assertIn("PRIV-001", rules_for(grp("sim.admin01", 2)))     # after hours
        self.assertIn("PRIV-001", rules_for(grp("sim.helpdesk05", 11)))  # not an approved admin
        non_admin_group = [mklog(0, "group_membership_change", asset="Domain Controller", source="directory", username="sim.helpdesk05",
                                 details={"target_user": "x", "group": "Radiology Staff", "action": "added"})]
        self.assertEqual(rules_for(non_admin_group), [])

    def test_device_rules_respect_allow_list_and_maintenance_window(self):
        def rdp(src):
            return [mklog(0, "device_network_connection", asset="Infusion Pump Network", source="device", src_ip=src,
                          dst_ip="10.30.1.33", dst_port=3389, details={"direction": "inbound"})]
        self.assertEqual(rules_for(rdp("10.50.0.5")), [])
        self.assertIn("DEV-002", rules_for(rdp("10.40.2.15")))
        fw = lambda mw: [mklog(0, "device_firmware_change", asset="MRI Scanner", source="device", details={"maintenance_window": mw})]
        self.assertEqual(rules_for(fw(True)), [])
        self.assertIn("DEV-004", rules_for(fw(False)))

    def test_device_scan_threshold(self):
        def scan(n):
            return [mklog(i * 2, "device_network_connection", asset="Patient Monitor Network", source="device", src_ip="10.30.3.17",
                          dst_ip="10.10.1.10", dst_port=1000 + i, details={"direction": "internal"}) for i in range(n)]
        self.assertNotIn("DEV-003", rules_for(scan(14)))
        self.assertIn("DEV-003", rules_for(scan(15)))

    def test_ransomware_needs_enough_files(self):
        def burst(files):
            return [mklog(0, "file_modified_burst", asset="Lab System", source="endpoint", details={"files_modified": files, "extension": ".locked"})]
        self.assertEqual(rules_for(burst(199)), [])
        self.assertIn("RAN-001", rules_for(burst(200)))
        harmless = [mklog(0, "file_modified_burst", asset="Lab System", source="endpoint", details={"files_modified": 5000, "extension": ".docx"})]
        self.assertEqual(rules_for(harmless), [])

    def test_documentation_ranges_count_as_external(self):
        self.assertTrue(is_internal("10.1.2.3") and is_internal("192.168.1.1") and is_internal("172.16.5.5"))
        self.assertFalse(is_internal("198.51.100.7") or is_internal("203.0.113.1") or is_internal("8.8.8.8"))
        self.assertFalse(is_internal("not-an-ip"))


class ClusterHelpers(unittest.TestCase):
    def test_burst_and_chain_clusters(self):
        evs = prepare([mklog(t, "x") for t in (0, 10, 20, 500, 510)])
        self.assertEqual([len(c) for c in burst_clusters(evs, 60, 3)], [3])
        self.assertEqual([len(c) for c in chain_clusters(evs, 100)], [3, 2])


if __name__ == "__main__":
    unittest.main()
