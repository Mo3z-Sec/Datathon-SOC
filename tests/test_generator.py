import ipaddress
import re
import unittest

from soc.detection import is_internal
from soc.generator import EXPECTED_RULES, SCENARIOS, generate
from helpers import DAY, assets

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


class GeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assets = assets()
        cls.logs = generate(cls.assets, seed=42, day=DAY)

    def test_deterministic_for_same_seed(self):
        self.assertEqual(self.logs, generate(self.assets, seed=42, day=DAY))

    def test_different_seed_changes_output(self):
        self.assertNotEqual(self.logs, generate(self.assets, seed=43, day=DAY))

    def test_every_log_is_labelled_simulated(self):
        self.assertTrue(all(l["simulated"] is True for l in self.logs))

    def test_all_six_scenarios_present(self):
        self.assertEqual({l["sim_scenario"] for l in self.logs if l["sim_scenario"]}, set(SCENARIOS))

    def test_logs_sorted_and_ids_unique(self):
        ts = [l["timestamp"] for l in self.logs]
        self.assertEqual(ts, sorted(ts))
        self.assertEqual(len({l["log_id"] for l in self.logs}), len(self.logs))

    def test_no_real_public_ip_addresses(self):
        for l in self.logs:
            for ip in (l["src_ip"], l["dst_ip"]):
                if ip and not is_internal(ip):
                    self.assertTrue(any(ipaddress.ip_address(ip) in n for n in DOC_NETS), f"non-reserved IP {ip}")

    def test_patient_ids_are_fake(self):
        ids = [l["details"]["patient_id"] for l in self.logs if "patient_id" in l["details"]]
        self.assertTrue(ids)
        self.assertTrue(all(re.fullmatch(r"SIM-PT-\d{5}", i) for i in ids))

    def test_asset_names_come_from_inventory(self):
        self.assertTrue({l["asset"] for l in self.logs} <= set(self.assets))

    def test_scenario_subset_and_validation(self):
        only = generate(self.assets, seed=1, day=DAY, benign=0, scenarios=["malware"])
        self.assertTrue(only and all(l["sim_scenario"] == "malware" for l in only))
        with self.assertRaises(ValueError):
            generate(self.assets, scenarios=["nope"])
        with self.assertRaises(ValueError):
            generate(self.assets, benign=-1)
        with self.assertRaises(ValueError):
            generate(self.assets, benign=5001)

    def test_expected_rules_cover_every_scenario(self):
        self.assertEqual(set(EXPECTED_RULES), set(SCENARIOS))


if __name__ == "__main__":
    unittest.main()
