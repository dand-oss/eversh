#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("analyze-tuning.py")
SPEC = importlib.util.spec_from_file_location("analyze_tuning", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)


class AnalyzeTuningTests(unittest.TestCase):
    def fixture(self, trials, fast_profile=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        profiles = ANALYZER.profile_names()
        manifest = {
            "schema_version": 1,
            "trials": trials,
            "seeds": {"0": 910001, "5": 910003},
            "profiles": profiles,
        }
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        for profile in profiles:
            for loss, seed in ((0, 910001), (5, 910003)):
                baseline = 1000 + loss * 20
                if profile == fast_profile:
                    baseline //= 2
                samples = [baseline + index % 7 for index in range(trials)]
                payload = {
                    "schema_version": 1,
                    "correct": True,
                    "loss_percent": loss,
                    "trials": trials,
                    "seed": seed,
                    "proxy": {
                        "client_packets": trials * 3,
                        "server_packets": trials * 3,
                        "client_drops": 1 if loss else 0,
                        "server_drops": 1 if loss else 0,
                    },
                    "total_us": samples,
                    "local_send_us": [2] * trials,
                    "gateway_accept_us": [baseline // 2] * trials,
                    "gateway_echo_us": [baseline // 2 + 1] * trials,
                }
                stem = root / f"{profile}-loss{loss}"
                stem.with_suffix(".json").write_text(json.dumps(payload), encoding="utf-8")
                stem.with_suffix(".time").write_text("0.10 0.02 4096 1.00\n", encoding="utf-8")
        return root

    def test_exact_matrix_with_equal_results_retains_default(self):
        result = ANALYZER.analyze(self.fixture(200), 200)
        self.assertEqual(result["valid_profile_count"], 18)
        self.assertEqual(result["selected_profile"], ANALYZER.DEFAULT)
        self.assertEqual(result["decision"], "default-retained")
        self.assertTrue(result["selection_eligible"])

    def test_clear_paired_winner_is_selected(self):
        winner = "rtt25-every-other-5ms-gso-on"
        result = ANALYZER.analyze(self.fixture(200, winner), 200)
        self.assertEqual(result["raw_winner"], winner)
        self.assertEqual(result["selected_profile"], winner)
        self.assertLess(result["winner_default_p95_ratio_interval_95"][1], 1.0)

    def test_short_smoke_can_validate_but_cannot_select(self):
        winner = "rtt25-every-other-5ms-gso-on"
        result = ANALYZER.analyze(self.fixture(20, winner), 100)
        self.assertEqual(result["raw_winner"], winner)
        self.assertEqual(result["selected_profile"], ANALYZER.DEFAULT)
        self.assertEqual(result["decision"], "validation-only-default-retained")
        self.assertFalse(result["selection_eligible"])


if __name__ == "__main__":
    unittest.main()
