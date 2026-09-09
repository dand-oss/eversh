import copy
import unittest

from analyze_reactor_partitions import analyze, PHASES
from test_analyze_reactor_work import result, trace as work_trace


def trace():
    value = work_trace()
    value.update(schema_version=2, protocol="everudp-reactor-partitions-v2")
    for event in value["events"]:
        if event["kind"] != "step":
            continue
        event["pump_drive_calls"] = 2
        event["result"]["work"] = 2
        event["partitions"] = {"valid": True, "overflow": False, "phases": {
            phase: {"calls": 2 if phase == "pump" else 1, "wall_ns": 1, "cpu_ns": 1}
            for phase in PHASES
        }}
    return value


class PartitionTests(unittest.TestCase):
    def test_nested_same_step_totals_preserve_input_and_exclusions(self):
        value = trace()
        original = copy.deepcopy(value)
        report = analyze(result(), value)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual(value, original)
        self.assertEqual(report["included_sequences"], 1)
        step = report["initial_post_offer_pairs"][0]["initial_post_offer"]
        self.assertEqual(step["unattributed_ns"], {"wall_ns": 5, "cpu_ns": 5})
        self.assertEqual(step["phases"]["send"]["calls"], 1)

    def test_invalid_partition_contracts_are_rejected(self):
        for case in range(8):
            value = trace()
            event = value["events"][1]
            partitions = event["partitions"]
            if case == 0: partitions["overflow"] = True
            elif case == 1: partitions["valid"] = False
            elif case == 2: partitions["phases"]["send"]["wall_ns"] = 100
            elif case == 3: partitions["phases"]["receive"]["calls"] = 0
            elif case == 4: partitions["phases"]["pump"]["calls"] = True
            elif case == 5: partitions["phases"]["event_drain"]["calls"] = 2
            elif case == 6: event.pop("partitions")
            else: partitions["phases"]["segment"]["calls"] = 2
            with self.subTest(case=case):
                self.assertEqual(analyze(result(), value)["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
