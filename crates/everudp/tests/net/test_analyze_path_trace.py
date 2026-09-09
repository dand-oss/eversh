import copy
import unittest
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from analyze_path_trace import analyze


IDENTITY = {
    "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
    "time_namespace_dev": 1,
    "time_namespace_ino": 2,
}


def event(stage, epoch, sequence, time_ns):
    return {"stage": stage, "epoch": epoch, "sequence": sequence, "time_ns": time_ns}


def trace(events, **overrides):
    value = {
        "schema_version": 1,
        "diagnostic_only": True,
        "clock": "CLOCK_MONOTONIC",
        "valid": True,
        "overflow": False,
        "pid": 11,
        "boot_id": IDENTITY["boot_id"],
        "namespace_dev": IDENTITY["time_namespace_dev"],
        "namespace_ino": IDENTITY["time_namespace_ino"],
        "events": events,
    }
    value.update(overrides)
    return value


def result():
    return {
        "public_clock": "CLOCK_MONOTONIC; local host and time namespace only",
        "clock_identity": IDENTITY,
        "trials": 1,
        "samples_us": [1],
        "transcript_failures": 0,
        "public_boundaries": [{"trial": 0, "send_ns": 100, "accepted_ns": 200}],
    }


def pair():
    client = trace([
        event("client_input_queued", 1, 7, 110),
        event("client_input_written", 1, 7, 120),
        event("client_output_staged", 9, 42, 160),
        event("client_output_accepted", 9, 42, 210),
    ])
    gateway = trace([
        event("gateway_input_prepared", 1, 7, 115),
        event("gateway_input_accepted", 1, 7, 140),
        event("gateway_output_queued", 9, 42, 150),
    ])
    return client, gateway, result()


class PathTraceTests(unittest.TestCase):
    def test_valid_trace_keeps_signed_handoffs_and_independent_sequences(self):
        report = analyze(*pair())
        self.assertEqual(report["status"], "DIAGNOSTIC")
        self.assertFalse(report["qualification"])
        self.assertEqual(report["rows"][0]["input"]["sequence"], 7)
        self.assertEqual(report["rows"][0]["output"]["sequence"], 42)
        self.assertEqual(report["rows"][0]["stream_handoff_ns"], -5)
        self.assertEqual(report["rows"][0]["output_handoff_ns"], 10)

    def test_retransmitted_write_is_reported(self):
        client, gateway, public = pair()
        client["events"].insert(2, event("client_input_written", 1, 7, 130))
        report = analyze(client, gateway, public)
        self.assertEqual(report["rows"][0]["input"]["written_ns"], [120, 130])

    def test_rejects_unknown_and_extra_fields(self):
        client, gateway, public = pair()
        client["events"][0]["payload"] = "secret"
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)
        client, gateway, public = pair()
        client["events"][0]["stage"] = "payload"
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)

    def test_rejects_identity_overflow_and_timestamp_regression(self):
        client, gateway, public = pair()
        gateway["namespace_dev"] = 9
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)
        client, gateway, public = pair()
        client["events"][1]["time_ns"] = 1
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)
        client, gateway, public = pair()
        client["events"][0]["sequence"] = True
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)

    def test_rejects_duplicate_acceptance_and_missing_markers(self):
        client, gateway, public = pair()
        client["events"].append(event("client_output_accepted", 9, 42, 211))
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)
        client, gateway, public = pair()
        client["events"].pop(0)
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)

    def test_rejects_ambiguous_measured_marker_but_counts_warmup(self):
        client, gateway, public = pair()
        client["events"].insert(0, event("client_input_queued", 1, 1, 90))
        report = analyze(client, gateway, public)
        self.assertEqual(report["warmup_client_markers"], 1)
        client["events"].insert(1, event("client_input_queued", 1, 8, 111))
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)

    def test_rejects_invalid_status_and_capacity(self):
        client, gateway, public = pair()
        client["valid"] = False
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)
        client, gateway, public = pair()
        client["events"] = client["events"] * 8193
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)

    def test_rejects_signed_overflow_and_negative_handoff_crossing(self):
        client, gateway, public = pair()
        client["events"][0]["sequence"] = 1 << 64
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)
        client, gateway, public = pair()
        gateway["events"][1]["time_ns"] = 100
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)

    def test_does_not_mutate_inputs(self):
        client, gateway, public = pair()
        original = copy.deepcopy((client, gateway, public))
        analyze(client, gateway, public)
        self.assertEqual((client, gateway, public), original)

    def test_duplicate_input_sequence_outside_window_is_not_warmup(self):
        client, gateway, public = pair()
        client["events"].insert(0, event("client_input_queued", 1, 7, 90))
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)

    def test_gateway_output_cannot_be_queued_after_client_staging(self):
        client, gateway, public = pair()
        gateway["events"][-1]["time_ns"] = 170
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)

    def test_late_anchor_is_not_counted_as_warmup(self):
        client, gateway, public = pair()
        client["events"].append(event("client_input_queued", 1, 8, 220))
        with self.assertRaises(ValueError):
            analyze(client, gateway, public)

    def test_cli_json_roundtrip_and_duplicate_key_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / f"{name}.json" for name in ("client", "gateway", "result")]
            for path, value in zip(paths, pair()):
                path.write_text(json.dumps(value), encoding="utf-8")
            command = [sys.executable, "-B", str(Path(__file__).with_name("analyze_path_trace.py")), *map(str, paths)]
            passed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertFalse(json.loads(passed.stdout)["qualification"])
            paths[0].write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            rejected = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("duplicate JSON", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
