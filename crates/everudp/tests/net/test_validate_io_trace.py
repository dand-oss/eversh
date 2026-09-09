import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_analyze_path_trace import pair
from validate_io_trace import CONTEXTUAL, TERMINAL, STAGES, load, validate


def fixture():
    base = pair()[0]
    sidecar = {**base, "trace_kind": "quic_io", "events": [
        {"stage": "udp_receive", "time_ns": 120, "connection": None, "stream": None},
        {"stage": "stream_readable", "time_ns": 130, "connection": 0, "stream": 3},
    ]}
    return sidecar, base


class IoTraceTests(unittest.TestCase):
    def test_valid_sidecar_is_diagnostic_only(self):
        result = validate(*fixture(), "client")
        self.assertFalse(result["qualification"])
        self.assertEqual(result["event_count"], 2)

    def test_every_stage_and_gateway_role(self):
        sidecar, _ = fixture()
        base = pair()[1]
        gateway_stages = STAGES - TERMINAL
        sidecar["events"] = [{"stage": stage, "time_ns": 130,
            "connection": 0 if stage in CONTEXTUAL else None,
            "stream": 2 if stage == "stream_readable" else None} for stage in sorted(gateway_stages)]
        self.assertEqual(validate(sidecar, base, "gateway")["event_count"], len(gateway_stages))

    def test_terminal_stages_roundtrip_on_client(self):
        sidecar, base = fixture()
        sidecar["events"] = [{"stage": stage, "time_ns": 130 + index,
            "connection": None, "stream": None}
            for index, stage in enumerate(sorted(TERMINAL))]
        result = validate(sidecar, base, "client")
        self.assertEqual(result["event_count"], len(TERMINAL))
        self.assertEqual(set(result["stage_counts"]), TERMINAL)

    def test_terminal_stages_reject_gateway_and_ids(self):
        for stage in sorted(TERMINAL):
            sidecar, base = fixture()
            sidecar["events"] = [{"stage": stage, "time_ns": 130,
                                  "connection": None, "stream": None}]
            with self.subTest(stage=stage):
                with self.assertRaises(ValueError):
                    validate(sidecar, base, "gateway")
            for field in ("connection", "stream"):
                sidecar, base = fixture()
                sidecar["events"] = [{"stage": stage, "time_ns": 130,
                                      "connection": None, "stream": None}]
                sidecar["events"][0][field] = 0
                with self.subTest(stage=stage, field=field):
                    with self.assertRaises(ValueError):
                        validate(sidecar, base, "client")

    def test_wrong_identity_or_status_fails(self):
        for key, value in (("pid", 12), ("pid", True), ("namespace_ino", 3),
                           ("boot_id", "bad"), ("schema_version", True), ("valid", False),
                           ("overflow", True), ("diagnostic_only", 1), ("trace_kind", "path"),
                           ("clock", "realtime"), ("events", [])):
            sidecar, base = fixture()
            sidecar[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate(sidecar, base, "client")

    def test_invalid_event_shapes_and_ids_fail(self):
        for index, key, value in ((0, "stage", "packet_received"), (0, "connection", 0),
                                  (0, "stream", 0), (1, "connection", None),
                                  (1, "connection", True), (1, "stream", None),
                                  (1, "stream", -1), (1, "stream", 1 << 64),
                                  (1, "time_ns", 119), (1, "time_ns", True)):
            sidecar, base = fixture()
            sidecar["events"][index][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate(sidecar, base, "client")
        for target in ("top", "event"):
            sidecar, base = fixture()
            (sidecar if target == "top" else sidecar["events"][0])["payload"] = "forbidden"
            with self.assertRaises(ValueError):
                validate(sidecar, base, "client")

    def test_capacity_and_invalid_paired_trace_fail(self):
        sidecar, base = fixture()
        sidecar["events"] = [sidecar["events"][0]] * 65_537
        with self.assertRaises(ValueError):
            validate(sidecar, base, "client")
        sidecar, base = fixture()
        base["valid"] = False
        with self.assertRaises(ValueError):
            validate(sidecar, base, "client")

    def test_cli_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sidecar, base = fixture()
            for name, value in (("io", sidecar), ("base", base)):
                (root / name).write_text(json.dumps(value))
            result = subprocess.run([sys.executable, "-B", str(Path(__file__).with_name(
                "validate_io_trace.py")), str(root / "io"), str(root / "base"), "client"],
                capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(result.stdout)["event_count"], 2)
            (root / "io").write_text('{"pid":1,"pid":2}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load(root / "io")
            with patch("validate_io_trace.MAX_JSON_BYTES", 5):
                with self.assertRaisesRegex(ValueError, "bounded"):
                    load(root / "io")


if __name__ == "__main__":
    unittest.main()
