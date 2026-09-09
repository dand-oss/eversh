import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_analyze_path_trace import pair
from validate_packet_trace import load, validate


def packet(event, time_ns, values):
    return {"event": event, "time_ns": time_ns, "values": values}


def fixture(role="client"):
    base = copy.deepcopy(pair()[0] if role == "client" else pair()[1])
    # QUIC diagnostics contain control traffic as well as operation anchors.
    events = [
        packet("packet_transmit_accepted", 100, [4, 7, 1200, 0]),
        packet("packet_built", 101, [4, 7, 8, 3, 0, 1200, 1]),
        packet("stream_sent" if role == "client" else "stream_received",
               102, [4, 7, 8, 3, 2 if role == "client" else 3, 0, 14, 1]),
        packet("operation", 103, [4, 2 if role == "client" else 3, 1, 7,
                                  0x20 if role == "client" else 0x40, 0, 14]),
        packet("packet_protection_start", 104, [4, 7, 8, 3, 1]),
        packet("packet_protection_end", 105, [4, 7, 8, 3, 1]),
    ]
    sidecar = {
        "schema_version": 1,
        "trace_kind": "quic_packets",
        "diagnostic_only": True,
        "clock": "CLOCK_MONOTONIC",
        "valid": True,
        "overflow": False,
        "pid": base["pid"],
        "boot_id": base["boot_id"],
        "namespace_dev": base["namespace_dev"],
        "namespace_ino": base["namespace_ino"],
        "events": events,
    }
    return sidecar, base


class PacketTraceTests(unittest.TestCase):
    def test_zero_connection_handle_is_valid(self):
        sidecar, base = fixture()
        for event in sidecar["events"]:
            event["values"][0] = 0
        validate(sidecar, base, "client")

    def test_protocol_integer_boundaries(self):
        for index, field, value in ((1, 2, 1 << 62), (2, 2, 1 << 62),
                                    (1, 4, (1 << 62) - 1),
                                    (2, 5, (1 << 62) - 1),
                                    (3, 5, (1 << 62) - 1), (3, 6, 13),
                                    (0, 1, True), (0, 2, 1 << 64)):
            sidecar, base = fixture()
            sidecar["events"][index]["values"][field] = value
            with self.subTest(index=index, field=field, value=value), self.assertRaises(ValueError):
                validate(sidecar, base, "client")
        sidecar, base = fixture()
        sidecar["pid"] = base["pid"] = 1 << 32
        with self.assertRaises(ValueError):
            validate(sidecar, base, "client")

    def test_real_shaped_fixture_is_diagnostic_only_and_preserves_events(self):
        sidecar, base = fixture()
        original = copy.deepcopy(sidecar["events"])
        result = validate(sidecar, base, "client")
        self.assertEqual(result["status"], "DIAGNOSTIC")
        self.assertFalse(result["qualification"])
        self.assertEqual(result["event_count"], 6)
        self.assertEqual(result["first_ns"], 100)
        self.assertEqual(result["last_ns"], 105)
        self.assertEqual(sidecar["events"], original)

    def test_gateway_output_role_and_counts(self):
        sidecar, base = fixture("gateway")
        self.assertEqual(validate(sidecar, base, "gateway")["stage_counts"]["operation"], 1)

    def test_identity_status_and_unknown_fields_rejected(self):
        for field, value in (("pid", 12), ("pid", True), ("boot_id", "bad"),
                             ("namespace_dev", 9), ("diagnostic_only", 1),
                             ("valid", False), ("overflow", True),
                             ("clock", "CLOCK_REALTIME"),
                             ("trace_kind", "path"), ("schema_version", True)):
            sidecar, base = fixture()
            sidecar[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate(sidecar, base, "client")
        sidecar, base = fixture()
        sidecar["events"][0]["extra"] = 1
        with self.assertRaises(ValueError):
            validate(sidecar, base, "client")
        sidecar, base = fixture()
        sidecar["events"][0]["event"] = "not_known"
        with self.assertRaises(ValueError):
            validate(sidecar, base, "client")

    def test_boolean_arity_overflow_cookie_and_clock_rejected(self):
        changes = [
            (0, "time_ns", True),
            (0, "values", [1]),
            (0, "values", [4, 0, 1200, 0]),
            (1, "values", [4, 7, 8, 4, 0, 1200, 1]),
            (1, "values", [4, 7, 8, 3, 0, 1200, 2]),
            (2, "values", [4, 7, 8, 3, 1 << 62, 0, 14, 1]),
            (2, "values", [4, 7, 8, 3, 2, 0, 0, 0]),
            (3, "values", [4, 2, 1, 7, 0x40, 0, 14]),
        ]
        for index, field, value in changes:
            sidecar, base = fixture()
            sidecar["events"][index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                validate(sidecar, base, "client")
        sidecar, base = fixture()
        sidecar["events"][1]["time_ns"] = 99
        with self.assertRaises(ValueError):
            validate(sidecar, base, "client")

    def test_invalid_markers_and_capacity_rejected(self):
        for marker in ("unsupported_path", "packet_trace_invalid"):
            sidecar, base = fixture()
            sidecar["events"] = [packet(marker, 104, [1, 2, 3] if marker == "unsupported_path" else [])]
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                validate(sidecar, base, "client")
        sidecar, base = fixture()
        sidecar["events"] = [sidecar["events"][0]] * 65_537
        with self.assertRaises(ValueError):
            validate(sidecar, base, "client")

    def test_direction_and_operation_stream_contract(self):
        sidecar, base = fixture()
        sidecar["events"][1]["values"][-1] = 2
        with self.assertRaises(ValueError):
            validate(sidecar, base, "client")
        sidecar, base = fixture()
        sidecar["events"][3]["values"][1] = 3
        with self.assertRaises(ValueError):
            validate(sidecar, base, "client")
        sidecar, base = fixture("gateway")
        sidecar["events"][3]["values"][4] = 0x20
        with self.assertRaises(ValueError):
            validate(sidecar, base, "gateway")

    def test_packet_protection_contract(self):
        for field, value in ((1, 0), (2, 1 << 62), (3, 4), (4, 2)):
            sidecar, base = fixture()
            sidecar["events"][4]["values"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate(sidecar, base, "client")
        sidecar, base = fixture()
        sidecar["events"][4]["values"] = [4, 7, 8, 3]
        with self.assertRaises(ValueError):
            validate(sidecar, base, "client")

    def test_duplicate_keys_and_file_limit_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.json"
            path.write_text('{"event":1,"event":2}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load(path)
            path.write_text("{}")
            with patch("validate_packet_trace.MAX_JSON_BYTES", 1):
                path.write_text("{}")
                with self.assertRaisesRegex(ValueError, "bounded"):
                    load(path)


if __name__ == "__main__":
    unittest.main()
