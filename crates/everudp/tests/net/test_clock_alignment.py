#!/usr/bin/env python3
"""Strict unit tests for diagnostic local-clock handoff attribution."""

from __future__ import annotations

import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import clock_alignment as alignment  # noqa: E402


IDENTITY = {
    "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
    "time_namespace_dev": 11,
    "time_namespace_ino": 22,
}


def _event(elapsed: int, stage: str, sequence: int, thread: str = "ThreadId(1)") -> dict:
    return {
        "elapsed_ns": elapsed,
        "stage": stage,
        "sequence": sequence,
        "thread": thread,
    }


def fixture(trials: int = 2) -> tuple[dict, dict]:
    result = {
        "schema_version": 1,
        "trials": trials,
        "public_clock": "CLOCK_MONOTONIC; local host and time namespace only",
        "clock_identity": copy.deepcopy(IDENTITY),
        "public_boundaries": [
            {"trial": index, "send_ns": 1_050 + index * 150, "accepted_ns": 1_150 + index * 150}
            for index in range(trials)
        ],
    }
    events = []
    for sequence in range(1, trials + 1):
        elapsed = 100 if sequence == 1 else 250
        events.extend([
            _event(elapsed, "terminal_read", sequence),
            _event(elapsed + 20, "sink_accepted", sequence),
        ])
    trace = {
        "clock_alignment": {
            "valid": True,
            "clock": "CLOCK_MONOTONIC",
            "identity": copy.deepcopy(IDENTITY),
            "start": {"elapsed_ns": 0, "lower_ns": 1_000, "upper_ns": 1_004},
            "end": {"elapsed_ns": 300, "lower_ns": 1_300, "upper_ns": 1_304},
        },
        "events": events,
    }
    return result, trace


class ClockAlignmentTests(unittest.TestCase):
    def test_known_positive_intervals_and_offset_uncertainty(self) -> None:
        result, client = fixture()
        report = alignment.analyze_handoffs(result, client)
        self.assertEqual(report["status"], "DIAGNOSTIC")
        self.assertEqual(report["clock_alignment"]["offset_ns"], {"lower": 1_000, "upper": 1_004})
        self.assertEqual(report["rows"][0]["input_handoff_ns"], {"lower": 50, "upper": 54})
        self.assertEqual(report["rows"][0]["output_handoff_ns"], {"lower": 26, "upper": 30})
        self.assertEqual(report["clock_alignment"]["uncertainty_ns"], 4)

    def test_absent_legacy_metadata_is_unavailable(self) -> None:
        result, client = fixture()
        del client["clock_alignment"]
        self.assertEqual(alignment.analyze_handoffs(result, client)["status"], "UNAVAILABLE")
        result, client = fixture()
        del result["clock_identity"]
        self.assertEqual(alignment.analyze_handoffs(result, client)["status"], "UNAVAILABLE")
        result, client = fixture()
        client["clock_alignment"]["start"] = None
        with self.assertRaises(ValueError):
            alignment.analyze_handoffs(result, client)

    def test_identity_mismatch_is_invalid(self) -> None:
        result, client = fixture()
        client["clock_alignment"]["identity"]["time_namespace_ino"] += 1
        with self.assertRaises(ValueError):
            alignment.analyze_handoffs(result, client)

    def test_malformed_anchor_fields_and_identity_fail_closed(self) -> None:
        for mutate in (
            lambda trace: trace["clock_alignment"].__setitem__("valid", False),
            lambda trace: trace["clock_alignment"].__setitem__("clock", "CLOCK_REALTIME"),
            lambda trace: trace["clock_alignment"]["start"].__setitem__("lower_ns", True),
            lambda trace: trace["clock_alignment"]["start"].__setitem__("upper_ns", 11_001),
            lambda trace: trace["clock_alignment"]["identity"].__setitem__("boot_id", "bad"),
        ):
            result, client = fixture()
            mutate(client)
            with self.assertRaises(ValueError):
                alignment.analyze_handoffs(result, client)

    def test_drift_or_disjoint_brackets_is_invalid(self) -> None:
        result, client = fixture()
        client["clock_alignment"]["end"] = {"elapsed_ns": 200, "lower_ns": 1_300, "upper_ns": 1_304}
        with self.assertRaises(ValueError):
            alignment.analyze_handoffs(result, client)

    def test_event_outside_anchor_is_invalid(self) -> None:
        result, client = fixture()
        client["events"].append(_event(301, "terminal_read", 99))
        with self.assertRaises(ValueError):
            alignment.analyze_handoffs(result, client)

    def test_negative_handoff_is_not_clamped(self) -> None:
        result, client = fixture()
        result["public_boundaries"][0]["send_ns"] = 1_105
        with self.assertRaisesRegex(ValueError, "handoff interval crosses zero"):
            alignment.analyze_handoffs(result, client)
        result, client = fixture()
        result["public_boundaries"][0]["accepted_ns"] = 1_110
        with self.assertRaisesRegex(ValueError, "handoff interval crosses zero"):
            alignment.analyze_handoffs(result, client)

    def test_offset_uses_intersection_not_midpoint(self) -> None:
        result, client = fixture()
        client["clock_alignment"]["end"]["lower_ns"] = 1_302
        client["clock_alignment"]["end"]["upper_ns"] = 1_306
        report = alignment.analyze_handoffs(result, client)
        self.assertEqual(report["clock_alignment"]["offset_ns"], {"lower": 1_002, "upper": 1_004})
        self.assertEqual(report["rows"][0]["input_handoff_ns"], {"lower": 52, "upper": 54})

    def test_duplicate_and_missing_public_sequence_are_invalid(self) -> None:
        result, client = fixture()
        client["events"].append(copy.deepcopy(client["events"][0]))
        with self.assertRaises(ValueError):
            alignment.analyze_handoffs(result, client)
        result, client = fixture()
        client["events"] = [event for event in client["events"] if event["sequence"] != 2]
        with self.assertRaises(ValueError):
            alignment.analyze_handoffs(result, client)

    def test_same_thread_and_order_are_required(self) -> None:
        result, client = fixture()
        client["events"][1]["thread"] = "ThreadId(2)"
        with self.assertRaises(ValueError):
            alignment.analyze_handoffs(result, client)
        result, client = fixture()
        client["events"][0]["elapsed_ns"], client["events"][1]["elapsed_ns"] = 80, 70
        with self.assertRaises(ValueError):
            alignment.analyze_handoffs(result, client)


if __name__ == "__main__":
    unittest.main()
