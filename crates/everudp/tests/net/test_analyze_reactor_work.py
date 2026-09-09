#!/usr/bin/env python3
"""Focused contract tests for analyze_reactor_work."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location("analyze_reactor_work", HERE / "analyze_reactor_work.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

IDENTITY = {
    "boot_id": "00000000-0000-0000-0000-000000000000",
    "time_namespace_dev": 5,
    "time_namespace_ino": 7,
}


def result() -> dict:
    boundaries = [
        {"trial": 0, "send_ns": 900, "accepted_ns": 1_060},
        {"trial": 1, "send_ns": 1_900, "accepted_ns": 2_060},
    ]
    return {
        "schema_version": 1,
        "public_clock": "CLOCK_MONOTONIC; local host and time namespace only",
        "clock_identity": copy.deepcopy(IDENTITY),
        "trials": 2,
        "public_boundaries": boundaries,
        "transcript_failures": 0,
        "samples_us": [(item["accepted_ns"] - item["send_ns"] + 999) // 1_000 for item in boundaries],
    }


def anchor(kind: str, sequence: int, begin: int) -> dict:
    return {
        "kind": "anchor",
        "anchor": kind,
        "sequence": sequence,
        "begin_time_ns": begin,
        "begin_cpu_time_ns": begin,
        "end_time_ns": begin,
        "end_cpu_time_ns": begin,
        "clock_valid": True,
    }


def step(phase: str, sequence: int, begin: int, end: int) -> dict:
    return {
        "kind": "step",
        "phase": phase,
        "sequence": sequence,
        "timer_due": phase == "retry_post_offer",
        "begin_time_ns": begin,
        "begin_cpu_time_ns": begin,
        "end_time_ns": end,
        "end_cpu_time_ns": end,
        "clock_valid": True,
        "pump_drive_calls": 1,
        "send_attempts": 1,
        "send_accepted": 1,
        "send_would_block": 0,
        "send_interrupted": 0,
        "receive_calls": 1,
        "receive_batches": 1,
        "receive_datagrams": 1,
        "receive_empty": 0,
        "receive_would_block": 0,
        "retained_gro_segments_delivered": 1,
        "overflow": False,
        "events_drained": 1,
        "application_ready": True,
        "pump": {
            "deferred_receives": 0,
            "deferred_receives_queued": 0,
            "timers_handled": 0,
            "endpoint_events": 0,
            "application_events_enqueued": 1,
            "transmits_generated": 1,
            "connections_retired": 0,
            "overflow": False,
        },
        "result": {"work": 1, "exhausted": False, "write_blocked": False},
    }


def trace() -> dict:
    events = [
        anchor("input_read", 0, 100),
        step("initial_post_offer", 0, 110, 120),
        step("loop_top", 0, 130, 140),
        anchor("sink_accepted", 0, 150),
        anchor("input_read", 1, 1_000),
        step("initial_post_offer", 1, 1_010, 1_020),
        step("loop_top", 1, 1_030, 1_040),
        anchor("sink_accepted", 1, 1_050),
        anchor("input_read", 2, 2_000),
        step("loop_top", 2, 2_010, 2_020),
        step("loop_top", 2, 2_030, 2_040),
        step("retry_post_offer", 2, 2_045, 2_050),
        step("loop_top", 2, 2_050, 2_060),
        anchor("sink_accepted", 2, 2_060),
    ]
    return {
        "schema_version": 1,
        "protocol": "everudp-reactor-work-v1",
        "diagnostic_only": True,
        "wall_clock": "CLOCK_MONOTONIC",
        "cpu_clock": "CLOCK_THREAD_CPUTIME_ID",
        "sample_order": "wall_then_cpu_not_simultaneous",
        "valid": True,
        "run_succeeded": True,
        "capacity": 8192,
        "overflow": False,
        "identity": {"pid": 42, "tid": 43, **IDENTITY},
        "cpu_clock_calibration_ns": [1] * 16,
        "events": events,
    }


class ReactorWorkAnalyzerTests(unittest.TestCase):
    def test_every_counter_rejects_boolean_negative_and_overflow_values(self) -> None:
        candidate = trace()["events"][1]
        for section in (None, "pump", "result"):
            fields = candidate if section is None else candidate[section]
            for field, value in fields.items():
                if type(value) is not int:
                    continue
                for invalid in (True, -1, 1 << 64):
                    malformed = trace()
                    target = malformed["events"][1]
                    if section is not None:
                        target = target[section]
                    target[field] = invalid
                    with self.subTest(section=section, field=field, invalid=invalid):
                        self.assertEqual(MODULE.analyze(result(), malformed)["status"], "UNKNOWN")

    def test_independent_validity_and_capacity_failures(self) -> None:
        for field, invalid in (("capacity", 1), ("capacity", 8193),
                               ("cpu_clock_calibration_ns", [1] * 15),
                               ("schema_version", True), ("valid", False),
                               ("diagnostic_only", False), ("overflow", True)):
            malformed = trace()
            malformed[field] = invalid
            with self.subTest(field=field):
                self.assertEqual(MODULE.analyze(result(), malformed)["status"], "UNKNOWN")
        malformed = trace()
        malformed["events"][1]["pump"]["overflow"] = True
        self.assertEqual(MODULE.analyze(result(), malformed)["status"], "UNKNOWN")

    def test_canonical_shape_reports_initial_pair_and_retry_sequence(self) -> None:
        report = MODULE.analyze(result(), trace())
        self.assertEqual(report["status"], "DIAGNOSTIC")
        self.assertEqual(report["included_sequences"], 1)
        self.assertEqual(len(report["initial_post_offer_pairs"]), 1)
        pair = report["initial_post_offer_pairs"][0]
        self.assertEqual(pair["sequence"], 1)
        self.assertEqual(pair["wall_ns"], 10)
        self.assertEqual(pair["following_loop_top"]["duration_ns"], {"wall": 10, "thread_cpu": 10})
        self.assertEqual(report["rows"][1]["steps"], 4)
        self.assertEqual(report["rows"][1]["exclusion"], "initial_offer_blocked")

    def test_exact_schema_rejects_unknown_fields_and_bool_as_int(self) -> None:
        unknown = trace()
        unknown["extra"] = 1
        self.assertEqual(MODULE.analyze(result(), unknown)["status"], "UNKNOWN")
        boolean_integer = trace()
        boolean_integer["events"][1]["pump_drive_calls"] = True
        self.assertEqual(MODULE.analyze(result(), boolean_integer)["status"], "UNKNOWN")

    def test_identity_overflow_and_failed_run_are_rejected(self) -> None:
        wrong_identity = trace()
        wrong_identity["identity"]["boot_id"] = "11111111-1111-1111-1111-111111111111"
        self.assertEqual(MODULE.analyze(result(), wrong_identity)["status"], "UNKNOWN")
        overflow = trace()
        overflow["events"][1]["overflow"] = True
        self.assertEqual(MODULE.analyze(result(), overflow)["status"], "UNKNOWN")
        failed = trace()
        failed["run_succeeded"] = False
        self.assertEqual(MODULE.analyze(result(), failed)["status"], "UNKNOWN")

    def test_missing_sequence_and_nonoverlap_are_rejected(self) -> None:
        missing = trace()
        missing["events"] = missing["events"][:8]
        self.assertEqual(MODULE.analyze(result(), missing)["status"], "UNKNOWN")
        overlap = trace()
        overlap["events"][2]["begin_time_ns"] = 115
        overlap["events"][2]["begin_cpu_time_ns"] = 115
        self.assertEqual(MODULE.analyze(result(), overlap)["status"], "UNKNOWN")

    def test_initial_offer_must_be_followed_by_loop_top(self) -> None:
        malformed = trace()
        malformed["events"][2]["phase"] = "retry_post_offer"
        self.assertEqual(MODULE.analyze(result(), malformed)["status"], "UNKNOWN")

    def test_window_race_is_explicit_exclusion(self) -> None:
        raced = trace()
        # The sink anchor is after the public receiver accepted the byte; the
        # parser preserves this as a bounded exclusion, not a fabricated value.
        raced["events"][7]["begin_time_ns"] = 1_070
        raced["events"][7]["end_time_ns"] = 1_070
        raced["events"][7]["begin_cpu_time_ns"] = 1_070
        raced["events"][7]["end_cpu_time_ns"] = 1_070
        report = MODULE.analyze(result(), raced)
        self.assertEqual(report["status"], "DIAGNOSTIC")
        self.assertEqual(report["rows"][0]["status"], "excluded")
        self.assertEqual(report["rows"][0]["exclusion"], "event_outside_public_window")
        self.assertEqual(report["included_sequences"], 0)
        self.assertEqual(report["initial_post_offer_pairs"], [])

    def test_impossible_event_grammar_is_rejected(self) -> None:
        for change in ("anchor_interval", "late_initial", "retry_without_top", "no_steps"):
            malformed = trace()
            if change == "anchor_interval":
                malformed["events"][0]["end_time_ns"] += 1
            elif change == "late_initial":
                malformed["events"][5]["phase"] = "loop_top"
                malformed["events"][6]["phase"] = "initial_post_offer"
            elif change == "retry_without_top":
                malformed["events"][9]["phase"] = "retry_post_offer"
            else:
                del malformed["events"][5:7]
            with self.subTest(change=change):
                self.assertEqual(MODULE.analyze(result(), malformed)["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
