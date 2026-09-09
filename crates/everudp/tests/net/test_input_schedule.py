#!/usr/bin/env python3
"""Strict tests for scheduler-chain attribution."""

from __future__ import annotations

import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import analyze_input_schedule as schedule  # noqa: E402
from test_floor_attribution import fixture as floor_fixture


IDENTITY = {"boot_id": "01234567-89ab-cdef-0123-456789abcdef", "time_namespace_dev": 11, "time_namespace_ino": 22}
PID = 42


def fixture() -> tuple[dict, dict, dict]:
    result, client, server = floor_fixture(1)
    result["clock_identity"] = copy.deepcopy(IDENTITY)
    result["public_boundaries"] = [{"trial": 0, "send_ns": 1_000, "accepted_ns": 1_200}]
    client["trace"]["pid"] = PID
    for event in client["trace"]["events"]:
        if event["elapsed_ns"] >= 20:
            event["elapsed_ns"] += 10
    client["trace"]["clock_alignment"] = {
        "valid": True, "clock": "CLOCK_MONOTONIC", "identity": copy.deepcopy(IDENTITY),
        "start": {"elapsed_ns": 0, "lower_ns": 1_000, "upper_ns": 1_000},
        "end": {"elapsed_ns": 500, "lower_ns": 1_500, "upper_ns": 1_500},
    }
    return result, client, server


def line(seconds_ns: int, kind: str, body: str) -> str:
    seconds, fraction = divmod(seconds_ns, 1_000_000_000)
    return f"{seconds}.{fraction:09d}: sched:{kind}: {body}"


def chain(start: int = 1_010) -> str:
    wake = "comm=everudp-floor pid=42 prio=120 target_cpu=040"
    switch = "prev_comm=swapper/40 prev_pid=0 prev_prio=120 prev_state=R ==> next_comm=everudp-floor next_pid=42 next_prio=120"
    return "\n".join([
        line(start, "sched_waking", wake),
        line(start + 10, "sched_wakeup", wake),
        line(start + 20, "sched_switch", switch),
    ])


def coverage_prefix() -> str:
    switch_out = "prev_comm=everudp-floor prev_pid=42 prev_prio=120 prev_state=S ==> next_comm=swapper/40 next_pid=0 next_prio=120"
    return line(900, "sched_switch", switch_out)


class InputScheduleTests(unittest.TestCase):
    def test_task_names_may_contain_spaces(self) -> None:
        result, client, server = fixture()
        text = (coverage_prefix() + "\n" + chain()).replace("swapper/40", "CPU 3/KVM")
        report = schedule.analyze(result, client, server, text, PID)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual(report["covered_rows"], 1)
        bad = text.replace("CPU 3/KVM", "x" * 17)
        self.assertEqual(schedule.analyze(result, client, server, bad, PID)["status"], "UNKNOWN")

    def test_positive_chain_reports_direct_interval(self) -> None:
        result, client, server = fixture()
        report = schedule.analyze(result, client, server, coverage_prefix() + "\n" + chain(), PID)
        self.assertEqual(report["status"], "DIAGNOSTIC")
        self.assertEqual(report["covered_rows"], 1)
        row = report["rows"][0]
        self.assertEqual(row["status"], "included")
        self.assertEqual(row["intervals_ns"]["send_to_switchin"], 30)
        self.assertEqual(row["intervals_ns"]["switchin_to_read"], {"lower": 0, "upper": 0})
        self.assertFalse(report["independently_verified"])

    def test_outside_coverage_is_explicit_and_retained(self) -> None:
        result, client, server = fixture()
        report = schedule.analyze(result, client, server, chain(2_000), PID)
        self.assertEqual(report["status"], "DIAGNOSTIC")
        self.assertEqual(len(report["rows"]), 1)
        self.assertEqual(report["rows"][0]["exclusion"], "outside_coverage")

    def test_extra_transition_is_ambiguous(self) -> None:
        result, client, server = fixture()
        extra = line(1_025, "sched_waking", "comm=everudp-floor pid=42 prio=120 target_cpu=040")
        text = "\n".join(sorted((coverage_prefix() + "\n" + chain() + "\n" + extra).splitlines()))
        report = schedule.analyze(result, client, server, text, PID)
        self.assertEqual(report["rows"][0]["exclusion"], "ambiguous_chain")
        self.assertEqual(report["rows"][0]["scheduler_kinds"], ["waking", "wakeup", "waking", "switch_in"])

    def test_malformed_and_wrong_pid_fail_closed(self) -> None:
        result, client, server = fixture()
        report = schedule.analyze(result, client, server, "garbage", PID)
        self.assertEqual(report["status"], "UNKNOWN")
        wrong = chain().replace("pid=42", "pid=43")
        report = schedule.analyze(result, client, server, wrong, PID)
        self.assertEqual(report["status"], "UNKNOWN")

    def test_regressing_scheduler_clock_fails_closed(self) -> None:
        result, client, server = fixture()
        text = chain()
        lines = text.splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        report = schedule.analyze(result, client, server, "\n".join(lines), PID)
        self.assertEqual(report["status"], "UNKNOWN")

    def test_target_pid_mismatch_fails_closed(self) -> None:
        result, client, server = fixture()
        report = schedule.analyze(result, client, server, chain(), 99)
        self.assertEqual(report["status"], "UNKNOWN")

    def test_read_clock_uncertainty_boundary_is_ambiguous(self) -> None:
        result, client, server = fixture()
        client["trace"]["clock_alignment"]["start"] = {
            "elapsed_ns": 0, "lower_ns": 1_000, "upper_ns": 1_050,
        }
        client["trace"]["clock_alignment"]["end"] = {
            "elapsed_ns": 500, "lower_ns": 1_510, "upper_ns": 1_560,
        }
        # The fixture's switch-in is at 1,030, while read.lower is 1,040;
        # place an additional target transition inside the uncertainty tail.
        wake = "comm=everudp-floor pid=42 prio=120 target_cpu=040"
        switch_out = "prev_comm=everudp-floor prev_pid=42 prev_prio=120 prev_state=S ==> next_comm=swapper/40 next_pid=0 next_prio=120"
        text = coverage_prefix() + "\n" + chain() + "\n" + line(1_050, "sched_waking", wake) + "\n" + line(1_100, "sched_switch", switch_out)
        report = schedule.analyze(result, client, server, text, PID)
        self.assertEqual(report["rows"][0]["exclusion"], "ambiguous_chain")

    def test_covered_gap_is_ambiguous_not_outside(self) -> None:
        result, client, server = fixture()
        wake = "comm=everudp-floor pid=42 prio=120 target_cpu=040"
        switch_out = "prev_comm=everudp-floor prev_pid=42 prev_prio=120 prev_state=S ==> next_comm=swapper/40 next_pid=0 next_prio=120"
        text = "\n".join([line(900, "sched_switch", switch_out), line(2_000, "sched_waking", wake)])
        report = schedule.analyze(result, client, server, text, PID)
        self.assertEqual(report["rows"][0]["exclusion"], "ambiguous_chain")

    def test_existing_floor_validation_is_required(self) -> None:
        result, client, server = fixture()
        result["transcript_failures"] = 1
        report = schedule.analyze(result, client, server, chain(), PID)
        self.assertEqual(report["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
