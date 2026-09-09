import copy
import unittest

from analyze_read_schedule import analyze


def fixture():
    result = {"trials": 1, "samples_us": [1], "transcript_failures": 0,
              "public_clock": "CLOCK_MONOTONIC; local host and time namespace only",
              "public_boundaries": [{"trial": 0, "send_ns": 100, "accepted_ns": 200}]}
    lines = [
        "0.000000090: sched:sched_switch: prev_comm=client prev_pid=42 prev_prio=120 prev_state=S ==> next_comm=idle next_pid=0 next_prio=120",
        "0.000000110: sched:sched_waking: comm=client pid=42 prio=120 target_cpu=001",
        "0.000000120: sched:sched_wakeup: comm=client pid=42 prio=120 target_cpu=001",
        "0.000000130: sched:sched_switch: prev_comm=idle prev_pid=0 prev_prio=120 prev_state=R ==> next_comm=client next_pid=42 next_prio=120",
        "0.000000140: syscalls:sys_enter_read: fd: 0x00000000, count: 0x00001000",
        "0.000000145:  syscalls:sys_exit_read: 0x1",
        "0.000000210: sched:sched_switch: prev_comm=client prev_pid=42 prev_prio=120 prev_state=S ==> next_comm=idle next_pid=0 next_prio=120",
    ]
    return result, lines


class ReadScheduleTests(unittest.TestCase):
    def test_exact_intervals(self):
        result, lines = fixture()
        report = analyze(result, "\n".join(lines), 42, 0)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual(report["rows"][0]["intervals_ns"], {
            "send_to_waking": 10, "waking_to_wakeup": 10, "wakeup_to_scheduled": 10,
            "send_to_scheduled": 30, "scheduled_to_read_enter": 10, "read_syscall": 5})

    def test_invalid_records_fail_closed(self):
        result, lines = fixture()
        for text in ("LOST 1", "\n".join(reversed(lines)),
                     "\n".join(lines).replace("pid=42", "pid=43"),
                     "\n".join(lines[:4] + lines[5:]),
                     "\n".join(lines).replace("sys_exit_read: 0x1", "sys_exit_read: 0x2000")):
            self.assertEqual(analyze(result, text, 42, 0)["status"], "UNKNOWN")

    def test_oracle_and_sample_validation(self):
        result, lines = fixture()
        for key, value in (("transcript_failures", 1), ("samples_us", [2]), ("samples_us", [True])):
            bad = copy.deepcopy(result)
            bad[key] = value
            self.assertEqual(analyze(bad, "\n".join(lines), 42, 0)["status"], "UNKNOWN")

    def test_coverage_and_descriptor_exclusions(self):
        result, lines = fixture()
        report = analyze(result, "\n".join(lines[1:]), 42, 0)
        self.assertEqual(report["rows"][0]["exclusion"], "outside_coverage")
        report = analyze(result, "\n".join(lines), 42, 13)
        self.assertEqual(report["rows"][0]["exclusion"], "ambiguous_read")

    def test_interrupted_chain_is_excluded(self):
        result, lines = fixture()
        lines.insert(4, lines[-1].replace("000000210", "000000135"))
        report = analyze(result, "\n".join(lines), 42, 0)
        self.assertEqual(report["rows"][0]["exclusion"], "ambiguous_scheduler_chain")
