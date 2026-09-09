import copy
import unittest

from analyze_poll_turns import analyze


def fixture():
    result = {
        "trials": 2,
        "samples_us": [1, 1],
        "transcript_failures": 0,
        "public_clock": "CLOCK_MONOTONIC; local host and time namespace only",
        "public_boundaries": [
            {"trial": 0, "send_ns": 100, "accepted_ns": 200},
            {"trial": 1, "send_ns": 300, "accepted_ns": 500},
        ],
    }
    lines = [
        "0.000000050: syscalls:sys_exit_read: 0x0",
        "0.000000110: syscalls:sys_enter_poll: nfds: 0x00000004, timeout_msecs: 0x00000000",
        "0.000000120: syscalls:sys_exit_poll: 0x0",
        "0.000000130: syscalls:sys_enter_poll: nfds: 0x00000004, timeout_msecs: 0x00000005",
        "0.000000150: syscalls:sys_exit_poll: 0x0",
        "0.000000320: syscalls:sys_enter_poll: nfds: 0x00000004, timeout_msecs: 0xffffffffffffffff",
        "0.000000340: syscalls:sys_exit_poll: 0x0",
        "0.000000550: syscalls:sys_enter_read: fd: 0x0, count: 0x1000",
    ]
    return result, lines


class PollTurnTests(unittest.TestCase):
    def test_read_context_cannot_overlap_poll_or_have_an_orphan_exit(self):
        result, _ = fixture()
        cases = [
            ["0.000000050: syscalls:sys_enter_read: fd: 0x0, count: 0x1",
             "0.000000110: syscalls:sys_enter_poll: nfds: 0x4, timeout_msecs: 0x0",
             "0.000000120: syscalls:sys_exit_poll: 0x0"],
            ["0.000000050: syscalls:sys_exit_read: 0x0",
             "0.000000110: syscalls:sys_exit_read: 0x0"],
        ]
        for lines in cases:
            self.assertEqual(analyze(result, "\n".join(lines), 42)["status"], "UNKNOWN")

    def test_multiple_calls_and_zero_timeout_count(self):
        result, lines = fixture()
        report = analyze(result, "\n".join(lines), 42)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual(report["rows"][0]["poll_calls"], 2)
        self.assertEqual(report["rows"][0]["zero_timeout_polls"], 1)
        self.assertEqual(report["rows"][0]["zero_poll_syscall_ns"], 10)
        self.assertEqual(report["rows"][0]["total_poll_syscall_ns"], 30)
        self.assertEqual(report["rows"][1]["zero_timeout_polls"], 0)
        self.assertEqual(report["rows"][1]["zero_poll_syscall_ns"], 0)
        self.assertEqual(report["rows"][1]["total_poll_syscall_ns"], 20)
        self.assertEqual(report["aggregate"]["median_zero_timeout_polls"], 0.5)
        self.assertEqual(report["aggregate"]["median_zero_poll_syscall_ns"], 5)

    def test_no_polls_is_an_included_zero_row(self):
        result, _ = fixture()
        lines = [
            "0.000000050: syscalls:sys_exit_read: 0x0",
            "0.000000240: syscalls:sys_enter_read: fd: 0x0, count: 0x1000",
            "0.000000250: syscalls:sys_exit_read: 0x0",
            "0.000000300: syscalls:sys_enter_read: fd: 0x0, count: 0x1000",
            "0.000000550: syscalls:sys_exit_read: 0x0",
        ]
        report = analyze(result, "\n".join(lines), 42)
        self.assertEqual(report["rows"][0]["status"], "included")
        self.assertEqual(report["rows"][0]["zero_timeout_polls"], 0)
        self.assertEqual(report["rows"][0]["zero_poll_syscall_ns"], 0)

    def test_nonzero_poll_spanning_boundary_does_not_hide_zero_turn(self):
        result = {
            "trials": 1,
            "samples_us": [1],
            "transcript_failures": 0,
            "public_clock": "CLOCK_MONOTONIC; local host and time namespace only",
            "public_boundaries": [{"trial": 0, "send_ns": 100, "accepted_ns": 300}],
        }
        lines = [
            "0.000000050: syscalls:sys_exit_read: 0x0",
            "0.000000090: syscalls:sys_enter_poll: nfds: 0x4, timeout_msecs: 0x00000005",
            "0.000000210: syscalls:sys_exit_poll: 0x0",
            "0.000000220: syscalls:sys_enter_poll: nfds: 0x4, timeout_msecs: 0x00000000",
            "0.000000230: syscalls:sys_exit_poll: 0x0",
            "0.000000550: syscalls:sys_enter_read: fd: 0x0, count: 0x1000",
        ]
        report = analyze(result, "\n".join(lines), 42)
        self.assertEqual(report["rows"][0]["status"], "included")
        self.assertEqual(report["rows"][0]["zero_timeout_polls"], 1)
        self.assertEqual(report["rows"][0]["zero_poll_syscall_ns"], 10)

    def test_spanning_boundary_is_excluded(self):
        result, _ = fixture()
        lines = [
            "0.000000050: syscalls:sys_exit_read: 0x0",
            "0.000000190: syscalls:sys_enter_poll: nfds: 0x4, timeout_msecs: 0x0",
            "0.000000220: syscalls:sys_exit_poll: 0x0",
            "0.000000550: syscalls:sys_enter_read: fd: 0x0, count: 0x1000",
        ]
        report = analyze(result, "\n".join(lines), 42)
        self.assertEqual(report["rows"][0]["exclusion"], "poll_spans_boundary")
        self.assertEqual(report["rows"][1]["status"], "included")

    def test_capture_edge_is_explicitly_excluded(self):
        result, _ = fixture()
        lines = [
            "0.000000110: syscalls:sys_exit_poll: 0x0",
            "0.000000120: syscalls:sys_enter_poll: nfds: 0x4, timeout_msecs: 0x0",
            "0.000000130: syscalls:sys_exit_poll: 0x0",
            "0.000000550: syscalls:sys_enter_read: fd: 0x0, count: 0x1000",
        ]
        report = analyze(result, "\n".join(lines), 42)
        self.assertEqual(report["rows"][0]["exclusion"], "outside_coverage")

    def test_fail_closed_malformed_lost_regression_overlap_and_oracle(self):
        result, lines = fixture()
        bad_texts = [
            "LOST 1",
            "\n".join(reversed(lines)),
            "\n".join(lines[:2] + [lines[2], lines[2]] + lines[3:]),
            "\n".join(lines).replace("timeout_msecs: 0x00000000", "timeout_msecs: nope"),
            "\n".join(lines).replace("nfds: 0x00000004", "nfds: nope"),
        ]
        for text in bad_texts:
            self.assertEqual(analyze(result, text, 42)["status"], "UNKNOWN")
        bad = copy.deepcopy(result)
        bad["transcript_failures"] = 1
        self.assertEqual(analyze(bad, "\n".join(lines), 42)["status"], "UNKNOWN")
        bad = copy.deepcopy(result)
        bad["samples_us"] = [2, 1]
        self.assertEqual(analyze(bad, "\n".join(lines), 42)["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
