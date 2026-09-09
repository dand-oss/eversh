import copy
import unittest

from io_trial_windows import analyze, analyze_client
from test_syscall_pairs import fixture as trace_fixture
from test_syscall_pairs import event


def fixture():
    boot = "a379fc1e-ec8d-4f5c-afaa-4bbe88d1fced"
    result = {"trials": 2, "samples_us": [1, 1], "transcript_failures": 0,
              "public_clock": "CLOCK_MONOTONIC; local host and time namespace only",
              "clock_identity": {"boot_id": boot, "time_namespace_dev": 5, "time_namespace_ino": 7},
              "public_boundaries": [{"trial": 0, "send_ns": 25, "accepted_ns": 55},
                                    {"trial": 1, "send_ns": 70, "accepted_ns": 90}]}
    capture = {"status": "DIAGNOSTIC", "clock": "CLOCK_MONOTONIC", "identity": {
        "pid": 42, "tids": [42], "boot_id": boot, "time_namespace": [5, 7]}}
    return result, trace_fixture(), capture


class IoTrialWindowTests(unittest.TestCase):
    def test_client_edges_exclude_eagain_and_keep_first_success(self):
        result, _, capture = fixture()
        result.update(trials=1, samples_us=[1], public_boundaries=[
            {"trial": 0, "send_ns": 10, "accepted_ns": 90}])
        trace = {"schema_version": 1, "events": [
            event(0, "exit_poll", {"ret": 0}),
            event(20, "enter_read", {"fd": 0, "count": 1}), event(25, "exit_read", {"ret": 1}),
            event(30, "enter_sendmsg", {"fd": 7, "flags": 0}), event(35, "exit_sendmsg", {"ret": -11}),
            event(40, "enter_sendmsg", {"fd": 7, "flags": 0}), event(45, "exit_sendmsg", {"ret": 75}),
            event(50, "enter_sendmsg", {"fd": 7, "flags": 0}), event(55, "exit_sendmsg", {"ret": 44}),
            event(60, "enter_write", {"fd": 1, "count": 1}), event(65, "exit_write", {"ret": 1}),
            event(100, "enter_poll", {"nfds": 4, "timeout_msecs": -1}),
        ]}
        report = analyze_client(result, trace, capture)
        self.assertEqual(report["included_trials"], 1, report)
        self.assertEqual(report["median_durations_ns"], {
            "public_send_to_stdin_enter": 10, "stdin_exit_to_first_successful_send_enter": 15,
            "stdout_syscall": 5, "stdout_exit_to_public_accept": 25})
        self.assertEqual(report["rows"][0]["observed_successful_send_calls"], 2)
        for index, replacement, reason in (
            (9, event(60, "enter_write", {"fd": 2, "count": 1}), "nonunique_terminal_edges"),
            (7, event(50, "enter_sendmsg", {"fd": 8, "flags": 0}), "multiple_network_descriptors"),
        ):
            modified = copy.deepcopy(trace)
            modified["events"][index] = replacement
            excluded = analyze_client(result, modified, capture)
            self.assertEqual(excluded["included_trials"], 0)
            self.assertEqual(excluded["rows"][0]["exclusion"], reason)

    def test_client_edges_use_explicit_descriptor_aliases(self):
        result, _, capture = fixture()
        result.update(trials=1, samples_us=[1], public_boundaries=[
            {"trial": 0, "send_ns": 10, "accepted_ns": 90}])
        capture["terminal_fds"] = {"stdin": [12, 14], "stdout": [13, 15]}
        trace = {"schema_version": 1, "events": [
            event(0, "exit_poll", {"ret": 0}),
            event(20, "enter_read", {"fd": 12, "count": 1}), event(25, "exit_read", {"ret": 1}),
            event(30, "enter_sendmsg", {"fd": 7, "flags": 0}), event(35, "exit_sendmsg", {"ret": 75}),
            event(60, "enter_write", {"fd": 15, "count": 1}), event(65, "exit_write", {"ret": 1}),
            event(100, "enter_poll", {"nfds": 4, "timeout_msecs": -1}),
        ]}
        report = analyze_client(result, trace, capture)
        self.assertEqual(report["included_trials"], 1, report)
        self.assertEqual(report["rows"][0]["durations_ns"]["public_send_to_stdin_enter"], 10)

    def test_malformed_aliases_and_unknown_descriptors_fail_closed(self):
        result, trace, capture = fixture()
        malformed = (
            None,
            {"stdin": [], "stdout": [1]},
            {"stdin": [0, True], "stdout": [1]},
            {"stdin": [0, 0], "stdout": [1]},
            {"stdin": [0], "stdout": [1], "extra": [2]},
            {"stdin": [0], "stdout": [1, -1]},
        )
        for aliases in malformed:
            with self.subTest(aliases=aliases):
                bad = copy.deepcopy(capture)
                bad["terminal_fds"] = aliases
                self.assertEqual(analyze_client(result, trace, bad)["status"], "UNKNOWN")
        bad = copy.deepcopy(capture)
        bad["terminal_fds"] = {"stdin": [12], "stdout": [13]}
        trace = {"schema_version": 1, "events": [
            event(0, "exit_poll", {"ret": 0}),
            event(20, "enter_read", {"fd": 0, "count": 1}), event(25, "exit_read", {"ret": 1}),
            event(60, "enter_write", {"fd": 1, "count": 1}), event(65, "exit_write", {"ret": 1}),
            event(100, "enter_poll", {"nfds": 4, "timeout_msecs": -1}),
        ]}
        result.update(trials=1, samples_us=[1], public_boundaries=[
            {"trial": 0, "send_ns": 10, "accepted_ns": 90}])
        report = analyze_client(result, trace, bad)
        self.assertEqual(report["included_trials"], 0)
        self.assertEqual(report["rows"][0]["exclusion"], "nonunique_terminal_edges")

    def test_crossing_calls_retained_and_eagain_not_successful(self):
        report = analyze(*fixture())
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual(report["included_trials"], 1)
        calls = report["rows"][0]["calls"]
        self.assertEqual(calls[0]["window_overlap_ns"], [25, 30])
        self.assertTrue(calls[0]["crosses_boundary"])
        self.assertFalse(calls[1]["successful"])
        self.assertEqual(report["rows"][1]["exclusion"], "outside_capture_coverage")

    def test_wrong_clocks_threads_or_oracle_fail_closed(self):
        result, trace, capture = fixture()
        for mutation in (lambda r, c: c["identity"].update(tids=[42, 43]),
                         lambda r, c: c["identity"].update(time_namespace=[5, 8]),
                         lambda r, c: r.update(transcript_failures=1),
                         lambda r, c: r.update(samples_us=[2, 1]),
                         lambda r, c: c.update(clock="CLOCK_REALTIME")):
            r, c = copy.deepcopy(result), copy.deepcopy(capture)
            mutation(r, c)
            self.assertEqual(analyze(r, trace, c)["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
