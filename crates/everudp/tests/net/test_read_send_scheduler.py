import copy
import unittest

from analyze_read_send_scheduler import analyze
from test_io_trial_windows import fixture as io_fixture
from test_syscall_pairs import event


def fixture():
    result, trace, capture = io_fixture()
    result.update(trials=1, samples_us=[1], public_boundaries=[
        {"trial": 0, "send_ns": 10, "accepted_ns": 90}])
    trace = {"schema_version": 1, "events": [
        event(0, "exit_poll", {"ret": 0}),
        event(20, "enter_read", {"fd": 0, "count": 1}), event(25, "exit_read", {"ret": 1}),
        event(30, "enter_sendmsg", {"fd": 7, "flags": 0}), event(35, "exit_sendmsg", {"ret": 75}),
        event(60, "enter_write", {"fd": 1, "count": 1}), event(65, "exit_write", {"ret": 1}),
        event(100, "enter_poll", {"nfds": 4, "timeout_msecs": -1}),
    ]}
    scheduler = {"schema_version": 1, "clock": "CLOCK_MONOTONIC", "pid": 42,
                 "events": [{"time_ns": 1, "prev_pid": 0, "next_pid": 42},
                             {"time_ns": 100, "prev_pid": 42, "next_pid": 0}]}
    return result, trace, capture, scheduler


class ReadSendSchedulerTests(unittest.TestCase):
    def test_no_switch_is_running_for_entire_edge(self):
        result, trace, capture, scheduler = fixture()
        report = analyze(result, trace, capture, scheduler)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual(report["rows"][0]["scheduled_wall_ns"], 5)
        self.assertEqual(report["rows"][0]["off_cpu_ns"], 0)

    def test_one_and_multiple_out_in_pairs_sum_off_cpu(self):
        result, trace, capture, scheduler = fixture()
        trace["events"][3] = event(40, "enter_sendmsg", {"fd": 7, "flags": 0})
        trace["events"][4] = event(45, "exit_sendmsg", {"ret": 75})
        scheduler["events"] = [
            {"time_ns": 1, "prev_pid": 0, "next_pid": 42},
            {"time_ns": 26, "prev_pid": 42, "next_pid": 0},
            {"time_ns": 28, "prev_pid": 0, "next_pid": 42},
            {"time_ns": 29, "prev_pid": 42, "next_pid": 7},
            {"time_ns": 30, "prev_pid": 7, "next_pid": 42},
            {"time_ns": 100, "prev_pid": 42, "next_pid": 0},
        ]
        report = analyze(result, trace, capture, scheduler)
        self.assertEqual(report["rows"][0]["off_cpu_ns"], 3)
        self.assertEqual(report["rows"][0]["scheduled_wall_ns"], 12)

    def test_wrong_pid_clock_schema_and_bool_fail_closed(self):
        result, trace, capture, scheduler = fixture()
        mutations = []
        bad = copy.deepcopy(scheduler); bad["pid"] = 43; mutations.append(bad)
        bad = copy.deepcopy(scheduler); bad["clock"] = "CLOCK_REALTIME"; mutations.append(bad)
        bad = copy.deepcopy(scheduler); bad["extra"] = 1; mutations.append(bad)
        bad = copy.deepcopy(scheduler); bad["events"][0]["time_ns"] = True; mutations.append(bad)
        bad = copy.deepcopy(scheduler); bad["events"][0]["prev_pid"] = True; mutations.append(bad)
        for bad in mutations:
            with self.subTest(scheduler=bad):
                self.assertEqual(analyze(result, trace, capture, bad)["status"], "UNKNOWN")

    def test_incomplete_or_impossible_chain_is_unknown_whole_report(self):
        result, trace, capture, scheduler = fixture()
        scheduler["events"] = [
            {"time_ns": 1, "prev_pid": 0, "next_pid": 42},
            {"time_ns": 26, "prev_pid": 42, "next_pid": 0},
            {"time_ns": 100, "prev_pid": 42, "next_pid": 0},
        ]
        report = analyze(result, trace, capture, scheduler)
        self.assertEqual(report["status"], "UNKNOWN")

    def test_switch_at_read_or_send_boundary_is_unknown(self):
        result, trace, capture, scheduler = fixture()
        scheduler["events"] = [
            {"time_ns": 1, "prev_pid": 0, "next_pid": 42},
            {"time_ns": 25, "prev_pid": 42, "next_pid": 0},
            {"time_ns": 30, "prev_pid": 0, "next_pid": 42},
            {"time_ns": 100, "prev_pid": 42, "next_pid": 0},
        ]
        self.assertEqual(analyze(result, trace, capture, scheduler)["status"], "UNKNOWN")

    def test_medians_use_final_scheduler_included_rows_only(self):
        result, trace, capture, scheduler = fixture()
        result.update(trials=2, samples_us=[1, 1], public_boundaries=[
            {"trial": 0, "send_ns": 10, "accepted_ns": 90},
            {"trial": 1, "send_ns": 110, "accepted_ns": 190}])
        trace["events"] = [
            event(0, "exit_poll", {"ret": 0}),
            event(20, "enter_read", {"fd": 0, "count": 1}), event(25, "exit_read", {"ret": 1}),
            event(30, "enter_sendmsg", {"fd": 7, "flags": 0}), event(35, "exit_sendmsg", {"ret": 75}),
            event(60, "enter_write", {"fd": 1, "count": 1}), event(65, "exit_write", {"ret": 1}),
            event(120, "enter_read", {"fd": 0, "count": 1}), event(125, "exit_read", {"ret": 1}),
            event(150, "enter_sendmsg", {"fd": 7, "flags": 0}), event(160, "exit_sendmsg", {"ret": 75}),
            event(170, "enter_write", {"fd": 1, "count": 1}), event(180, "exit_write", {"ret": 1}),
            event(200, "enter_poll", {"nfds": 4, "timeout_msecs": -1}),
        ]
        scheduler["events"] = [
            {"time_ns": 1, "prev_pid": 0, "next_pid": 42},
            {"time_ns": 100, "prev_pid": 42, "next_pid": 0},
        ]
        report = analyze(result, trace, capture, scheduler)
        self.assertEqual(report["included_trials"], 1)
        self.assertEqual(report["median_durations_ns"]["stdin_exit_to_first_successful_send_enter"], 5)
        self.assertEqual(report["rows"][1]["exclusion"], "outside_scheduler_coverage")

    def test_outside_scheduler_coverage_is_explicit_exclusion(self):
        result, trace, capture, scheduler = fixture()
        scheduler["events"] = [
            {"time_ns": 26, "prev_pid": 0, "next_pid": 42},
            {"time_ns": 30, "prev_pid": 42, "next_pid": 0},
        ]
        report = analyze(result, trace, capture, scheduler)
        self.assertEqual(report["status"], "DIAGNOSTIC")
        self.assertEqual(report["rows"][0]["exclusion"], "outside_scheduler_coverage")

    def test_existing_io_exclusion_is_preserved(self):
        result, trace, capture, scheduler = fixture()
        trace["events"][5] = event(60, "enter_write", {"fd": 2, "count": 1})
        report = analyze(result, trace, capture, scheduler)
        self.assertEqual(report["rows"][0]["exclusion"], "nonunique_terminal_edges")


if __name__ == "__main__":
    unittest.main()
