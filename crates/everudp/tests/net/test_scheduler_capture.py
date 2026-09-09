from pathlib import Path
import unittest

from scheduler_capture import (
    SCHEDULER_EVENTS,
    sanitize_scheduler,
    scheduler_command,
    validate_attributes,
)


ATTRIBUTES = """sched:sched_waking: type: 2 (PERF_TYPE_TRACEPOINT), size: 144, config: 0x139 (sched:sched_waking), { sample_period, sample_freq }: 1, sample_type: IP|TID|TIME|CPU|PERIOD|RAW|IDENTIFIER, read_format: ID|LOST, disabled: 1, sample_id_all: 1, use_clockid: 1, clockid: 1
sched:sched_wakeup: type: 2 (PERF_TYPE_TRACEPOINT), size: 144, config: 0x138 (sched:sched_wakeup), { sample_period, sample_freq }: 1, sample_type: IP|TID|TIME|CPU|PERIOD|RAW|IDENTIFIER, read_format: ID|LOST, disabled: 1, sample_id_all: 1, use_clockid: 1, clockid: 1
sched:sched_switch: type: 2 (PERF_TYPE_TRACEPOINT), size: 144, config: 0x136 (sched:sched_switch), { sample_period, sample_freq }: 1, sample_type: IP|TID|TIME|CPU|PERIOD|RAW|IDENTIFIER, read_format: ID|LOST, disabled: 1, sample_id_all: 1, use_clockid: 1, clockid: 1
dummy:u: type: 1 (PERF_TYPE_SOFTWARE), size: 144, config: 0x9 (PERF_COUNT_SW_DUMMY), { sample_period, sample_freq }: 1, sample_type: IP|TID|TIME|CPU|IDENTIFIER, read_format: ID|LOST, exclude_kernel: 1, exclude_hv: 1, mmap: 1, comm: 1, task: 1, sample_id_all: 1, exclude_guest: 1, mmap2: 1, comm_exec: 1, use_clockid: 1, ksymbol: 1, bpf_event: 1, build_id: 1, clockid: 1
# Tip: use 'perf evlist --trace-fields' to show fields for tracepoint events
"""


def event(seconds, kind, body):
    return f"{seconds}: sched:{kind}: {body}"


def valid_text():
    return "\n".join((
        event("10.000000001", "sched_waking", "comm=everudp pid=42 prio=120 target_cpu=040"),
        event("10.000000002", "sched_wakeup", "comm=everudp pid=42 prio=120 target_cpu=040"),
        event("10.000000003", "sched_switch", "prev_comm=swapper prev_pid=0 prev_prio=120 prev_state=R ==> next_comm=everudp next_pid=42 next_prio=120"),
        event("10.000000004", "sched_switch", "prev_comm=everudp prev_pid=42 prev_prio=120 prev_state=S ==> next_comm=swapper next_pid=0 next_prio=120"),
    )) + "\n"


class SchedulerCaptureTests(unittest.TestCase):
    def test_command_is_all_cpu_filtered_and_bounded(self):
        command = scheduler_command(["perf"], [42, 43], Path("/capture"), 60000)
        self.assertEqual(command[1], "record")
        self.assertIn("-a", command)
        self.assertIn("--synth", command)
        self.assertIn("no", command)
        self.assertIn("--clockid", command)
        self.assertIn("mono", command)
        self.assertIn("--delay=-1", command)
        self.assertEqual(command[command.index("--control") + 1],
                         "fifo:/capture/control,/capture/ack")
        self.assertEqual([command[i + 1] for i, value in enumerate(command) if value == "-e"], list(SCHEDULER_EVENTS))
        self.assertEqual([command[i + 1] for i, value in enumerate(command) if value == "--filter"], [
            "pid == 42 || pid == 43", "pid == 42 || pid == 43",
            "prev_pid == 42 || next_pid == 42 || prev_pid == 43 || next_pid == 43",
        ])
        self.assertEqual(command[-3:], ["--", "/usr/bin/sleep", "60.0"])
        for forbidden in ("-g", "--call-graph", "--user-regs", "--intr-regs", "-R"):
            self.assertNotIn(forbidden, command)

    def test_command_rejects_empty_duplicate_and_invalid_targets(self):
        for tids in ([], [42, 42], [0], [-1], [True], "42", None):
            with self.subTest(tids=tids), self.assertRaises(ValueError):
                scheduler_command(["perf"], tids, Path("/capture"), 1000)
        for budget in (0, 9, 60001, True):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                scheduler_command(["perf"], [42], Path("/capture"), budget)

    def test_attributes_are_exact_and_sensitive_fields_fail_closed(self):
        validate_attributes(ATTRIBUTES)
        invalid = (
            ATTRIBUTES.replace("sched:sched_wakeup:", "sched:wrong:", 1),
            ATTRIBUTES.replace("clockid: 1", "clockid: 10", 1),
            ATTRIBUTES.replace("sample_type: IP|TID|TIME|CPU|PERIOD|RAW|IDENTIFIER",
                                "sample_type: IP|TID|TIME|CPU|PERIOD|RAW|IDENTIFIER|CALLCHAIN", 1),
            ATTRIBUTES.replace("dummy:u:", "other:u:", 1),
            ATTRIBUTES.replace("dummy:u: type: 1 (PERF_TYPE_SOFTWARE), size: 144, config: 0x9 (PERF_COUNT_SW_DUMMY), { sample_period, sample_freq }: 1, sample_type: IP|TID|TIME|CPU|IDENTIFIER",
                               "dummy:u: type: 1 (PERF_TYPE_SOFTWARE), size: 144, config: 0x9 (PERF_COUNT_SW_DUMMY), { sample_period, sample_freq }: 1, sample_type: IP|TID|TIME|CPU|IDENTIFIER|RAW", 1),
            "\n".join(ATTRIBUTES.splitlines()[:3] + ATTRIBUTES.splitlines()[4:]),
        )
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(ValueError):
                validate_attributes(text)

    def test_sanitizer_redacts_names_and_keeps_scheduler_shape(self):
        safe = sanitize_scheduler(valid_text(), [42])
        self.assertNotIn("everudp", safe)
        self.assertNotIn("swapper", safe)
        self.assertEqual(safe.count("sched:"), 4)
        self.assertIn("comm=<task> pid=42", safe)
        self.assertIn("prev_comm=<task> prev_pid=0", safe)
        self.assertEqual(sanitize_scheduler(valid_text().replace(": sched:", ":    sched:"), [42]), safe)
        sanitize_scheduler(valid_text().replace("10.000000004", "10.000000003"), [42])

    def test_sanitizer_rejects_lost_malformed_outside_and_regressing_records(self):
        cases = (
            valid_text() + "LOST 1 events\n",
            valid_text().replace("target_cpu=040", "target_cpu=", 1),
            valid_text().replace("pid=42", "pid=99", 1),
            valid_text().replace("10.000000004", "10.000000002", 1),
            valid_text().replace("next_pid=42", "next_pid=43", 1),
        )
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                sanitize_scheduler(text, [42])

    def test_sanitizer_rejects_empty_and_non_scheduler_records(self):
        for text in ("", "\n", "10.000000001: cycles: value=1\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                sanitize_scheduler(text, [42])


if __name__ == "__main__":
    unittest.main()
