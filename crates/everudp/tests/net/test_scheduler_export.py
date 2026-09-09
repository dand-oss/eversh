import unittest

from scheduler_export import split_capture


class SchedulerExportTests(unittest.TestCase):
    def test_scalar_switch_export_omits_comm_and_preserves_io(self):
        text = (
            "1.000000001: syscalls:sys_enter_read: fd: 0x0, buf: 0xdead, count: 0x1\n"
            "1.000000002:          sched:sched_switch: prev_comm=secret-name prev_pid=42 prev_prio=120 prev_state=S ==> next_comm=idle next_pid=0 next_prio=120\n"
            "1.000000003:          sched:sched_switch: prev_comm=idle prev_pid=0 prev_prio=120 prev_state=R ==> next_comm=secret-name next_pid=42 next_prio=120\n"
            "1.000000004: syscalls:sys_exit_read: 0x1\n"
        )
        io, scheduler = split_capture(text, 42)
        self.assertEqual(len(io["events"]), 2)
        self.assertNotIn("buf", io["events"][0]["fields"])
        self.assertEqual(scheduler["events"], [
            {"time_ns": 1000000002, "prev_pid": 42, "next_pid": 0},
            {"time_ns": 1000000003, "prev_pid": 0, "next_pid": 42}])
        self.assertNotIn("secret-name", str(scheduler))
        for bad in (text.replace("prev_pid=42", "prev_pid=43"),
                    text + "LOST 1 events\n",
                    text.replace("sched:sched_switch", "sched:unknown")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                split_capture(bad, 42)


if __name__ == "__main__":
    unittest.main()
