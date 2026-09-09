import os
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import subprocess

from perf_counter_control import counter_command, await_ack, CounterSession


class CounterControlTests(unittest.TestCase):
    def test_command_is_scoped_grouped_disabled_and_bounded(self):
        command = counter_command(["perf"], 123, Path("/capture"), 60000)
        self.assertIn("{cycles:u,instructions:u,cache-misses:u}", command)
        self.assertEqual(command[command.index("-t") + 1], "123")
        self.assertIn("--no-inherit", command)
        self.assertIn("--delay=-1", command)
        self.assertIn("--timeout", command)
        self.assertNotIn("-a", command)
        self.assertNotIn("record", command)

    def test_invalid_scope_or_budget_is_rejected(self):
        for tid, budget in ((0, 1000), (-1, 1000), (True, 1000), (12, 0), (12, 60001)):
            with self.subTest(tid=tid, budget=budget), self.assertRaises(ValueError):
                counter_command(["perf"], tid, Path("/capture"), budget)

    def test_exact_ack_only(self):
        for payload in (b"ack\n\x00", b"ack\n", b"bad\n", b"ack\nextra\n", b""):
            read, write = os.pipe()
            try:
                os.write(write, payload)
                os.close(write)
                write = None
                if payload == b"ack\n\x00":
                    await_ack(read, 0.1)
                else:
                    with self.assertRaises(ValueError):
                        await_ack(read, 0.1)
            finally:
                os.close(read)
                if write is not None:
                    os.close(write)

    def test_missing_ack_times_out(self):
        read, write = os.pipe()
        try:
            with self.assertRaises(TimeoutError):
                await_ack(read, 0.01)
        finally:
            os.close(read)
            os.close(write)

    def test_cleanup_escalates_owned_group_after_interrupt_timeout(self):
        session = CounterSession.__new__(CounterSession)
        session.process = Mock(pid=123)
        session.process.poll.return_value = None
        session.process.wait.side_effect = [subprocess.TimeoutExpired("perf", 5), 0]
        session.descriptors = []
        session.log = None
        with patch("perf_counter_control.os.getpgid", return_value=123), \
                patch("perf_counter_control.subprocess.run") as run:
            session.close()
        self.assertEqual(run.call_args.args[0],
                         ["sudo", "-n", "/bin/kill", "-TERM", "--", "-123"])


if __name__ == "__main__":
    unittest.main()
