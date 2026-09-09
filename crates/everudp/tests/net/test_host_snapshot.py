import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from host_snapshot import cpu_list, task_sample, snapshot


class HostSnapshotTests(unittest.TestCase):
    def test_cpu_ranges(self):
        self.assertEqual(cpu_list("2,4-6,2"), [2, 4, 5, 6])
        for bad in ("", "3-1", "-1", "4096", "1,,2"):
            with self.assertRaises(ValueError):
                cpu_list(bad)

    def test_live_task_exports_only_scalar_allowlist(self):
        value = task_sample(Path(f"/proc/{os.getpid()}/task/{os.getpid()}"))
        self.assertEqual(set(value), {"start_ticks", "user_ticks", "system_ticks",
                                     "voluntary", "involuntary", "affinity", "status"})
        self.assertEqual(value["status"], "available")
        self.assertGreater(value["start_ticks"], 0)
        self.assertEqual(value["affinity"], sorted(os.sched_getaffinity(0)))

    def test_disappeared_task_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(task_sample(Path(directory)), {"status": "FileNotFoundError"})

    def test_comm_is_not_exported_and_parentheses_do_not_shift_fields(self):
        live = Path(f"/proc/{os.getpid()}/task/{os.getpid()}")
        raw = (live / "stat").read_text()
        fields = raw.rsplit(")", 1)[1]
        status = (live / "status").read_text()
        altered = f"{os.getpid()} (private ) name (value)){fields}"
        with patch.object(Path, "read_text", side_effect=[altered, status, altered]):
            value = task_sample(live)
        self.assertEqual(value["start_ticks"], int(fields.split()[19]))
        self.assertNotIn("private", str(value))

    def test_reused_identity_is_not_reported_as_available(self):
        live = Path(f"/proc/{os.getpid()}/task/{os.getpid()}")
        raw = (live / "stat").read_text()
        fields = raw.rsplit(")", 1)[1].split()
        fields[19] = str(int(fields[19]) + 1)
        changed = raw.rsplit(")", 1)[0] + ") " + " ".join(fields)
        status = (live / "status").read_text()
        with patch.object(Path, "read_text", side_effect=[raw, status, changed]):
            self.assertEqual(task_sample(live), {"status": "identity_changed"})

    def test_snapshot_scope_and_monotonic_bounds(self):
        selected = [min(os.sched_getaffinity(0))]
        value = snapshot(selected, {"client": [os.getpid()], "server": []})
        self.assertEqual(value["selected_cpus"], selected)
        self.assertLessEqual(value["begin_monotonic_ns"], value["end_monotonic_ns"])
        self.assertIn(str(selected[0]), value["cpus"])
        self.assertEqual(value["tasks"][0]["side"], "client")
        self.assertEqual(value["tasks"][0]["pid"], os.getpid())
        self.assertEqual(value["tasks"][0]["enumerated_threads"], len(value["tasks"]))
        self.assertFalse(value["qualification"])

    def test_integration_is_outside_window_and_counter_capture(self):
        script = (Path(__file__).parent / "bench-performance-block.sh").read_text()
        before = script.index('host_snapshot before')
        after = script.index('host_snapshot after')
        self.assertLess(script.index('wait_measurement_barrier "$candidate_dir/window/start.ready"'), before)
        self.assertLess(before, script.index('counter_capture_barrier "$candidate_dir/window" start'))
        self.assertLess(script.index('counter_capture_barrier "$candidate_dir/window" stop'), after)
        self.assertLess(after, script.index('touch "$candidate_dir/window/finish.go"'))


if __name__ == "__main__":
    unittest.main()
