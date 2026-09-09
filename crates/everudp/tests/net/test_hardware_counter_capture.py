from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from capture_hardware_counters import wait_marker, scheduler_scope


class HardwareCaptureTests(unittest.TestCase):
    def test_scheduler_scope_uses_only_sealed_binary_threads(self):
        row = {"pid": 100, "tid": 101, "start_ticks": 12, "side": "client",
               "status": "available"}
        same = lambda proc, binary: str(binary) == "/sealed/client"
        sample = lambda root: {"status": "available", "start_ticks": 12}
        scope = scheduler_scope({"tasks": [row]}, {"client": Path("/sealed/client")}, same, sample)
        self.assertEqual(scope, [{**row, "binary": "client"}])
        with self.assertRaises(ValueError):
            scheduler_scope({"tasks": [row]}, {"client": Path("/sealed/client")}, same,
                            lambda root: {"status": "available", "start_ticks": 13})

    def test_scheduler_scope_requires_every_requested_binary(self):
        with self.assertRaises(ValueError):
            scheduler_scope({"tasks": []}, {"client": Path("/sealed/client")})

    def test_existing_marker_releases_without_wait(self):
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / "ready"
            marker.touch()
            wait_marker(marker, Mock(), 0)

    def test_missing_marker_and_dead_benchmark_fail(self):
        with tempfile.TemporaryDirectory() as raw:
            process = Mock()
            process.poll.return_value = 1
            with self.assertRaises(ValueError):
                wait_marker(Path(raw) / "missing", process, 1)

    def test_missing_marker_and_live_benchmark_time_out(self):
        with tempfile.TemporaryDirectory() as raw:
            process = Mock()
            process.poll.return_value = None
            with self.assertRaises(TimeoutError):
                wait_marker(Path(raw) / "missing", process, 0)


if __name__ == "__main__":
    unittest.main()
