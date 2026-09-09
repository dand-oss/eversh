from pathlib import Path
import subprocess
import tempfile
import time
import unittest


NET = Path(__file__).parent


class CounterCaptureTests(unittest.TestCase):
    def test_invalid_or_mixed_options_fail_before_setup(self):
        for options in ({"EVERUDP_COUNTER_CAPTURE": "yes"},
                        {"EVERUDP_COUNTER_CAPTURE": "1", "EVERUDP_PATH_TRACE": "1"},
                        {"EVERUDP_COUNTER_CAPTURE": "1", "EVERUDP_FLOOR_TRACE": "1"}):
            result = subprocess.run(["bash", str(NET / "bench-performance-block.sh")],
                                    env={"PATH": "/usr/bin:/bin", **options},
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("counter capture", result.stderr)

    def test_enabled_barrier_waits_for_collector_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = 'source "$1"; COUNTER_CAPTURE=1; counter_capture_barrier "$2" start $$ 5'
            process = subprocess.Popen(["bash", "-c", command, "test",
                                        str(NET / "counter-capture.sh"), directory],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 3
                while not (root / "counter-start.ready").exists():
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.005)
                self.assertIsNone(process.poll())
                (root / "counter-start.go").touch()
                _, error = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, error.decode())
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate()

    def test_disabled_barrier_is_noop_and_missing_collector_times_out(self):
        with tempfile.TemporaryDirectory() as directory:
            for enabled, expected in (("0", 0), ("1", 1)):
                result = subprocess.run(["bash", "-c",
                    'source "$1"; COUNTER_CAPTURE=$3; counter_capture_barrier "$2" stop $$ 0',
                    "test", str(NET / "counter-capture.sh"), directory, enabled],
                    capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, expected, result.stderr)
                if enabled == "0":
                    self.assertEqual(list(Path(directory).iterdir()), [])

    def test_integration_brackets_public_window_and_marks_diagnostic(self):
        script = (NET / "bench-performance-block.sh").read_text()
        start = script.index('counter_capture_barrier "$candidate_dir/window" start')
        stop = script.index('counter_capture_barrier "$candidate_dir/window" stop')
        self.assertLess(script.index('wait_measurement_barrier "$candidate_dir/window/start.ready"'), start)
        self.assertLess(start, script.index('touch "$candidate_dir/window/start.go"'))
        self.assertLess(script.index('wait_measurement_barrier "$candidate_dir/window/finish.ready"'), stop)
        self.assertLess(stop, script.index('touch "$candidate_dir/window/finish.go"'))
        self.assertIn('"hardware_counter_capture": counter_capture == "1"', script)
        self.assertIn('"diagnostic_tracing": (counter_capture == "1" or', script)


if __name__ == "__main__":
    unittest.main()
