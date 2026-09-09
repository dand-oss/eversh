"""Compile and exercise the public benchmark's optional measurement barriers."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


class MeasurementWindowTests(unittest.TestCase):
    def test_barriers_hold_trials_and_teardown_until_controller_snapshots(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            binary = root / "pty-bench"
            subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                            str(Path(__file__).with_name("pty-bench.c")), "-lutil",
                            "-o", str(binary)], check=True)
            window = root / "window"
            window.mkdir()
            result = root / "result.json"
            env = dict(os.environ, PTY_BENCH_WINDOW_DIR=str(window))
            process = subprocess.Popen([str(binary), "2", "1", str(result),
                                        str(root / "candidate.stderr"), "--", "/bin/cat"],
                                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                for phase in ("start", "finish"):
                    deadline = time.monotonic() + 10
                    while not (window / f"{phase}.ready").exists():
                        self.assertIsNone(process.poll(), "benchmark exited before barrier")
                        self.assertLess(time.monotonic(), deadline, "barrier deadline")
                        time.sleep(0.005)
                    self.assertFalse(result.exists(), "result published before snapshot release")
                    if phase == "start":
                        time.sleep(0.03)
                        self.assertFalse((window / "finish.ready").exists())
                    (window / f"{phase}.go").touch()
                _, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr.decode())
                evidence = json.loads(result.read_text())
                self.assertEqual(evidence["trials"], 2)
                self.assertEqual(evidence["transcript_failures"], 0)
                self.assertEqual(len(evidence["public_boundaries"]), 2)
                self.assertIn("CLOCK_MONOTONIC", evidence["public_clock"])
                namespace = Path("/proc/self/ns/time").stat()
                self.assertEqual(evidence["clock_identity"], {
                    "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                    "time_namespace_dev": namespace.st_dev,
                    "time_namespace_ino": namespace.st_ino,
                })
                for index, boundary in enumerate(evidence["public_boundaries"]):
                    self.assertEqual(boundary["trial"], index)
                    elapsed = boundary["accepted_ns"] - boundary["send_ns"]
                    self.assertGreater(elapsed, 0)
                    self.assertEqual((elapsed + 999) // 1000, evidence["samples_us"][index])
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=10)


if __name__ == "__main__":
    unittest.main()
