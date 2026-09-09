"""Reject confounded single-owner builds before any artifact is created."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class FloorBuildOptionsTests(unittest.TestCase):
    def run_options(self, overrides):
        env = os.environ.copy()
        for name in (
            "EVERUDP_FLOOR_DIAGNOSTICS",
            "EVERUDP_FLOOR_SEND_FAST_PATH",
            "EVERUDP_FLOOR_ACK_INLINE_STORAGE",
            "EVERUDP_FLOOR_SINGLE_OWNER",
        ):
            env[name] = "0"
        env.update(overrides)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "build"
            result = subprocess.run(
                ["bash", str(Path(__file__).with_name("build-floor.sh")), str(output)],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertFalse(output.exists())
            return result

    def test_invalid_single_owner_value(self):
        result = self.run_options({"EVERUDP_FLOOR_SINGLE_OWNER": "yes"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("EVERUDP_FLOOR_SINGLE_OWNER must be 0 or 1", result.stderr)

    def test_single_owner_rejects_each_other_experiment(self):
        for name in (
            "EVERUDP_FLOOR_DIAGNOSTICS",
            "EVERUDP_FLOOR_SEND_FAST_PATH",
            "EVERUDP_FLOOR_ACK_INLINE_STORAGE",
        ):
            with self.subTest(option=name):
                result = self.run_options({"EVERUDP_FLOOR_SINGLE_OWNER": "1", name: "1"})
                self.assertEqual(result.returncode, 2)
                self.assertIn("other experiments disabled", result.stderr)


if __name__ == "__main__":
    unittest.main()
