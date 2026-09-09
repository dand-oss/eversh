import os
from pathlib import Path
import subprocess
import unittest


class NativeTraceOptionsTests(unittest.TestCase):
    def test_invalid_and_conflicting_flags_fail_before_setup(self):
        script = Path(__file__).with_name("bench-performance-block.sh")
        for native, legacy, message in (("yes", "0", "must be 0 or 1"),
                                        ("1", "1", "cannot be combined")):
            env = {**os.environ, "EVERUDP_FLOOR_NATIVE_TRACE": native, "EVERUDP_FLOOR_TRACE": legacy}
            result = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
