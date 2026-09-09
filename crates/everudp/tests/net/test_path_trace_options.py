import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class PathTraceOptionsTests(unittest.TestCase):
    def test_packet_trace_requires_io_and_boolean_option(self):
        script = Path(__file__).with_name("bench-performance-block.sh")
        for packet, io in (("yes", "1"), ("1", "0")):
            env = {**os.environ, "EVERUDP_PATH_PACKET_TRACE": packet,
                   "EVERUDP_PATH_IO_TRACE": io, "EVERUDP_PATH_TRACE": "1"}
            result = subprocess.run(["bash", str(script)], env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("production packet tracing", result.stderr)

    def test_remote_wrapper_clears_inherited_flags_and_uses_owned_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrapper = root / "remote-everudp"
            wrapper.write_bytes(Path(__file__).with_name("remote-everudp.sh").read_bytes())
            binary = root / "everudp"
            binary.write_text('#!/bin/sh\nprintf "%s\\n" "${EVERUDP_PATH_IO_TRACE-unset}" '
                              '"${EVERUDP_GATEWAY_PATH_TRACE-unset}"\n')
            binary.chmod(0o700)
            env = {"PATH": "/usr/bin:/bin", "EVERUDP_PATH_IO_TRACE": "inherited",
                   "EVERUDP_GATEWAY_PATH_TRACE": "inherited"}
            for marker, expected in ((None, ["unset", "unset"]),
                    ("path-trace.enabled", ["unset", str(root / "path-trace.json")]),
                    ("path-io-trace.enabled", ["1", str(root / "path-trace.json")])):
                if marker:
                    (root / marker).touch()
                result = subprocess.run(["/bin/sh", str(wrapper)], env=env,
                                        capture_output=True, text=True, check=True)
                self.assertEqual(result.stdout.splitlines(), expected)

    def test_io_trace_requires_path_trace_and_boolean_option(self):
        script = Path(__file__).with_name("bench-performance-block.sh")
        for io, path in (("yes", "1"), ("1", "0")):
            env = {**os.environ, "EVERUDP_PATH_IO_TRACE": io, "EVERUDP_PATH_TRACE": path}
            result = subprocess.run(["bash", str(script)], env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("production I/O tracing", result.stderr)

    def test_invalid_or_mixed_trace_modes_fail_before_setup(self):
        script = Path(__file__).with_name("bench-performance-block.sh")
        for value, floor in (("yes", "0"), ("1", "1")):
            env = {**os.environ, "EVERUDP_PATH_TRACE": value,
                   "EVERUDP_PATH_IO_TRACE": "0",
                   "EVERUDP_FLOOR_TRACE": floor}
            result = subprocess.run(["bash", str(script)], env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("production path tracing", result.stderr)


if __name__ == "__main__":
    unittest.main()
