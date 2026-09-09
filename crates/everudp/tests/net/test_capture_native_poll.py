import unittest
import os
from pathlib import Path
import tempfile
import subprocess
import sys

from capture_native_poll import capture_plan, descriptor_aliases, role_matches


class CapturePlanTests(unittest.TestCase):
    def test_scheduler_and_production_require_scalar_export_before_preflight(self):
        base = [sys.executable, str(Path(__file__).with_name("capture_native_poll.py")),
                "--build", "/nonexistent", "--out", "/nonexistent",
                "--perf", "/nonexistent", "--perf-libs", "/nonexistent",
                "--head", "unused", "--seed", "1", "--loss", "0"]
        for flags in (["--scheduler", "--io"], ["--production"]):
            result = subprocess.run(base + flags, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("requires", result.stderr)

    def test_descriptor_aliases_are_verified_objects_not_guessed_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory / "0").touch()
            os.link(directory / "0", directory / "15")
            (directory / "1").touch()
            (directory / "not-a-descriptor").touch()
            self.assertEqual(descriptor_aliases(directory, 0), [0, 15])
            self.assertEqual(descriptor_aliases(directory, 1), [1])

    def test_production_keeps_complete_control_set_but_traces_two_clients(self):
        roles, order = capture_plan(True)
        self.assertEqual(order, ["everudp", "zmosh-udp", "zmosh-quic"])
        self.assertEqual(roles["everudp"], [("client", "production-client")])
        self.assertEqual(roles["zmosh-udp"], [("client", "attach")])
        self.assertEqual(roles["zmosh-quic"], [])

    def test_native_plan_is_unchanged(self):
        roles, order = capture_plan(False)
        self.assertEqual(order, ["everudp-floor", "zmosh-udp"])
        self.assertEqual(roles["everudp-floor"],
                         [("client", "client"), ("server", "__floor-server-v1")])

    def test_production_client_requires_exact_harness_prefix(self):
        self.assertTrue(role_matches(
            [b"everudp", b"--remote-program", b"remote", b"connect", b"target"],
            "production-client"))
        for argv in ([b"everudp"], [b"everudp", b"__gateway-v1", b"connect"],
                     [b"everudp", b"--remote-program", b"remote", b"__gateway-v1"],
                     [b"everudp", b"connect", b"--remote-program", b"remote"]):
            self.assertFalse(role_matches(argv, "production-client"))
        self.assertTrue(role_matches([b"zmosh", b"attach", b"target"], "attach"))
        self.assertFalse(role_matches([b"zmosh", b"server", b"attach"], "attach"))


if __name__ == "__main__":
    unittest.main()
