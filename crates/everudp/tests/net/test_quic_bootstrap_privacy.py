"""Bootstrap credentials reach the bridge, never the evidence log."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class BootstrapPrivacyTests(unittest.TestCase):
    def exercise(self, record, bridge_status):
        key = "FIXTUREKEY0123456789="
        with tempfile.TemporaryDirectory(prefix="everudp-privacy-") as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir()
            ssh = root / "ssh"
            ssh.write_text("#!/bin/sh\nprintf '%s\\n' '" + record + "'\n")
            ssh.chmod(0o700)
            bridge = root / "bridge"
            bridge.write_text(
                "#!/bin/sh\n[ \"$3\" = '" + key + "' ] || exit 91\n"
                + f"exit {bridge_status}\n"
            )
            bridge.chmod(0o700)
            source = Path(__file__).with_name("launch-zmosh-quic.sh").read_text()
            launcher = root / "launcher"
            launcher.write_text(source.replace("/usr/bin/ssh ", str(ssh) + " "))
            log = root / "connect.log"
            result = subprocess.run(
                ["sh", str(launcher), "host", "127.0.0.1", "/config", "/remote",
                 "fixture", "/echo", str(bridge), str(log), str(root / "server.stderr")],
                input=b"", capture_output=True, timeout=5,
                env={**os.environ, "TMPDIR": str(private)},
            )
            self.assertNotIn(key.encode(), result.stdout + result.stderr + log.read_bytes())
            self.assertEqual(list(private.iterdir()), [])
            return result.returncode, log.read_text()

    def test_success_passes_key_only_to_bridge(self):
        status, log = self.exercise("ZMX_CONNECT quic 12345 FIXTUREKEY0123456789=", 0)
        self.assertEqual(status, 0)
        self.assertEqual(log, "ZMX_CONNECT quic 12345 [REDACTED]\n")

    def test_bridge_failure_keeps_only_redacted_record(self):
        status, log = self.exercise("ZMX_CONNECT quic 12345 FIXTUREKEY0123456789=", 7)
        self.assertEqual(status, 7)
        self.assertEqual(log, "ZMX_CONNECT quic 12345 [REDACTED]\n")

    def test_malformed_record_is_not_archived(self):
        status, log = self.exercise("ZMX_CONNECT invalid 12345 FIXTUREKEY0123456789=", 0)
        self.assertEqual(status, 1)
        self.assertEqual(log, "")


if __name__ == "__main__":
    unittest.main()
