import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from argparse import Namespace
import os
import pty
import time
from unittest.mock import patch

import pgo_terminal_train as training

from pgo_terminal_train import READY, LARGE_SIZE, ONE_BYTE_ROUNDTRIPS, command, payload


class PgoTerminalTrainTests(unittest.TestCase):
    def test_payload_is_deterministic_and_bounded(self):
        self.assertEqual(payload(8, 3), payload(8, 3))
        self.assertNotEqual(payload(8, 3), payload(8, 4))
        self.assertEqual(len(payload(LARGE_SIZE, 287)), LARGE_SIZE)

    def test_command_uses_local_shim_and_exact_fixture(self):
        result = command(Path("/bin/everudp"), Path("/bin/everudp"), Path("/tmp/ssh"),
                         Path("/tmp/state"), Path("/tmp/status"), Path("/tmp/pgo-echo"))
        self.assertIn("--remote-program", result)
        self.assertIn("/tmp/pgo-echo", result[-1])
        self.assertNotIn("--ssh-option", result)

    def test_command_quotes_fixture_path(self):
        result = command(Path("/bin/everudp"), Path("/bin/everudp"), Path("/tmp/ssh"),
                         Path("/tmp/state"), Path("/tmp/status"), Path("/tmp/pgo echo;bad"))
        self.assertIn("'/tmp/pgo echo;bad'", result[-1])

    def test_invalid_timeout_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            for timeout in (0, -1, float("nan"), float("inf")):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    training.run(Namespace(binary=Path('/bin/true'), fixture=Path('/bin/true'),
                                           output_dir=output, timeout=timeout))
                self.assertFalse(output.exists())

    def test_eof_requires_parent_slave_closed(self):
        master, slave = pty.openpty()
        try:
            with self.assertRaises(TimeoutError):
                training._require_eof(master, time.monotonic() + 0.01)
            os.close(slave)
            slave = -1
            training._require_eof(master, time.monotonic() + 0.2)
        finally:
            os.close(master)
            if slave >= 0:
                os.close(slave)

    def test_trailing_output_is_rejected(self):
        master, slave = pty.openpty()
        try:
            os.write(slave, b'extra')
            with self.assertRaisesRegex(RuntimeError, 'trailing'):
                training._require_eof(master, time.monotonic() + 0.2)
        finally:
            os.close(master)
            os.close(slave)

    def test_startup_failure_preserves_failed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'run'
            args = Namespace(binary=Path('/bin/true'), fixture=Path('/bin/true'),
                             output_dir=output, timeout=0.05)
            with patch.object(training, 'route_selected_ip', return_value='192.0.2.2'):
                with self.assertRaises(TimeoutError):
                    training.run(args)
            receipt = json.loads((output / 'pgo-training-receipt.json').read_text())
            self.assertEqual(receipt['status'], 'FAILED')
            self.assertFalse(receipt['qualification'])
            self.assertNotIn('stderr_tail', receipt['error'])
            self.assertEqual((output / 'state/client.stderr').stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
