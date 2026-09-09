import tempfile, unittest
import json
import os
from argparse import Namespace
from unittest.mock import patch
from pathlib import Path
import pgo_network_train as training
from pgo_network_train import CELLS, netem_commands

class NetworkPlanTests(unittest.TestCase):
    def test_preregistered_cells_and_server_offset(self):
        self.assertEqual(CELLS, ((0, 20100001), (5, 20105001)))
        commands = netem_commands("s", "c", 5, 20105001)
        self.assertIn("20105001", commands[0]); self.assertIn("21105004", commands[1])
    def test_namespace_scoped_commands(self):
        for command in netem_commands("s", "c", 0, 20100001):
            self.assertEqual(command[:3], ["ip", "netns", "exec"])

    def test_setup_failure_cleans_only_created_namespace_and_seals_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'run'
            args = Namespace(binary=Path('/bin/true'), fixture=Path('/bin/true'),
                             output_dir=output, timeout=1, user='appsmith')
            with patch.object(training.os, 'geteuid', return_value=0), \
                 patch.object(training.os, 'chown'), \
                 patch.object(training.secrets, 'token_hex', return_value='abcdef'), \
                 patch.object(training, 'execute', side_effect=['', RuntimeError('setup')]), \
                 patch.object(training, 'cleanup_namespace') as cleanup:
                result = training.run(args)
            cleanup.assert_called_once_with('epgoabcdefs')
            self.assertEqual(result['status'], 'FAILED')
            self.assertFalse(result['qualification'])
            self.assertEqual(json.loads((output / 'pgo-network-training-receipt.json').read_text()), result)
            self.assertIn('pgo-network-training-receipt.json', (output / 'SHA256SUMS').read_text())

    def test_nonroot_refused_before_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'run'
            args = Namespace(binary=Path('/bin/true'), fixture=Path('/bin/true'),
                             output_dir=output, timeout=1, user='appsmith')
            with patch.object(training.os, 'geteuid', return_value=1000), self.assertRaises(ValueError):
                training.run(args)
            self.assertFalse(output.exists())

if __name__ == "__main__": unittest.main()
