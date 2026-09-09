"""Exercise the actual floor analyzer heredoc with controlled block evidence."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


class FixedBootstrap:
    def choices(self, values, k):
        return values[:k]


class FloorReceiptTests(unittest.TestCase):
    def analyze(self, packet_counts, tracing=None):
        script = Path(__file__).with_name("qualify-floor.sh").read_text()
        source = script.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = []
            for loss in (0, 5):
                for block, attempts in enumerate(packet_counts, 1):
                    directory = root / f"loss{loss}-block{block}"
                    directory.mkdir()
                    manifest = {"loss_evidence": {}}
                    if tracing:
                        manifest[tracing] = True
                    for name, latency, count in (("everudp-floor", 80, attempts),
                                                 ("zmosh-udp", 100, 100)):
                        (directory / name).mkdir()
                        (directory / name / "result.json").write_text(json.dumps({
                            "samples_us": [latency] * 200, "transcript_failures": 0}))
                        manifest["loss_evidence"][name] = {
                            "summed_egress_attempt_delta": count,
                            "measurement_window": "post-warmup-start-barrier-to-pre-teardown-finish-barrier"}
                    (directory / "manifest.json").write_text(json.dumps(manifest))
                    (directory / "SHA256SUMS").write_text("fixture identity")
                    paths.append(str(directory))
            arguments = ["-", raw, "head", "tree", "200", "started", "finished", *paths]
            with patch("sys.argv", arguments), patch("random.Random", return_value=FixedBootstrap()):
                exec(compile(source, "qualify-floor.sh:analyzer", "exec"), {})
            return json.loads((root / "receipt.json").read_text()), json.loads((root / "analysis.json").read_text())

    def test_one_bad_packet_block_cannot_hide_in_pooled_ratio(self):
        receipt, analysis = self.analyze([200, 100])
        self.assertEqual(receipt["quantitative_gate_status"], "FAIL")
        self.assertEqual(analysis["cells"]["0"]["packet_attempt_ratio"], 1.5)
        self.assertFalse(analysis["pass"])

    def test_numerical_pass_is_invalid_without_attribution(self):
        receipt, analysis = self.analyze([100, 100])
        self.assertTrue(analysis["pass"])
        self.assertEqual(receipt["status"], "INVALID")
        self.assertFalse(receipt["production_actor_integration_authorized"])

    def test_zero_attempts_rejected(self):
        with self.assertRaises(SystemExit):
            self.analyze([0, 100])

    def test_diagnostic_blocks_cannot_count_as_performance(self):
        for field in ("diagnostic_tracing", "native_stage_tracing", "reactor_work_tracing", "reactor_partition_tracing"):
            with self.subTest(field=field), self.assertRaises(SystemExit):
                self.analyze([100, 100], tracing=field)

    def test_reactor_trace_bad_options_fail_before_network_setup(self):
        script = Path(__file__).with_name("bench-performance-block.sh")
        for overrides, message in [
            ({"EVERUDP_FLOOR_REACTOR_TRACE": "yes"}, "must be 0 or 1"),
            ({"EVERUDP_FLOOR_REACTOR_TRACE": "1", "EVERUDP_FLOOR_NATIVE_TRACE": "1"},
             "cannot be combined"),
            ({"EVERUDP_FLOOR_REACTOR_TRACE": "1", "EVERUDP_FLOOR_TRACE": "1"},
             "cannot be combined"),
            ({"EVERUDP_FLOOR_PARTITION_TRACE": "yes"}, "must be 0 or 1"),
            ({"EVERUDP_FLOOR_PARTITION_TRACE": "1", "EVERUDP_FLOOR_REACTOR_TRACE": "1"}, "cannot be combined"),
            ({"EVERUDP_FLOOR_PARTITION_TRACE": "1", "EVERUDP_FLOOR_NATIVE_TRACE": "1"}, "cannot be combined"),
            ({"EVERUDP_FLOOR_PARTITION_TRACE": "1", "EVERUDP_FLOOR_TRACE": "1"}, "cannot be combined"),
        ]:
            env = dict(os.environ, EVERUDP_FLOOR_REACTOR_TRACE="0",
                       EVERUDP_FLOOR_PARTITION_TRACE="0",
                       EVERUDP_FLOOR_NATIVE_TRACE="0", EVERUDP_FLOOR_TRACE="0")
            env.update(overrides)
            with self.subTest(overrides=overrides):
                result = subprocess.run(["bash", str(script)], env=env,
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
