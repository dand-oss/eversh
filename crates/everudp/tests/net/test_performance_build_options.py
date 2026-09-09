"""Keep production stream scheduling experiments distinct from datagram builds."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class PerformanceBuildOptionsTests(unittest.TestCase):
    def test_input_ack_hold_experiment_is_isolated(self):
        accepted = self.run_options("cli,input-ack-hold-spike")
        self.assertEqual(accepted.returncode, 1)
        self.assertIn("set EVERUDP_ZIG_0152", accepted.stderr)
        for extra in ("discarded-space-spike", "datagram-spike", "quic-ack-threshold-spike"):
            self.assertEqual(self.run_options(f"cli,input-ack-hold-spike,{extra}").returncode, 2)

    def test_discarded_space_experiment_is_isolated(self):
        accepted = self.run_options("cli,discarded-space-spike")
        self.assertEqual(accepted.returncode, 1)
        self.assertIn("set EVERUDP_ZIG_0152", accepted.stderr)
        for extra in ("single-path-scheduling-spike", "datagram-spike", "quic-ack-threshold-spike"):
            rejected = self.run_options(f"cli,discarded-space-spike,{extra}")
            self.assertEqual(rejected.returncode, 2)

    def test_single_path_profiles_reach_tool_preflight(self):
        for features in (
            "cli,single-path-scheduling-spike",
            "cli,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike,single-path-scheduling-spike",
            "cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike,single-path-scheduling-spike",
        ):
            with self.subTest(features=features):
                result = self.run_options(features)
                self.assertEqual(result.returncode, 1)
                self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_unknown_engine_is_rejected_before_toolchain_preflight(self):
        result = self.run_options("cli", engine="not-an-engine")
        self.assertEqual(result.returncode, 2)
        self.assertIn("EVERUDP_ENGINE must be noq or quinn-eval", result.stderr)

    def test_quinn_eval_accepts_only_the_cli_feature(self):
        accepted = self.run_options("cli", engine="quinn-eval")
        self.assertEqual(accepted.returncode, 1)
        self.assertIn("set EVERUDP_ZIG_0152", accepted.stderr)
        result = self.run_options("cli,stream-delivery-spike", engine="quinn-eval")
        self.assertEqual(result.returncode, 2)
        self.assertIn("quinn-eval engine accepts only EVERUDP_CARGO_FEATURES=cli", result.stderr)

    def test_quinn_eval_builder_contract_names_its_isolated_package(self):
        script = Path(__file__).with_name("build-performance.sh").read_text()
        self.assertIn("spikes/everudp-quinn-eval/Cargo.toml", script)
        self.assertIn("everudp-quinn-eval", script)
        self.assertIn("cargo_lock_sha256", script)
        self.assertIn("quinn-proto", script)

    def test_single_path_rejects_other_experiment_mixes(self):
        for extra in ("pty-ready-spike", "packet-preparation-spike", "datagram-spike",
                      "quic-ack-coalescing-spike", "stream-flush-spike"):
            with self.subTest(extra=extra):
                result = self.run_options(f"cli,single-path-scheduling-spike,{extra}")
                self.assertEqual(result.returncode, 2)

    def test_packet_preparation_profiles_reach_tool_preflight(self):
        for features in (
            "cli,packet-preparation-spike",
            "cli,application-task-spike,stream-delivery-spike,packet-preparation-spike",
            "cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike,packet-preparation-spike",
        ):
            with self.subTest(features=features):
                result = self.run_options(features)
                self.assertEqual(result.returncode, 1)
                self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_packet_preparation_rejects_unrelated_experiments(self):
        result = self.run_options("cli,packet-preparation-spike,datagram-spike")
        self.assertEqual(result.returncode, 2)

    def test_ack_coalescing_profiles_reach_tool_preflight(self):
        for features in (
            "cli,quic-ack-coalescing-spike",
            "cli,application-task-spike,stream-delivery-spike,quic-ack-coalescing-spike",
            "cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike,quic-ack-coalescing-spike",
        ):
            with self.subTest(features=features):
                result = self.run_options(features)
                self.assertEqual(result.returncode, 1)
                self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_ack_coalescing_rejects_packet_and_datagram_mixes(self):
        for extra in ("packet-preparation-spike", "datagram-spike"):
            result = self.run_options(f"cli,quic-ack-coalescing-spike,{extra}")
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVERUDP_CARGO_FEATURES must be", result.stderr)

    def test_ack_threshold_profiles_reach_tool_preflight(self):
        for features in (
            "cli,quic-ack-threshold-spike",
            "cli,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike",
            "cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike",
        ):
            with self.subTest(features=features):
                result = self.run_options(features)
                self.assertEqual(result.returncode, 1)
                self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_ack_threshold_rejects_other_ack_and_packet_mixes(self):
        for extra in (
            "quic-ack-coalescing-spike", "packet-preparation-spike", "datagram-spike",
        ):
            result = self.run_options(f"cli,quic-ack-threshold-spike,{extra}")
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVERUDP_CARGO_FEATURES must be", result.stderr)

    def test_pty_ready_profiles_reach_tool_preflight(self):
        for features in (
            "cli,pty-ready-spike",
            "cli,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike,pty-ready-spike",
            "cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike,pty-ready-spike",
        ):
            with self.subTest(features=features):
                result = self.run_options(features)
                self.assertEqual(result.returncode, 1)
                self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_pty_ready_rejects_coalescing_cid_and_datagram_mixes(self):
        for extra in (
            "quic-ack-coalescing-spike", "packet-preparation-spike", "datagram-spike",
        ):
            result = self.run_options(f"cli,pty-ready-spike,{extra}")
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVERUDP_CARGO_FEATURES must be", result.stderr)

    def test_application_task_profiles_reach_tool_preflight(self):
        for features in (
            "cli,application-task-spike",
            "cli,application-task-spike,stream-delivery-spike",
            "cli,path-packet-diagnostics,application-task-spike",
            "cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike",
        ):
            with self.subTest(features=features):
                result = self.run_options(features)
                self.assertEqual(result.returncode, 1)
                self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_application_task_rejects_unrelated_experiments(self):
        for extra in ("stream-flush-spike", "stream-receive-spike", "datagram-spike"):
            result = self.run_options(f"cli,application-task-spike,{extra}")
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVERUDP_CARGO_FEATURES must be", result.stderr)

    def run_options(self, features, engine=None):
        env = os.environ.copy()
        env.update(EVERUDP_CARGO_FEATURES=features,
                   EVERUDP_ZIG_0152="/nonexistent-everudp-test-zig")
        env["EVERUDP_ENGINE"] = engine or "noq"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "build"
            result = subprocess.run(
                ["bash", str(Path(__file__).with_name("build-performance.sh")), str(output)],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertFalse(output.exists())
            return result

    def test_stream_experiment_reaches_tool_preflight(self):
        result = self.run_options("cli,stream-flush-spike")
        self.assertEqual(result.returncode, 1)
        self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_combined_experiments_are_rejected(self):
        result = self.run_options("cli,datagram-spike,stream-flush-spike")
        self.assertEqual(result.returncode, 2)
        self.assertIn("EVERUDP_CARGO_FEATURES must be", result.stderr)

    def test_receive_experiment_reaches_tool_preflight(self):
        result = self.run_options("cli,stream-receive-spike")
        self.assertEqual(result.returncode, 1)
        self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_named_stream_pump_experiment_reaches_tool_preflight(self):
        result = self.run_options("cli,stream-pump-spike")
        self.assertEqual(result.returncode, 1)
        self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_stream_pump_cannot_mix_with_other_experiments(self):
        for other in ("datagram-spike", "path-io-diagnostics", "stream-flush-spike"):
            result = self.run_options(f"cli,stream-pump-spike,{other}")
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVERUDP_CARGO_FEATURES must be", result.stderr)

    def test_path_diagnostics_reaches_tool_preflight(self):
        result = self.run_options("cli,path-diagnostics")
        self.assertEqual(result.returncode, 1)
        self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_packet_diagnostics_reaches_tool_preflight(self):
        result = self.run_options("cli,path-packet-diagnostics")
        self.assertEqual(result.returncode, 1)
        self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_stream_delivery_experiment_reaches_tool_preflight(self):
        result = self.run_options("cli,stream-delivery-spike")
        self.assertEqual(result.returncode, 1)
        self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_packet_diagnostics_delivery_experiment_reaches_tool_preflight(self):
        result = self.run_options("cli,path-packet-diagnostics,stream-delivery-spike")
        self.assertEqual(result.returncode, 1)
        self.assertIn("set EVERUDP_ZIG_0152", result.stderr)

    def test_receive_experiment_cannot_mix_scheduling_changes(self):
        for other in ("stream-flush-spike", "datagram-spike"):
            result = self.run_options(f"cli,stream-receive-spike,{other}")
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVERUDP_CARGO_FEATURES must be", result.stderr)

    def test_delivery_cannot_mix_with_other_scheduling_experiments(self):
        for other in (
            "datagram-spike", "stream-flush-spike", "stream-receive-spike",
            "stream-pump-spike", "path-diagnostics", "path-io-diagnostics",
        ):
            result = self.run_options(f"cli,stream-delivery-spike,{other}")
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVERUDP_CARGO_FEATURES must be", result.stderr)

    def test_packet_diagnostics_delivery_cannot_mix_with_scheduling_changes(self):
        for other in ("datagram-spike", "stream-flush-spike", "stream-receive-spike"):
            result = self.run_options(
                f"cli,path-packet-diagnostics,stream-delivery-spike,{other}"
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVERUDP_CARGO_FEATURES must be", result.stderr)


if __name__ == "__main__":
    unittest.main()
