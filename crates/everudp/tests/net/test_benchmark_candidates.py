"""Candidate identities cannot silently change a historical comparison set."""
import itertools
import os
from pathlib import Path
import subprocess
import unittest


class CandidateTests(unittest.TestCase):
    def runner_source(self):
        return Path(__file__).with_name("bench-performance-block.sh").read_text()

    def classify(self, order):
        helper = Path(__file__).with_name("benchmark-candidates.sh")
        return subprocess.run(["bash", "-c", 'source "$1"; benchmark_candidate_mode "$2"',
                               "candidate-test", str(helper), order],
                              capture_output=True, text=True, check=False)

    def test_all_orders_preserve_three_disjoint_sets(self):
        sets = {
            "datagram-floor": ["everudp-floor", "zmosh-udp"],
            "production": ["everudp", "zmosh-udp", "zmosh-quic"],
            "stream-floor": ["everudp-stream-native", "everudp-stream-ordinary", "zmosh-udp"],
        }
        for mode, candidates in sets.items():
            for order in itertools.permutations(candidates):
                with self.subTest(order=order):
                    result = self.classify(",".join(order))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), mode)

    def test_mixed_missing_duplicate_and_unknown_candidates_rejected(self):
        for order in ["", "everudp-floor,zmosh-udp,", ",everudp-floor,zmosh-udp",
                      "everudp-floor,,zmosh-udp", "everudp-floor,zmosh-udp,zmosh-udp",
                      "everudp-floor,zmosh-udp\nignored", "everudp-floor, zmosh-udp",
                      "everudp-stream-native,zmosh-udp", "everudp-stream-native,everudp,zmosh-udp",
                      "everudp-stream-native,everudp-stream-ordinary,zmosh-quic",
                      "everudp-floor,everudp-stream-ordinary,zmosh-udp", "unknown,zmosh-udp"]:
            with self.subTest(order=order):
                self.assertEqual(self.classify(order).returncode, 2)

    def test_actual_dispatch_uses_shared_binary_and_explicit_runtime(self):
        source = self.runner_source()
        function = "run_named_candidate() {" + source.split("run_named_candidate() {", 1)[1].split("\nSTARTED_UTC=", 1)[0]
        environment = dict(os.environ, TAG="fixture", OUTDIR="/output", TMP="/fixture",
                           EVERUDP_STREAM_BIN="/shared/everudp-stream-floor", NATIVE_TRACE="0",
                           REACTOR_TRACE="0", PARTITION_TRACE="0", EVERUDP_FLOOR_TRACE="0")
        for runtime in ("ordinary", "native"):
            label = "everudp-stream-" + runtime
            result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + function +
                                     '\nrun_candidate() { printf "%s\\0" "$@"; }\nrun_named_candidate "$1" 1',
                                     "dispatch-test", label], env=environment,
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = result.stdout.split("\0")[:-1]
            self.assertEqual(arguments[:8], [label, "/usr/bin/env", "TERM=xterm-256color",
                                             "/shared/everudp-stream-floor", "client", "target",
                                             "--runtime", runtime])
            self.assertEqual(arguments[arguments.index("--remote-program") + 1],
                             "/fixture/remote-everudp-stream/remote-everudp-stream")
            self.assertEqual(arguments[-1], "--ssh-option=-F/fixture/client_config")
            self.assertNotIn("--ssh-option", arguments)

    def test_actual_stream_mode_rejects_instrumented_timing(self):
        source = self.runner_source()
        validation = 'IFS=, read -r -a CANDIDATES <<<"$ORDER"' + source.split(
            'IFS=, read -r -a CANDIDATES <<<"$ORDER"', 1)[1].split("\nEVERUDP_BIN=", 1)[0]
        environment = dict(os.environ, NET=str(Path(__file__).resolve().parent),
                           ORDER="everudp-stream-native,everudp-stream-ordinary,zmosh-udp",
                           PATH_TRACE="0", NATIVE_TRACE="0", REACTOR_TRACE="0", PARTITION_TRACE="0",
                           EVERUDP_FLOOR_TRACE="0")
        environment.pop("EVERUDP_STREAM_PROFILE_DIR", None)
        result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + validation],
                                env=environment, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        for key in ("PATH_TRACE", "NATIVE_TRACE", "REACTOR_TRACE", "PARTITION_TRACE",
                    "EVERUDP_FLOOR_TRACE", "EVERUDP_STREAM_PROFILE_DIR"):
            with self.subTest(key=key):
                result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + validation],
                                        env=dict(environment, **{key: "1"}),
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertIn("stream timing cannot include", result.stderr)


if __name__ == "__main__":
    unittest.main()
