#!/usr/bin/env python3

import importlib.util
import unittest
import json
import hashlib
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("analyze-performance.py")
SPEC = importlib.util.spec_from_file_location("analyze_performance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)


class AnalyzePerformanceTests(unittest.TestCase):
    def test_diagnostic_manifest_cannot_enter_qualification(self):
        for flag in ("diagnostic_tracing", "production_path_tracing", "production_io_tracing", "production_packet_tracing", "native_stage_tracing",
                     "reactor_work_tracing", "reactor_partition_tracing"):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = root / "manifest.json"
                manifest.write_text(json.dumps({"schema_version": 1, flag: True}), encoding="utf-8")
                (root / "SHA256SUMS").write_text(
                    hashlib.sha256(manifest.read_bytes()).hexdigest() + "  manifest.json\n",
                    encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "diagnostic tracing"):
                    ANALYZER.load_block(root, 200)

    def test_io_sidecar_cannot_qualify_with_false_trace_flags(self):
        for name in ("client-path-trace.json.io.json", "gateway-path-trace.json.io.json",
                     "client-path-trace.json.packets.json", "gateway-path-trace.json.packets.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "everudp").mkdir()
                files = {
                    "manifest.json": json.dumps({"schema_version": 1,
                        "diagnostic_tracing": False, "production_io_tracing": False}),
                    f"everudp/{name}": "{}",
                }
                for path, value in files.items():
                    (root / path).write_text(value, encoding="utf-8")
                (root / "SHA256SUMS").write_text("".join(
                    hashlib.sha256((root / path).read_bytes()).hexdigest() + f"  {path}\n"
                    for path in files), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "diagnostic tracing"):
                    ANALYZER.load_block(root, 200)

    def blocks(self, everudp: int, udp: int, quic: int):
        return [
            {
                "everudp": [everudp + index % 3 for index in range(40)],
                "zmosh-udp": [udp + index % 3 for index in range(40)],
                "zmosh-quic": [quic + index % 3 for index in range(40)],
            }
            for _ in range(6)
        ]

    def test_clear_win_passes_all_thresholds(self):
        result = ANALYZER.compare(self.blocks(500, 1000, 1200), "zmosh-udp", 500, 7)
        self.assertTrue(result["gate"]["pass"])
        self.assertLess(result["bootstrap"]["p95_ratio_upper95"], 1.0)

    def test_slow_p50_fails_point_rule(self):
        result = ANALYZER.compare(self.blocks(1100, 1000, 1200), "zmosh-udp", 500, 7)
        self.assertFalse(result["gate"]["p50_point_at_most_1_00"])
        self.assertFalse(result["gate"]["pass"])

    def test_nearest_rank_rejects_empty_input(self):
        with self.assertRaises(ValueError):
            ANALYZER.nearest_rank([], 0.5)


if __name__ == "__main__":
    unittest.main()
