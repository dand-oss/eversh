#!/usr/bin/env python3

import importlib.util
import math
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("stream_floor_statistics.py")
SPEC = importlib.util.spec_from_file_location("stream_floor_statistics", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
STATS = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = STATS
SPEC.loader.exec_module(STATS)


NATIVE = "everudp-stream-native"
ORDINARY = "everudp-stream-ordinary"
UDP = "zmosh-udp"
CANDIDATES = (NATIVE, ORDINARY, UDP)


class StreamFloorStatisticsTests(unittest.TestCase):
    def result(self, value: float, *, failures: int = 0, trials: int = 200):
        return {
            "schema_version": 1,
            "trials": trials,
            "gap_ms": 100,
            "samples_us": [value + (index % 3) for index in range(200)],
            "transcript_failures": failures,
            "public_clock": "CLOCK_MONOTONIC; local host and time namespace only",
            "clock_identity": {"boot_id": "test", "time_namespace_dev": 1, "time_namespace_ino": 2},
            "benchmark_pid": 1,
            "public_boundaries": [],
        }

    def blocks(self, native: float = 80, ordinary: float = 90, udp: float = 100):
        values = {NATIVE: native, ORDINARY: ordinary, UDP: udp}
        first = (NATIVE, ORDINARY, UDP)
        second = tuple(reversed(first))
        result = []
        for loss, order in ((0, first), (0, second), (5, first), (5, second)):
            result.append(
                STATS.Block(
                    loss,
                    order,
                    {name: self.result(value) for name, value in values.items()},
                    {NATIVE: 100, ORDINARY: 105, UDP: 100},
                )
            )
        return result

    def analyze_fast(self, blocks):
        # Keep unit tests deterministic and independent of the 20,000-sample
        # production bootstrap; the evaluator's validation and gate logic are
        # still exercised in full.
        with mock.patch.object(STATS, "_bootstrap_upper95", return_value=0.81):
            return STATS.analyze(blocks)

    def test_success_has_floor_only_pass_and_expected_ratios(self):
        report = self.analyze_fast(self.blocks())
        self.assertEqual(report["purpose"], "matched-reliable-stream-floor-quantitative")
        self.assertEqual(report["quantitative_gate_status"], "PASS")
        self.assertEqual(report["cells"]["0"]["ratios"]["native_vs_zmosh_udp"]["p50"], 81 / 101)
        self.assertTrue(report["cells"]["5"]["gate"]["pass"])
        self.assertTrue(report["bootstrap"]["upper95_reported_not_gating"])

    def test_latency_threshold_miss_fails(self):
        report = self.analyze_fast(self.blocks(native=91))
        self.assertEqual(report["quantitative_gate_status"], "FAIL")
        self.assertFalse(report["cells"]["0"]["gate"]["pass"])

    def test_exact_floor_boundaries_pass(self):
        # The fixture's repeating +0/+1/+2 pattern has median base+1, so
        # 89/99 produces the exact 90/100 boundary ratio.
        blocks = self.blocks(native=89, ordinary=94, udp=99)
        blocks = [
            STATS.Block(b.loss, b.order, b.results, {NATIVE: 160, ORDINARY: 100, UDP: 100})
            for b in blocks
        ]
        report = self.analyze_fast(blocks)
        self.assertEqual(report["quantitative_gate_status"], "PASS")
        self.assertEqual(report["cells"]["0"]["ratios"]["native_vs_zmosh_udp"]["p50"], 0.9)
        self.assertEqual(report["cells"]["0"]["packet_attempt_ratios_vs_zmosh_udp"][NATIVE], 1.6)
        self.assertTrue(report["cells"]["0"]["gate"]["pass"])

    def test_bootstrap_uses_block_stratified_choices(self):
        class DeterministicRandom:
            def __init__(self, seed):
                self.seed = seed
                self.calls = 0

            def choices(self, population, *, k):
                self.calls += 1
                return [population[0]] * k

        fake = DeterministicRandom(0)
        with mock.patch.object(STATS.random, "Random", return_value=fake):
            upper = STATS._bootstrap_upper95([[1.0, 2.0], [1.0, 2.0]], [[2.0, 4.0], [2.0, 4.0]], seed=7, resamples=2)
        self.assertEqual(upper, 0.5)
        self.assertEqual(fake.calls, 8)

    def test_bad_packet_block_cannot_be_hidden_by_pooled_ratio(self):
        blocks = self.blocks()
        blocks[0] = STATS.Block(
            blocks[0].loss,
            blocks[0].order,
            blocks[0].results,
            {NATIVE: 161, ORDINARY: 100, UDP: 100},
        )
        report = self.analyze_fast(blocks)
        self.assertLessEqual(
            report["cells"]["0"]["packet_attempt_ratios_vs_zmosh_udp"][NATIVE], 1.60
        )
        self.assertFalse(report["cells"]["0"]["gate"]["pass"])

    def test_bootstrap_rejects_nonfinite_resampled_ratio(self):
        # A finite pooled median does not guarantee finite resampled medians.
        with mock.patch.object(STATS.random.Random, "choices", side_effect=(
            [1.0e308, 1.0e308], [1.0, 1.0],
        )):
            with self.assertRaises(ValueError):
                STATS._bootstrap_upper95([[1.0, 1.0e308]], [[1.0, 1.0]], seed=7, resamples=1)

    def malformed_cases(self):
        base = self.blocks()
        yield "duplicate order", base[:1] + [STATS.Block(0, base[0].order, base[1].results, base[1].packet_attempts)] + base[2:]
        yield "missing candidate", [STATS.Block(b.loss, b.order, {NATIVE: b.results[NATIVE], UDP: b.results[UDP]}, b.packet_attempts) for b in base]
        yield "wrong trials", self.replace_result(base, NATIVE, lambda r: {**r, "trials": True})
        yield "trace failures", self.replace_result(base, NATIVE, lambda r: {**r, "transcript_failures": 1})
        yield "nonfinite", self.replace_result(base, NATIVE, lambda r: {**r, "samples_us": [math.inf] + r["samples_us"][1:]})
        yield "boolean sample", self.replace_result(base, NATIVE, lambda r: {**r, "samples_us": [True] + r["samples_us"][1:]})
        yield "negative sample", self.replace_result(base, NATIVE, lambda r: {**r, "samples_us": [0] + r["samples_us"][1:]})
        yield "bad packet attempts", [STATS.Block(b.loss, b.order, b.results, {**b.packet_attempts, NATIVE: True}) for b in base]
        yield "bad schema", self.replace_result(base, NATIVE, lambda r: {**r, "schema_version": 2})
        yield "bad gap", self.replace_result(base, NATIVE, lambda r: {**r, "gap_ms": 99})
        yield "missing schema", self.replace_result(base, NATIVE, lambda r: {key: value for key, value in r.items() if key != "schema_version"})
        yield "missing gap", self.replace_result(base, NATIVE, lambda r: {key: value for key, value in r.items() if key != "gap_ms"})

    def replace_result(self, blocks, candidate, transform):
        replaced = []
        for block in blocks:
            results = dict(block.results)
            results[candidate] = transform(results[candidate])
            replaced.append(STATS.Block(block.loss, block.order, results, block.packet_attempts))
        return replaced

    def test_malformed_evidence_is_rejected(self):
        for name, blocks in self.malformed_cases():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.analyze_fast(blocks)

    def test_wrong_block_count_and_loss_layout_are_rejected(self):
        with self.assertRaises(ValueError):
            self.analyze_fast(self.blocks()[:3])
        blocks = self.blocks()
        blocks[3] = STATS.Block(0, blocks[3].order, blocks[3].results, blocks[3].packet_attempts)
        with self.assertRaises(ValueError):
            self.analyze_fast(blocks)

    def test_derived_ratio_overflow_is_rejected(self):
        blocks = self.blocks()
        replaced = []
        for block in blocks:
            results = dict(block.results)
            results[NATIVE] = {**results[NATIVE], "samples_us": [1.0e308] * 200}
            results[UDP] = {**results[UDP], "samples_us": [1.0e-308] * 200}
            replaced.append(STATS.Block(block.loss, block.order, results, block.packet_attempts))
        with self.assertRaises(ValueError):
            self.analyze_fast(replaced)


if __name__ == "__main__":
    unittest.main()
