import unittest
from unittest.mock import patch

from parse_cpu_samples import correlate, parse


def row(symbol="noq_proto::connection::Connection::detect_lost_packets",
        pid=123, tid=123, time="12.123456789", event="cpu-clock:u"):
    return f"{pid}/{tid} {time}: {event}: 560fd4928005 {symbol} (/tmp/everudp)"


class CpuSampleTests(unittest.TestCase):
    def test_correlation_excludes_edge_windows_and_keeps_zero_sample_trials(self):
        samples = [{"pid": pid, "time_ns": time, "event": "cpu-clock:u", "symbol": "f"}
                   for time, pid in ((0, 1), (5, 2), (20, 1), (30, 2), (90, 1), (100, 2))]
        bounds = [{"trial": i, "send_ns": a, "accepted_ns": b}
                  for i, (a, b) in enumerate(((1, 4), (10, 30), (40, 50), (91, 95)))]
        result = correlate(samples, bounds, {1: "client", 2: "gateway"})
        self.assertEqual(result["coverage_ns"], [5, 90])
        self.assertIn("excluded", result["rows"][0])
        self.assertIn("excluded", result["rows"][3])
        self.assertEqual(result["rows"][1]["samples"], 2)
        self.assertEqual(result["rows"][2], {"trial": 2, "samples": 0})
        self.assertEqual(result["outside_samples"], 4)

    def test_correlation_requires_samples_from_every_role(self):
        with self.assertRaises(ValueError):
            correlate([], [], {1: "client"})
        with self.assertRaises(ValueError):
            correlate([], [], {1: "client", 2: "client"})

    def test_loss_word_in_symbol_is_a_sample(self):
        result = parse(row(), {123: [123]})
        self.assertEqual(result[0]["time_ns"], 12_123_456_789)
        self.assertTrue(result[0]["symbol"].endswith("detect_lost_packets"))
        self.assertNotIn("ip", result[0])

    def test_kernel_unknown_and_scoped_secondary_thread(self):
        result = parse(row("[unknown]", tid=124, event="cpu-clock:k"), {123: [123, 124]})
        self.assertEqual(result[0]["symbol"], "[unknown]")

    def test_non_sample_records_fail_even_after_valid_samples(self):
        for bad in ("PERF_RECORD_LOST 9", "LOST 9 events", "warning: truncated",
                    row(time="12.123"), row(event="cycles:u")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse(row() + "\n" + bad, {123: [123]})

    def test_pid_and_tid_are_both_scoped(self):
        for bad in (row(pid=124), row(tid=124)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse(bad, {123: [123]})

    def test_regression_overflow_and_empty_fail(self):
        for bad in (row() + "\n" + row(time="11.999999999"),
                    row(time="18446744073709551615.000000000"), "\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse(bad, {123: [123]})

    def test_bounds_and_invalid_scope(self):
        for scope in ({}, {0: [1]}, {123: []}, {123: [True]}):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                parse(row(), scope)
        with patch("parse_cpu_samples.MAX_BYTES", 1), self.assertRaises(ValueError):
            parse(row(), {123: [123]})
        with patch("parse_cpu_samples.MAX_SAMPLES", 1), self.assertRaises(ValueError):
            parse(row() + "\n" + row(), {123: [123]})


if __name__ == "__main__":
    unittest.main()
