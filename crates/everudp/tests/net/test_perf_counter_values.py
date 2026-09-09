import json
import unittest

from perf_counter_values import parse_counter_values


_PREFLIGHT = """\
{"counter-value" : "253195.000000", "unit" : "", "event" : "cycles:u", "event-runtime" : 467244, "pcnt-running" : 100.00}
{"counter-value" : "144651.000000", "unit" : "", "event" : "instructions:u", "event-runtime" : 467244, "pcnt-running" : 100.00}
{"counter-value" : "91.000000", "unit" : "", "event" : "cache-misses:u", "event-runtime" : 467244, "pcnt-running" : 100.00}
"""


def _records(text=_PREFLIGHT):
    return [json.loads(line) for line in text.splitlines() if line]


class PerfCounterValueTests(unittest.TestCase):
    def test_actual_perf_preflight_shape_is_normalized(self):
        result = parse_counter_values(_PREFLIGHT)

        self.assertEqual(result["events"], ["cycles:u", "instructions:u", "cache-misses:u"])
        self.assertEqual(
            result["counts"],
            {"cycles:u": 253195, "instructions:u": 144651, "cache-misses:u": 91},
        )
        self.assertEqual(
            result["runtime"],
            {"cycles:u": 467244, "instructions:u": 467244, "cache-misses:u": 467244},
        )
        self.assertAlmostEqual(result["ipc"], 144651 / 253195)
        self.assertAlmostEqual(result["cache_misses_per_instruction"], 91 / 144651)

    def test_only_the_observed_perf_keys_are_allowed(self):
        records = _records()
        records[0]["pid"] = 17
        text = "\n".join(json.dumps(record) for record in records) + "\n"
        with self.assertRaises(ValueError):
            parse_counter_values(text)

    def test_required_events_are_unique_and_complete(self):
        records = _records()
        for replacement in (
            {"event": "cycles:u"},
            {"event": "branches:u"},
        ):
            malformed = [dict(record) for record in records]
            malformed[-1].update(replacement)
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                parse_counter_values("\n".join(json.dumps(record) for record in malformed))

    def test_counter_values_must_be_finite_nonnegative_integers(self):
        for value in ("253195.5", "-1.000000", "NaN", "Infinity", "1e3"):
            records = _records()
            records[0]["counter-value"] = value
            text = "\n".join(json.dumps(record) for record in records)
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_counter_values(text)

    def test_runtime_and_percent_running_are_strict(self):
        cases = []
        records = _records()
        records[1]["event-runtime"] = 0
        cases.append(records)
        records = _records()
        records[1]["pcnt-running"] = 99.99
        cases.append(records)
        records = _records()
        records[1]["pcnt-running"] = "100.00"
        cases.append(records)
        records = _records()
        records[1]["unit"] = "cycles"
        cases.append(records)
        records = _records()
        records[1]["event-runtime"] = -1
        cases.append(records)
        for malformed in cases:
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                parse_counter_values("\n".join(json.dumps(record) for record in malformed))

    def test_per_event_runtime_differences_are_reported_not_rejected(self):
        records = _records()
        records[1]["event-runtime"] = 467245
        result = parse_counter_values("\n".join(json.dumps(record) for record in records))
        self.assertEqual(result["runtime"]["cycles:u"], 467244)
        self.assertEqual(result["runtime"]["instructions:u"], 467245)

    def test_empty_malformed_and_duplicate_records_fail_closed(self):
        for text in ("", "not json\n", _PREFLIGHT + _PREFLIGHT.splitlines()[0] + "\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_counter_values(text)

    def test_duplicate_json_fields_are_rejected(self):
        text = _PREFLIGHT.replace('"unit" : ""', '"unit" : "bogus", "unit" : ""', 1)
        with self.assertRaises(ValueError):
            parse_counter_values(text)

    def test_grouped_events_require_equal_runtimes(self):
        records = _records()
        records[1]["event-runtime"] += 1
        with self.assertRaises(ValueError):
            parse_counter_values("\n".join(json.dumps(record) for record in records), grouped=True)
        self.assertEqual(parse_counter_values(_PREFLIGHT, grouped=True)["ipc"], 144651 / 253195)

    def test_zero_instructions_is_rejected_before_derived_ratios(self):
        for index in (0, 1):
            records = _records()
            records[index]["counter-value"] = "0.000000"
            with self.subTest(index=index), self.assertRaises(ValueError):
                parse_counter_values("\n".join(json.dumps(record) for record in records))


if __name__ == "__main__":
    unittest.main()
