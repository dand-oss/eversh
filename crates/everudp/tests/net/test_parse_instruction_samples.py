import unittest
from unittest.mock import patch

from parse_instruction_samples import parse


def row(symbol="everudp::client::send_input", pid=123, tid=123,
        time="12.123456789", event="instructions:u", ip="560fd4928005",
        dso="/tmp/everudp"):
    return f"{pid}/{tid} {time}: {event}: {ip} {symbol} ({dso})"


class InstructionSampleTests(unittest.TestCase):
    def test_perf_script_row_is_normalized_without_address_or_dso(self):
        result = parse(row(), {123: [123]})
        self.assertEqual(result, [{
            "pid": 123,
            "tid": 123,
            "time_ns": 12_123_456_789,
            "event": "instructions:u",
            "symbol": "everudp::client::send_input",
        }])

    def test_symbols_with_spaces_and_loss_word_are_samples(self):
        result = parse(row("[unknown] loss marker"), {123: [123]})
        self.assertEqual(result[0]["symbol"], "[unknown] loss marker")
        self.assertNotIn("ip", result[0])
        self.assertNotIn("dso", result[0])

    def test_scope_checks_process_and_thread(self):
        for bad in (row(pid=124), row(tid=124)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse(bad, {123: [123]})
        self.assertEqual(len(parse(row(tid=124), {123: [123, 124]})), 1)

    def test_only_instructions_user_event_is_accepted(self):
        for event in ("instructions:k", "cycles:u", "instructions", "cpu-clock:u"):
            with self.subTest(event=event), self.assertRaises(ValueError):
                parse(row(event=event), {123: [123]})

    def test_malformed_lost_and_empty_records_fail_closed(self):
        bad_records = (
            "",
            "\n  \n",
            "PERF_RECORD_LOST 9",
            "LOST 9 events",
            "warning: truncated",
            row().replace("560fd4928005", "not-an-ip", 1),
            row().replace(" (/tmp/everudp)", "", 1),
            row(time="12.123"),
        )
        for bad in bad_records:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse(bad, {123: [123]})

    def test_timestamps_are_monotonic_and_u64_bounded(self):
        for bad in (
            row() + "\n" + row(time="11.999999999"),
            row(time="18446744073709551615.000000000"),
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse(bad, {123: [123]})

    def test_scope_and_exports_are_bounded(self):
        for scope in ({}, {0: [1]}, {123: []}, {123: [True]}):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                parse(row(), scope)
        with patch("parse_instruction_samples.MAX_BYTES", 1), self.assertRaises(ValueError):
            parse(row(), {123: [123]})
        with patch("parse_instruction_samples.MAX_SAMPLES", 1), self.assertRaises(ValueError):
            parse(row() + "\n" + row(time="12.123456790"), {123: [123]})


if __name__ == "__main__":
    unittest.main()
