import copy
import unittest

from analyze_stdin_trace import split_window


def fixture():
    names = ("stdin_ready", "stdin_read_start", "stdin_read_end", "stdin_data", "stdin_dispatch")
    return [{"stage": name, "time_ns": 110 + 10 * i,
             "connection": None, "stream": None} for i, name in enumerate(names)]


class StdinTraceTests(unittest.TestCase):
    def test_exact_complete_window(self):
        report = split_window(fixture(), 100, 160)
        self.assertEqual(report["durations_ns"], {
            "public_send_to_ready": 10, "ready_to_read": 10,
            "read_call": 10, "read_end_to_data": 10,
            "data_to_dispatch": 10, "dispatch_to_queue": 10,
            "public_send_to_queue": 60})

    def test_missing_duplicate_and_reversed_markers_rejected(self):
        for index in range(5):
            for mode in ("missing", "duplicate", "outside"):
                events = fixture()
                if mode == "missing": events.pop(index)
                elif mode == "duplicate": events.insert(index, copy.deepcopy(events[index]))
                else: events[index]["time_ns"] = 99
                with self.subTest(index=index, mode=mode), self.assertRaises(ValueError):
                    split_window(events, 100, 160)
        events = fixture()
        events[1]["time_ns"], events[2]["time_ns"] = 130, 120
        with self.assertRaises(ValueError): split_window(events, 100, 160)

    def test_retry_is_explicitly_ambiguous_not_discarded(self):
        events = fixture()
        events.insert(0, {**events[0], "time_ns": 105})
        with self.assertRaises(ValueError): split_window(events, 100, 160)

    def test_other_io_and_prior_warmup_do_not_replace_current_read(self):
        events = [{**event, "time_ns": event["time_ns"] - 100} for event in fixture()]
        events += fixture() + [{"stage": "driver_poll", "time_ns": 155}]
        self.assertEqual(split_window(events, 100, 160)["durations_ns"]["read_call"], 10)


if __name__ == "__main__":
    unittest.main()
