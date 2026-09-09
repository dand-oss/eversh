import copy
import unittest

from analyze_preframes import split_preframes


def event(stage, time, connection=3):
    return {"stage": stage, "time_ns": time, "connection": connection, "stream": None}


def fixture():
    return [event("driver_service", 110), event("protocol_transmit_start", 120),
            event("protocol_transmit_ready", 170)]


class PreframeTests(unittest.TestCase):
    def test_exact_partition(self):
        self.assertEqual(split_preframes(fixture(), 3, 100, 130, 150), {
            "reservation_to_service_ns": 10, "service_to_protocol_ns": 10,
            "protocol_to_frames_ns": 10, "reservation_ns": 100,
            "driver_service_ns": 110, "protocol_start_ns": 120,
            "frames_start_ns": 130, "built_ns": 150, "protocol_ready_ns": 170})

    def test_missing_duplicate_or_wrong_connection_service_rejected(self):
        for events in (fixture()[1:], [event("driver_service", 110), event("driver_service", 115),
                                      event("protocol_transmit_start", 120), event("protocol_transmit_ready", 170)],
                       [event("driver_service", 111, 4), *fixture()[1:]]):
            with self.subTest(events=events), self.assertRaises(ValueError):
                split_preframes(events, 3, 100, 130, 150)

    def test_protocol_must_enclose_frames_and_end_ready(self):
        variants = [
            [event("driver_service", 110), event("protocol_transmit_start", 120),
             event("protocol_transmit_ready", 129)],
            [event("driver_service", 110), event("protocol_transmit_start", 120),
             event("protocol_transmit_idle", 170)],
            [event("driver_service", 110), event("protocol_transmit_start", 120),
             event("protocol_transmit_ready", 170, 4)],
        ]
        for events in variants:
            with self.subTest(events=events), self.assertRaises(ValueError):
                split_preframes(events, 3, 100, 130, 150)

    def test_nested_incomplete_and_mismatched_protocol_calls_rejected(self):
        variants = [
            [event("driver_service", 110), event("protocol_transmit_start", 120),
             event("protocol_transmit_start", 125), event("protocol_transmit_ready", 170)],
            [event("driver_service", 110), event("protocol_transmit_start", 120)],
            [event("driver_service", 110), event("protocol_transmit_ready", 170)],
            [event("driver_service", 110), event("protocol_transmit_start", 120),
             event("protocol_transmit_ready", 170, 4)],
        ]
        for events in variants:
            with self.subTest(events=events), self.assertRaises(ValueError):
                split_preframes(events, 3, 100, 130, 150)

    def test_idle_pair_is_global_validity_but_not_candidate(self):
        events = fixture() + [event("protocol_transmit_start", 180),
                               event("protocol_transmit_idle", 190)]
        self.assertEqual(split_preframes(events, 3, 100, 130, 150)["protocol_ready_ns"], 170)

    def test_different_connection_protocol_is_not_substituted(self):
        events = [event("driver_service", 110), event("protocol_transmit_start", 120, 4),
                  event("protocol_transmit_ready", 170, 4)]
        with self.assertRaises(ValueError):
            split_preframes(events, 3, 100, 130, 150)

    def test_timestamps_and_field_shapes_fail_closed(self):
        events = fixture()
        events[1]["time_ns"] = 109
        with self.assertRaises(ValueError):
            split_preframes(events, 3, 100, 130, 150)
        malformed = copy.deepcopy(fixture())
        malformed[0]["connection"] = True
        with self.assertRaises(ValueError):
            split_preframes(malformed, 3, 100, 130, 150)
        malformed = copy.deepcopy(fixture())
        malformed[0]["connection"] = 1 << 64
        with self.assertRaises(ValueError):
            split_preframes(malformed, 3, 100, 130, 150)
        with self.assertRaises(ValueError):
            split_preframes(fixture(), 1 << 64, 100, 130, 150)


if __name__ == "__main__":
    unittest.main()
