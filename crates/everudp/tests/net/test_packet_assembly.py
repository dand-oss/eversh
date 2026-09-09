"""Strict joins for frame-population intervals, including hostile evidence."""
import unittest

from analyze_packet_protection import split_assembly
from validate_packet_trace import _check_values


def marker(name, time, identity=(0, 7, 8, 3), direction=1):
    return {"event": name, "time_ns": time, "values": [*identity, direction]}


def fixture():
    return [marker("packet_frames_start", 110), marker("packet_frames_end", 120),
            marker("packet_protection_start", 130), marker("packet_protection_end", 140)]


class AssemblyTests(unittest.TestCase):
    def test_partitions_are_exact_and_nonoverlapping(self):
        self.assertEqual(split_assembly(fixture(), [0, 7, 8, 3], 100, 145), {
            "reservation_to_frames_ns": 10, "frame_population_ns": 10,
            "frames_to_protection_ns": 10, "protection_ns": 10,
            "protection_to_built_ns": 5})

    def test_missing_duplicate_wrong_identity_or_direction_rejected(self):
        events = fixture()
        variants = [events[1:], events[:1] + events, events[:1] + events[2:],
                    [marker("packet_frames_start", 110, direction=2)] + events[1:],
                    [marker("packet_frames_start", 110, identity=(1, 7, 8, 3))] + events[1:]]
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                split_assembly(variant, [0, 7, 8, 3], 100, 145)

    def test_crossed_or_outside_boundaries_rejected(self):
        for index, time in ((0, 99), (1, 131), (2, 119), (3, 146)):
            events = fixture()
            events[index]["time_ns"] = time
            with self.subTest(index=index), self.assertRaises(ValueError):
                split_assembly(events, [0, 7, 8, 3], 100, 145)

    def test_other_packet_does_not_contaminate_exact_join(self):
        events = [marker("packet_frames_start", 105, identity=(0, 9, 8, 3)), *fixture()]
        self.assertEqual(split_assembly(events, [0, 7, 8, 3], 100, 145)["frame_population_ns"], 10)

    def test_validator_enforces_frame_marker_shape(self):
        for name in ("packet_frames_start", "packet_frames_end"):
            _check_values(name, [0, 7, 8, 3, 1], "client")
            for values in ([0, 0, 8, 3, 1], [0, 7, 8, 4, 1], [0, 7, 8, 3, 2],
                           [0, 7, 1 << 62, 3, 1], [0, 7, 8, 3, True], [0, 7, 8, 3]):
                with self.subTest(name=name, values=values), self.assertRaises(ValueError):
                    _check_values(name, values, "client")


if __name__ == "__main__":
    unittest.main()
