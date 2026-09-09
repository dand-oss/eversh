import unittest

from analyze_packet_protection import split_protection


def marker(name, time, cookie=7):
    return {"event": name, "time_ns": time, "values": [0, cookie, 12, 3, 1]}


class ProtectionTests(unittest.TestCase):
    def test_exact_pair(self):
        events = [marker("packet_protection_start", 110), marker("packet_protection_end", 130)]
        self.assertEqual(split_protection(events, [0, 7, 12, 3], 100, 140), {
            "reservation_to_protection_ns": 10, "protection_ns": 20,
            "protection_to_built_ns": 10})

    def test_missing_duplicate_reversed_and_outside_rejected(self):
        start, end = marker("packet_protection_start", 110), marker("packet_protection_end", 130)
        for events in ([start], [start, start, end], [end, start],
                       [marker("packet_protection_start", 99), end],
                       [start, marker("packet_protection_end", 141)]):
            with self.subTest(events=events), self.assertRaises(ValueError):
                split_protection(events, [0, 7, 12, 3], 100, 140)

    def test_wrong_identity_never_substituted(self):
        events = [marker("packet_protection_start", 110), marker("packet_protection_end", 130, 8)]
        with self.assertRaises(ValueError):
            split_protection(events, [0, 7, 12, 3], 100, 140)

    def test_other_packet_does_not_change_pair(self):
        events = [marker("packet_protection_start", 101, 8),
                  marker("packet_protection_start", 110), marker("packet_protection_end", 130)]
        self.assertEqual(split_protection(events, [0, 7, 12, 3], 100, 140)["protection_ns"], 20)
