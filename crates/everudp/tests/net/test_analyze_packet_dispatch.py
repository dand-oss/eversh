import copy
import unittest

from analyze_packet_dispatch import split_window


def fixture():
    packet = {"stream_received_ns": 100, "receiver_boundary_ns": 200,
              "packet_number": 7, "number_space": 3, "stream": 2}
    received = [{"event": "stream_received", "time_ns": 100,
                 "values": [0, 8, 7, 3, 2, 0, 15, 0]}]
    events = [{"stage": "stream_readable", "time_ns": 150, "connection": 0, "stream": 2}]
    return packet, received, events, [(110, 130, "protocol"), (135, 145, "send")]


class DispatchTests(unittest.TestCase):
    def test_exact_connection_and_packet_window(self):
        result = split_window(*fixture())
        self.assertEqual(result["before_notification"], {
            "window_ns": 50, "protocol_ns": 20, "send_ns": 10,
            "clipped_calls": 0, "residual_ns": 20})
        self.assertEqual(result["after_notification"]["residual_ns"], 50)

    def test_missing_duplicate_or_wrong_connection_marker_rejected(self):
        for mode in ("missing", "duplicate", "connection", "stream", "time"):
            args = list(fixture())
            if mode == "missing": args[2] = []
            elif mode == "duplicate": args[2] *= 2
            elif mode == "connection": args[2][0]["connection"] = 1
            elif mode == "stream": args[2][0]["stream"] = 3
            else: args[2][0]["time_ns"] = 99
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                split_window(*args)

    def test_duplicate_packet_anchor_rejected(self):
        args = list(fixture())
        args[1].append(copy.deepcopy(args[1][0]))
        with self.assertRaises(ValueError): split_window(*args)

    def test_calls_crossing_notification_are_clipped_not_double_counted(self):
        args = list(fixture())
        args[3] = [(140, 160, "send")]
        result = split_window(*args)
        self.assertEqual(result["before_notification"]["send_ns"], 10)
        self.assertEqual(result["after_notification"]["send_ns"], 10)


if __name__ == "__main__":
    unittest.main()
