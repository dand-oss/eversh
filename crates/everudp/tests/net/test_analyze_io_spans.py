import unittest

from analyze_io_spans import coverage, pair


def event(stage, timestamp, connection=None):
    return {"stage": stage, "time_ns": timestamp, "connection": connection, "stream": None}


class IoSpansTests(unittest.TestCase):
    def test_ready_idle_blocked_error_and_zero_duration(self):
        for start, ends, connection in (
                ("protocol_transmit_start", ("protocol_transmit_ready", "protocol_transmit_idle"), 0),
                ("transmit_poll", ("transmit_accepted", "transmit_blocked", "transmit_error"), None)):
            for end in ends:
                with self.subTest(end=end):
                    spans = pair([event(start, 1, connection), event(end, 1, connection)])
                    self.assertEqual(spans[0][:2], (1, 1))

    def test_malformed_boundaries_fail(self):
        start = event("protocol_transmit_start", 2, 0)
        end = event("protocol_transmit_ready", 3, 0)
        for events in ([end], [start], [start, start, end],
                       [start, event("transmit_accepted", 3)],
                       [start, event("protocol_transmit_ready", 3, 1)],
                       [start, event("protocol_transmit_ready", 1, 0)]):
            with self.subTest(events=events), self.assertRaises(ValueError):
                pair(events)

    def test_unrelated_events_do_not_end_a_call(self):
        self.assertEqual(pair([event("transmit_poll", 1), event("driver_poll", 2),
                               event("transmit_accepted", 3)]), [(1, 3, "send")])

    def test_clip_both_edges_and_keep_residual(self):
        self.assertEqual(coverage([(0, 4, "protocol"), (6, 10, "send")], 2, 8),
                         {"window_ns": 6, "protocol_ns": 2, "send_ns": 2,
                          "residual_ns": 2, "clipped_calls": 2})

    def test_disjoint_and_boundary_touch_do_not_count(self):
        self.assertEqual(coverage([(0, 2, "send"), (8, 10, "protocol")], 2, 8),
                         {"window_ns": 6, "protocol_ns": 0, "send_ns": 0,
                          "residual_ns": 6, "clipped_calls": 0})

    def test_invalid_spans_and_window_fail(self):
        for spans in ([(3, 2, "send")], [(0, 4, "send"), (3, 5, "protocol")],
                      [(0, 1, "unknown")]):
            with self.subTest(spans=spans), self.assertRaises(ValueError):
                coverage(spans, 0, 10)
        with self.assertRaises(ValueError):
            coverage([], 2, 1)


if __name__ == "__main__":
    unittest.main()
