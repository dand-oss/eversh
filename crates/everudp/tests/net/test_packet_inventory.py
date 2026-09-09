import copy
import unittest

from packet_inventory import inventory
from test_validate_packet_trace import fixture, packet


class PacketInventoryTests(unittest.TestCase):
    def make(self):
        trace, base = fixture()
        trace["events"][0]["time_ns"] = 110
        trace["events"].sort(key=lambda event: event["time_ns"])
        return trace, base

    def test_stream_classification_and_half_open_window(self):
        trace, base = self.make()
        self.assertEqual(inventory(trace, base, "client", 100, 111)["packets_by_streams"], {"2": 1})
        self.assertEqual(inventory(trace, base, "client", 100, 110)["packets_by_streams"], {})

    def test_mixed_streams_are_one_packet_and_nonstream_is_not_called_ack(self):
        trace, base = self.make()
        trace["events"].insert(2, packet("stream_sent", 102, [4, 7, 8, 3, 0, 0, 14, 0]))
        self.assertEqual(inventory(trace, base, "client", 100, 111)["packets_by_streams"], {"0+2": 1})
        trace["events"] = [event for event in trace["events"] if event["event"] != "stream_sent"]
        self.assertEqual(inventory(trace, base, "client", 100, 111)["packets_by_streams"], {"no_stream": 1})

    def test_duplicate_packet_or_orphan_stream_is_invalid(self):
        for kind in ("duplicate", "orphan"):
            trace, base = self.make()
            if kind == "duplicate":
                trace["events"].insert(1, copy.deepcopy(trace["events"][0]))
            else:
                next(event for event in trace["events"] if event["event"] == "stream_sent")["values"][2] += 1
            with self.assertRaises(ValueError):
                inventory(trace, base, "client", 100, 111)

    def test_unsent_packets_are_reported_not_counted(self):
        trace, base = self.make()
        trace["events"] = [event for event in trace["events"] if event["event"] != "packet_transmit_accepted"]
        result = inventory(trace, base, "client", 100, 111)
        self.assertEqual(result["packets_by_streams"], {})
        self.assertEqual(result["built_without_accepted_transmit"], 1)


if __name__ == "__main__":
    unittest.main()
