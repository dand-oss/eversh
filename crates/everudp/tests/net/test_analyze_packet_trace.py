import copy
import unittest

from analyze_packet_trace import analyze
from test_analyze_path_trace import pair
from test_packet_join import add_packet, event


def fixture():
    client, gateway, result = pair()
    gateway["pid"] = 12
    gateway["events"][0]["time_ns"] = 130
    cp = {**copy.deepcopy(client), "trace_kind": "quic_packets", "events": []}
    gp = {**copy.deepcopy(gateway), "trace_kind": "quic_packets", "events": []}
    cp["events"].append(event("operation", 111, [0, 2, 1, 7, 0x20, 0, 30]))
    add_packet(cp["events"], gp["events"], 4, 11, 21, 0, 30, 121)
    # The opposite direction uses a server unidirectional stream and the
    # receiver's local connection handle, not the sender's handle.
    tx, rx = [], []
    add_packet(tx, rx, 9, 22, 12, 0, 30, 153)
    for row in tx:
        row["values"][0] = 8
        if row["event"] == "stream_sent":
            row["values"][4] = 3
    for row in rx:
        if row["event"] != "datagram_received":
            row["values"][0] = 0
        if row["event"] == "stream_received":
            row["values"][4] = 3
    gp["events"].append(event("operation", 151, [8, 3, 9, 42, 0x40, 0, 30]))
    gp["events"].extend(tx)
    cp["events"].extend(rx)
    for trace in cp, gp:
        trace["events"].sort(key=lambda e: e["time_ns"])
    return client, gateway, result, cp, gp


class AnalyzePacketTests(unittest.TestCase):
    def test_public_trial_joins_both_directions(self):
        report = analyze(*fixture())
        self.assertFalse(report["qualification"])
        row = report["rows"][0]
        self.assertEqual(row["input"]["packet_number"], 4)
        self.assertEqual(row["output"]["packet_number"], 9)
        self.assertEqual(row["input"]["durations_ns"]["send_poll_to_userspace_receive"], 2)

    def test_wrong_identity_and_ambiguous_anchor_fail(self):
        args = fixture()
        args[3]["pid"] = 99
        with self.assertRaises(ValueError):
            analyze(*args)
        args = fixture()
        args[3]["events"].insert(0, copy.deepcopy(args[3]["events"][0]))
        with self.assertRaises(ValueError):
            analyze(*args)

    def test_application_boundary_before_completed_packet_fails(self):
        args = fixture()
        args[1]["events"][0]["time_ns"] = 123
        with self.assertRaises(ValueError):
            analyze(*args)


if __name__ == "__main__":
    unittest.main()
