"""Synthetic causal joins; these tests do not measure transport performance."""
import copy
import unittest

from packet_join import correlate_operation


def event(name, time, values):
    return {"event": name, "time_ns": time, "values": values}


def fixture():
    operation = event("operation", 10, [0, 2, 1, 7, 0x20, 0, 30])
    sender = [operation]
    receiver = []
    add_packet(sender, receiver, 4, 11, 21, 0, 30, 20)
    return sender, receiver, operation


def add_packet(sender, receiver, pn, tx, rx, offset, length, time,
               packet_offset=0, tx_bytes=100, segment=0):
    sender.extend([
        event("packet_built", time, [0, tx, pn, 3, packet_offset, 100, 1]),
        event("stream_sent", time, [0, tx, pn, 3, 2, offset, length, 0]),
        event("packet_transmit_poll", time + 1, [0, tx, tx_bytes, segment]),
        event("packet_transmit_accepted", time + 2, [0, tx, tx_bytes, segment]),
    ])
    receiver.extend([
        event("datagram_received", time + 3, [rx, 100]),
        event("packet_authenticated", time + 4, [8, rx, pn, 3, 0, 100, 2]),
        event("stream_received", time + 5, [8, rx, pn, 3, 2, offset, length, 0]),
    ])


class PacketJoinTests(unittest.TestCase):
    def join(self, sender, receiver, operation):
        return correlate_operation(sorted(sender, key=lambda e: e["time_ns"]),
                                   sorted(receiver, key=lambda e: e["time_ns"]),
                                   operation, 100)

    def test_single_packet_zero_handle(self):
        result = self.join(*fixture())
        self.assertEqual(result["packet_number"], 4)
        self.assertEqual(result["operation_end"], 30)
        self.assertEqual(result["poll_ns"], 21)

    def test_sequential_operations_in_one_epoch_are_valid(self):
        sender, receiver, operation = fixture()
        sender.append(event("operation", 30, [0, 2, 1, 8, 0x21, 30, 18]))
        self.join(sender, receiver, operation)
        sender[-1]["values"][5] = 0
        with self.assertRaises(ValueError):
            self.join(sender, receiver, operation)

    def test_wrong_receiver_connection_and_packet_length_fail(self):
        for index, field, value in ((1, 0, 99), (1, 5, 99)):
            sender, receiver, operation = fixture()
            receiver[index]["values"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.join(sender, receiver, operation)

    def test_receiver_can_run_before_sender_records_acceptance(self):
        sender, receiver, operation = fixture()
        sender[-1]["time_ns"] = 50
        result = self.join(sender, receiver, operation)
        self.assertGreater(result["accepted_ns"], result["received_ns"])

    def test_blocked_retry_uses_successful_poll(self):
        sender, receiver, operation = fixture()
        sender.extend([
            event("packet_transmit_poll", 20, [0, 11, 100, 0]),
            event("packet_transmit_blocked", 20, [0, 11, 100, 0]),
        ])
        self.assertEqual(self.join(sender, receiver, operation)["poll_ns"], 21)

    def test_split_and_retransmit_completion(self):
        sender, receiver, operation = fixture()
        sender[2]["values"][6] = receiver[-1]["values"][6] = 15
        add_packet(sender, receiver, 5, 12, 22, 0, 15, 30)
        add_packet(sender, receiver, 6, 13, 23, 15, 15, 40)
        self.assertEqual(self.join(sender, receiver, operation)["packet_number"], 6)

    def test_coalesced_operation_range(self):
        sender, receiver, operation = fixture()
        operation["values"][5:7] = [5, 20]
        self.assertEqual(self.join(sender, receiver, operation)["operation_end"], 25)

    def test_gso_offset_is_within_one_segment(self):
        sender, receiver, operation = fixture()
        sender[1]["values"][4] = 100
        for row in sender[3:]:
            row["values"][2:] = [200, 100]
        self.join(sender, receiver, operation)
        sender[1]["values"][4] = 50
        with self.assertRaises(ValueError):
            self.join(sender, receiver, operation)

    def test_missing_each_join_is_rejected(self):
        for side, names in ((0, ("packet_built", "stream_sent", "packet_transmit_poll",
                                 "packet_transmit_accepted")),
                            (1, ("datagram_received", "packet_authenticated", "stream_received"))):
            for name in names:
                args = list(fixture())
                args[side] = [row for row in args[side] if row["event"] != name]
                with self.subTest(name=name), self.assertRaises(ValueError):
                    self.join(*args)

    def test_duplicate_packet_identity_rejected(self):
        sender, receiver, operation = fixture()
        sender.append(copy.deepcopy(sender[1]))
        with self.assertRaises(ValueError):
            self.join(sender, receiver, operation)

    def test_missing_coverage_and_wrong_range_rejected(self):
        for both in (False, True):
            sender, receiver, operation = fixture()
            receiver[-1]["values"][6] = 29
            if both:
                sender[2]["values"][6] = 29
            with self.subTest(both=both), self.assertRaises(ValueError):
                self.join(sender, receiver, operation)

    def test_reconnect_is_explicitly_unsupported(self):
        sender, receiver, operation = fixture()
        other = copy.deepcopy(operation)
        other["values"][0] = 1
        sender.append(other)
        with self.assertRaises(ValueError):
            self.join(sender, receiver, operation)

    def test_causality_and_transmit_metadata_rejected(self):
        sender, receiver, operation = fixture()
        receiver[0]["time_ns"] = 19
        with self.assertRaises(ValueError):
            self.join(sender, receiver, operation)
        sender, receiver, operation = fixture()
        sender[-1]["values"][2] = 99
        with self.assertRaises(ValueError):
            self.join(sender, receiver, operation)


if __name__ == "__main__":
    unittest.main()
