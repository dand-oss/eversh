#!/usr/bin/env python3

import importlib.util
from dataclasses import replace
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).with_name("packet_accounting.py")
SPEC = importlib.util.spec_from_file_location("packet_accounting", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ACCOUNTING = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ACCOUNTING
SPEC.loader.exec_module(ACCOUNTING)


FIXTURE_ROOT = (
    Path(__file__).parents[4]
    / "docs"
    / "release-evidence"
    / "20260907-everudp-floor-b91b75b"
    / "loss0-block1"
)


def qdisc(sent: int, dropped: int, handle: str = "877d:", seed: int = 74001) -> str:
    return (
        f"qdisc netem {handle} root refcnt 49 limit 1000 seed {seed}\n"
        f" Sent {sent * 120} bytes {sent} pkt (dropped {dropped}, overlimits 0 requeues 0) \n"
        " backlog 0b 0p requeues 0\n"
    )


class PacketAccountingTests(unittest.TestCase):
    def test_parses_real_sealed_tc_fixture(self):
        before = (FIXTURE_ROOT / "netem-everudp-floor-client-before.txt").read_text()
        after = (FIXTURE_ROOT / "netem-everudp-floor-client-after.txt").read_text()
        parsed_before = ACCOUNTING.parse_root_netem(before)
        parsed_after = ACCOUNTING.parse_root_netem(after)
        self.assertEqual(parsed_before.handle, "877d:")
        self.assertEqual(parsed_after.sent_packets, 445)
        self.assertEqual(ACCOUNTING.derive_attempt_delta(parsed_before, parsed_after).attempts, 445)

    def test_sums_sent_and_netem_dropped_for_both_directions(self):
        result = ACCOUNTING.account_packet_attempts(
            qdisc(10, 2),
            qdisc(19, 5),
            qdisc(11, 1, handle="877e:", seed=1074004),
            qdisc(18, 4, handle="877e:", seed=1074004),
        )
        self.assertEqual(result.client.sent_packets, 9)
        self.assertEqual(result.client.dropped_packets, 3)
        self.assertEqual(result.server.sent_packets, 7)
        self.assertEqual(result.server.dropped_packets, 3)
        self.assertEqual(result.total_attempts, 22)

    def test_child_qdisc_is_not_double_counted(self):
        root = qdisc(100, 8)
        child = (
            "qdisc pfifo_fast 10: parent 877d:1 limit 1000\n"
            " Sent 999999 bytes 9999 pkt (dropped 777, overlimits 0 requeues 0)\n"
        )
        parsed = ACCOUNTING.parse_root_netem(root + child)
        self.assertEqual(parsed.sent_packets, 100)
        self.assertEqual(parsed.dropped_packets, 8)

    def test_rejects_missing_root(self):
        with self.assertRaisesRegex(ACCOUNTING.PacketAccountingError, "missing root"):
            ACCOUNTING.parse_root_netem(
                "qdisc netem 877d: parent 1:1 limit 1000\n"
                " Sent 10 bytes 1 pkt (dropped 0, overlimits 0 requeues 0)\n"
            )

    def test_rejects_wrong_root(self):
        with self.assertRaisesRegex(ACCOUNTING.PacketAccountingError, "wrong root"):
            ACCOUNTING.parse_root_netem(
                "qdisc pfifo_fast 877d: root limit 1000\n"
                " Sent 10 bytes 1 pkt (dropped 0, overlimits 0 requeues 0)\n"
            )

    def test_rejects_ambiguous_roots(self):
        with self.assertRaisesRegex(ACCOUNTING.PacketAccountingError, "ambiguous"):
            ACCOUNTING.parse_root_netem(qdisc(1, 0) + qdisc(2, 0, handle="877e:"))

    def test_rejects_missing_or_malformed_stats(self):
        with self.assertRaises(ACCOUNTING.PacketAccountingError):
            ACCOUNTING.parse_root_netem("qdisc netem 877d: root limit 1000\n backlog 0b 0p\n")
        with self.assertRaises(ACCOUNTING.PacketAccountingError):
            ACCOUNTING.parse_root_netem(
                "qdisc netem 877d: root limit 1000\n"
                " Sent not-a-counter bytes ??? pkt (dropped 0)\n"
            )

    def test_rejects_counter_regression(self):
        with self.assertRaisesRegex(ACCOUNTING.PacketAccountingError, "regressed"):
            ACCOUNTING.derive_attempt_delta(
                ACCOUNTING.parse_root_netem(qdisc(10, 3)),
                ACCOUNTING.parse_root_netem(qdisc(9, 4)),
            )
        with self.assertRaisesRegex(ACCOUNTING.PacketAccountingError, "regressed"):
            ACCOUNTING.derive_attempt_delta(
                ACCOUNTING.parse_root_netem(qdisc(10, 3)),
                ACCOUNTING.parse_root_netem(qdisc(10, 2)),
            )
        before = ACCOUNTING.parse_root_netem(qdisc(10, 3))
        after = replace(
            ACCOUNTING.parse_root_netem(qdisc(11, 3)),
            sent_bytes=before.sent_bytes - 1,
        )
        with self.assertRaisesRegex(ACCOUNTING.PacketAccountingError, "byte counter"):
            ACCOUNTING.derive_attempt_delta(before, after)

    def test_rejects_qdisc_identity_change(self):
        with self.assertRaisesRegex(ACCOUNTING.PacketAccountingError, "identity"):
            ACCOUNTING.derive_attempt_delta(
                ACCOUNTING.parse_root_netem(qdisc(10, 0, seed=74001)),
                ACCOUNTING.parse_root_netem(qdisc(11, 0, seed=74002)),
            )

    def test_rejects_zero_total_denominator(self):
        with self.assertRaisesRegex(ACCOUNTING.PacketAccountingError, "zero"):
            ACCOUNTING.account_packet_attempts(
                qdisc(0, 0), qdisc(0, 0), qdisc(0, 0, "877e:", 1074004), qdisc(0, 0, "877e:", 1074004)
            )

    def test_mapping_wrapper_requires_both_directions(self):
        with self.assertRaisesRegex(ACCOUNTING.PacketAccountingError, "missing qdisc direction"):
            ACCOUNTING.account_directions({"client": qdisc(1, 0)}, {"client": qdisc(2, 0)})


if __name__ == "__main__":
    unittest.main()
