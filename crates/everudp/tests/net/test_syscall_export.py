import unittest

from syscall_export import ExportError, parse


TRACE = """\
100.000000001: syscalls:sys_enter_poll: ufds: 0x1000, nfds: 0x00000004, timeout_msecs: 0xffffffffffffffff
100.000000002: syscalls:sys_exit_poll: 0xffffffffffffffff
100.000000003: syscalls:sys_enter_read: fd: 0x00000000, buf: 0x2000, count: 0x00000010
100.000000004: syscalls:sys_exit_read: 0x1
100.000000005: syscalls:sys_enter_write: fd: 0x00000001, buf: 0x3000, count: 0x1
100.000000006: syscalls:sys_exit_write: 0x1
100.000000007: syscalls:sys_enter_sendmsg: fd: 0x2, msg: 0x4000, flags: 0x0
100.000000008: syscalls:sys_exit_sendmsg: 0x2
100.000000009: syscalls:sys_enter_sendmmsg: fd: 0x2, mmsg: 0x4000, vlen: 0x2, flags: 0x0
100.000000010: syscalls:sys_exit_sendmmsg: 0x2
100.000000011: syscalls:sys_enter_recvmsg: fd: 0x2, msg: 0x4000, flags: 0x0
100.000000012: syscalls:sys_exit_recvmsg: 0x2
100.000000013: syscalls:sys_enter_recvmmsg: fd: 0x2, mmsg: 0x4000, vlen: 0x2, flags: 0x0, timeout: 0x5000
100.000000014: syscalls:sys_exit_recvmmsg: 0x2
"""


class SyscallExportTests(unittest.TestCase):
    def test_raw_write_omits_buffer_and_unused_arguments(self):
        trace = ("100.000000001: raw_syscalls:sys_enter: NR 1 (1, abc123, 1, aa, bb, cc)\n"
                 "100.000000002: raw_syscalls:sys_exit: NR 1 = 1\n")
        events = parse(trace)["events"]
        self.assertEqual(events[0]["event"], "syscalls:sys_enter_write")
        self.assertEqual(events[0]["fields"], {"fd": 1, "count": 1})
        self.assertEqual(events[1]["fields"], {"ret": 1})
        for bad in (trace.replace("NR 1", "NR 2"),
                    trace.replace("abc123", "10000000000000000"),
                    trace.replace("= 1", "= 9223372036854775808"),
                    trace.replace("1, aa, bb, cc", "1, aa, bb")):
            with self.subTest(trace=bad), self.assertRaises(ExportError):
                parse(bad)

    def test_export_is_pointer_free_and_signed(self):
        report = parse(TRACE)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["events"][0], {
        "time_ns": 100_000_000_001,
        "event": "syscalls:sys_enter_poll",
        "fields": {"nfds": 4, "timeout_msecs": -1},
        })
        self.assertEqual(report["events"][1]["fields"], {"ret": -1})
        self.assertTrue(all(not any(key in event["fields"] for key in ("buf", "ufds", "msg", "mmsg", "timeout")) for event in report["events"]))

    def test_export_fails_closed(self):
        cases = [
            TRACE.replace("nfds: 0x00000004", "nfds: 0x00000004, nope: 1"),
            TRACE.replace("buf: 0x2000, ", ""),
            TRACE.replace("100.000000004", "99.000000004"),
            TRACE.replace("sys_exit_read: 0x1", "sys_exit_read: nope"),
            TRACE.replace("sys_enter_read", "sys_enter_open"),
            TRACE.replace("100.000000001", "100.000000001: LOST"),
        ]
        for bad in cases:
            with self.subTest(case=bad):
                with self.assertRaises(ExportError):
                    parse(bad)

    def test_integer_widths_and_unsigned_rejection(self):
        self.assertEqual(parse(TRACE)["events"][0]["fields"]["timeout_msecs"], -1)
        # Scalar parsing is width-aware: unsigned arguments reject negatives,
        # while signed returns and int32 timeout values accept only canonical
        # two's-complement spellings.
        cases = [
            ("fd: 0x10000000000000000", "unsigned overflow"),
            ("fd: -1", "unsigned negative"),
            ("sys_exit_read: 0x10000000000000000", "signed overflow"),
            ("sys_exit_read: 9223372036854775808", "signed decimal overflow"),
            ("timeout_msecs: 0x1ffffffff", "non-sign-extended int32"),
        ]
        for replacement, label in cases:
            candidate = TRACE
            if replacement.startswith("fd:"):
                candidate = TRACE.replace("fd: 0x00000000", replacement, 1)
            elif replacement.startswith("sys_exit_read:"):
                candidate = TRACE.replace("sys_exit_read: 0x1", replacement, 1)
            else:
                candidate = TRACE.replace("timeout_msecs: 0xffffffffffffffff", replacement, 1)
            with self.subTest(raw=replacement, label=label), self.assertRaises(ExportError):
                parse(candidate)
        valid_timeout = TRACE.replace(
            "timeout_msecs: 0xffffffffffffffff", "timeout_msecs: 0xffffffff", 1
        )
        self.assertEqual(parse(valid_timeout)["events"][0]["fields"]["timeout_msecs"], -1)

    def test_sendto_and_recvfrom_pointer_whitelist(self):
        report = parse("""\
100.000000001: syscalls:sys_enter_sendto: fd: 0x2, buff: 0x1000, len: 0x4, flags: 0x0, addr: 0x2000, addr_len: 0x10
100.000000002: syscalls:sys_exit_sendto: 0x4
100.000000003: syscalls:sys_enter_recvfrom: fd: 0x2, ubuf: 0x1000, size: 0x4, flags: 0x0, addr: 0x2000, addr_len: 0x3000
100.000000004: syscalls:sys_exit_recvfrom: 0x4
""")
        self.assertEqual(report["events"][0]["fields"], {"fd": 2, "len": 4, "flags": 0, "addr_len": 16})
        self.assertEqual(report["events"][2]["fields"], {"fd": 2, "size": 4, "flags": 0})


if __name__ == "__main__":
    unittest.main()
