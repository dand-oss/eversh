import copy
import unittest

from syscall_pairs import pair_syscalls


def event(time, name, fields):
    return {"time_ns": time, "event": "syscalls:sys_" + name, "fields": fields}


def fixture():
    return {"schema_version": 1, "events": [
        event(10, "exit_poll", {"ret": 0}),
        event(20, "enter_read", {"fd": 0, "count": 1}),
        event(30, "exit_read", {"ret": 1}),
        event(40, "enter_recvmmsg", {"fd": 7, "vlen": 16, "flags": 64}),
        event(50, "exit_recvmmsg", {"ret": -11}),
        event(60, "enter_poll", {"nfds": 4, "timeout_msecs": -1}),
    ]}


class SyscallPairTests(unittest.TestCase):
    def test_zmosh_syscalls_and_msg_trunc(self):
        for flags, returned, valid in ((0, 4, True), (0, 5, False), (0x20, 5, True)):
            trace = {"schema_version": 1, "events": [
                event(10, "enter_sendto", {"fd": 7, "len": 4, "flags": 0, "addr_len": 16}),
                event(20, "exit_sendto", {"ret": 4}),
                event(30, "enter_recvfrom", {"fd": 7, "size": 4, "flags": flags}),
                event(40, "exit_recvfrom", {"ret": returned}),
            ]}
            if valid:
                self.assertEqual(len(pair_syscalls(trace)["pairs"]), 2)
            else:
                with self.assertRaises(ValueError):
                    pair_syscalls(trace)

    def test_partial_edges_and_eagain_are_preserved(self):
        report = pair_syscalls(fixture())
        self.assertEqual(report["coverage_ns"], [10, 60])
        self.assertEqual([p["ret"] for p in report["pairs"]], [1, -11])
        self.assertEqual([e["edge"] for e in report["partial_edges"]],
                         ["initial_exit", "final_enter"])

    def test_invalid_edges_and_fields_fail_closed(self):
        cases = []
        for index, replacement in (
            (2, event(30, "exit_write", {"ret": 1})),
            (2, event(30, "enter_poll", {"nfds": 1, "timeout_msecs": 0})),
            (2, event(19, "exit_read", {"ret": 1})),
            (2, event(30, "exit_read", {"ret": 2})),
            (2, event(30, "exit_read", {"ret": True})),
            (1, event(20, "enter_read", {"fd": 0, "count": 1, "buf": 123})),
            (4, event(50, "exit_recvmmsg", {"ret": 17})),
            (4, event(50, "exit_unknown", {"ret": 0})),
        ):
            case = copy.deepcopy(fixture())
            case["events"][index] = replacement
            cases.append(case)
        orphan = fixture()
        orphan["events"].insert(1, event(15, "exit_poll", {"ret": 0}))
        cases.append(orphan)
        cases.extend([{}, {"schema_version": True, "events": []}])
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                pair_syscalls(case)


if __name__ == "__main__":
    unittest.main()
