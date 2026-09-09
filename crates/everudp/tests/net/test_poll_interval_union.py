import copy
import unittest

from poll_interval_union import combine


def fixture():
    result = {
        "trials": 3,
        "samples_us": [1, 1, 1],
        "transcript_failures": 0,
        "public_clock": "CLOCK_MONOTONIC; local host and time namespace only",
        "public_boundaries": [
            {"trial": 0, "send_ns": 100, "accepted_ns": 200},
            {"trial": 1, "send_ns": 300, "accepted_ns": 400},
            {"trial": 2, "send_ns": 500, "accepted_ns": 600},
        ],
    }

    def report(pid, intervals):
        rows = []
        for trial, values in enumerate(intervals):
            duration = sum(end - start for start, end in values)
            rows.append({
                "trial": trial,
                "status": "included",
                "zero_timeout_polls": len(values),
                "zero_poll_syscall_ns": duration,
                "zero_poll_intervals_ns": values,
            })
        return {"status": "DIAGNOSTIC", "target_pid": pid, "rows": rows}

    client = report(101, [[[110, 120]], [[310, 320]], []])
    server = report(202, [[[115, 130]], [[330, 350]], []])
    return result, client, server


class PollIntervalUnionTests(unittest.TestCase):
    def test_overlap_disjoint_and_empty_union(self):
        result, client, server = fixture()
        report = combine(result, client, server)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual([row["union_ns"] for row in report["rows"]], [20, 30, 0])
        self.assertEqual(report["rows"][0]["union_intervals_ns"], [[110, 130]])
        self.assertEqual(report["rows"][1]["union_intervals_ns"], [[310, 320], [330, 350]])
        self.assertEqual(report["aggregate"], {
            "included_trials": 3,
            "median_union_ns": 20,
            "p95_union_ns": 30,
        })

    def test_only_both_included_trials_are_aggregated(self):
        result, client, server = fixture()
        client["rows"][1] = {"trial": 1, "status": "excluded", "exclusion": "outside_coverage"}
        report = combine(result, client, server)
        self.assertEqual(report["rows"][1]["status"], "excluded")
        self.assertEqual(report["rows"][1]["exclusion"], "client_excluded")
        self.assertEqual(report["aggregate"]["included_trials"], 2)
        self.assertEqual(report["aggregate"]["median_union_ns"], 10)

    def test_fail_closed_malformed_matrix(self):
        result, client, server = fixture()
        cases = []

        same_pid = copy.deepcopy(server)
        same_pid["target_pid"] = client["target_pid"]
        cases.append((client, same_pid))

        bad_status = copy.deepcopy(client)
        bad_status["status"] = "UNKNOWN"
        cases.append((bad_status, server))

        duplicate = copy.deepcopy(client)
        duplicate["rows"][1]["trial"] = 0
        cases.append((duplicate, server))

        out_of_window = copy.deepcopy(client)
        out_of_window["rows"][0]["zero_poll_intervals_ns"] = [[99, 110]]
        cases.append((out_of_window, server))

        count_mismatch = copy.deepcopy(client)
        count_mismatch["rows"][0]["zero_timeout_polls"] = 2
        cases.append((count_mismatch, server))

        duration_mismatch = copy.deepcopy(client)
        duration_mismatch["rows"][0]["zero_poll_syscall_ns"] = 99
        cases.append((duration_mismatch, server))

        unordered = copy.deepcopy(client)
        unordered["rows"][0]["zero_poll_intervals_ns"] = [[115, 120], [110, 114]]
        unordered["rows"][0]["zero_timeout_polls"] = 2
        unordered["rows"][0]["zero_poll_syscall_ns"] = 9
        cases.append((unordered, server))

        for bad_client, bad_server in cases:
            self.assertEqual(combine(result, bad_client, bad_server)["status"], "UNKNOWN")

    def test_malformed_public_boundaries_fail_closed(self):
        result, client, server = fixture()
        bad = copy.deepcopy(result)
        bad["public_boundaries"][1]["trial"] = 0
        self.assertEqual(combine(bad, client, server)["status"], "UNKNOWN")
        for key, value in (("transcript_failures", 1), ("samples_us", [2, 1, 1])):
            bad = copy.deepcopy(result)
            bad[key] = value
            self.assertEqual(combine(bad, client, server)["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
