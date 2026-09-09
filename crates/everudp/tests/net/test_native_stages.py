import copy
import unittest

from analyze_native_stages import STAGES, analyze

IDENTITY = {"boot_id": "a379fc1e-ec8d-4f5c-afaa-4bbe88d1fced", "time_namespace_dev": 5, "time_namespace_ino": 4026531834}


def fixture(trials=1):
    events = []
    for sequence in range(trials + 1):
        for offset, stage in enumerate(STAGES):
            events.append({"time_ns": sequence * 1000 + offset * 10, "cpu_time_ns": sequence * 100 + offset, "stage": stage, "sequence": sequence})
    return {
        "schema_version": 1, "cpu_clock_calibration_ns": [1] * 16,
        "diagnostic_only": True, "wall_clock": "CLOCK_MONOTONIC", "cpu_clock": "CLOCK_THREAD_CPUTIME_ID",
        "sample_order": "wall_then_cpu_not_simultaneous", "valid": True, "run_succeeded": True,
        "capacity": len(events) + 1, "overflow": False,
        "identity": {"pid": 12, "tid": 12, **IDENTITY}, "events": events,
    }


def result(trials=1, start=900, end=1100):
    return {"schema_version": 1, "trials": trials, "transcript_failures": 0,
            "samples_us": [1] * trials, "public_clock": "CLOCK_MONOTONIC; local host and time namespace only", "clock_identity": IDENTITY,
            "public_boundaries": [{"trial": i, "send_ns": start + i * 1000, "accepted_ns": end + i * 1000} for i in range(trials)]}


class NativeStageTests(unittest.TestCase):
    def test_valid_trace_and_separate_aggregates(self):
        report = analyze(result(), fixture())
        self.assertEqual(report["status"], "DIAGNOSTIC")
        self.assertEqual(report["included_trials"], 1)
        self.assertIn("wall", report["aggregate_medians_ns"])
        self.assertIn("thread_cpu", report["aggregate_medians_ns"])

    def test_rejects_invalid_header_identity_and_overflow(self):
        for key, value in (("diagnostic_only", False), ("valid", False), ("overflow", True)):
            trace = fixture(); trace[key] = value
            with self.subTest(key=key): self.assertEqual(analyze(result(), trace)["status"], "UNKNOWN")
        trace = fixture(); trace["identity"]["boot_id"] = "other"
        self.assertEqual(analyze(result(), trace)["status"], "UNKNOWN")

    def test_duplicate_stage_retry_selects_first_complete_attempt(self):
        trace = fixture(); events = trace["events"]
        # An incomplete first offer attempt is followed by a complete retry.
        read_end = next(i for i, event in enumerate(events) if event["stage"] == "offer_start" and event["sequence"] == 1)
        events.insert(read_end + 1, {**events[read_end], "stage": "offer_start", "time_ns": events[read_end]["time_ns"] + 1})
        report = analyze(result(), trace)
        self.assertEqual(report["status"], "UNKNOWN")

    def test_window_and_sink_boundaries_are_explicit(self):
        trace = fixture()
        trace["events"][-1]["time_ns"] = 1200
        report = analyze(result(), trace)
        self.assertEqual(report["rows"][0]["exclusion"], "sink_outside_public_window")

    def test_missing_post_offer_is_invalid(self):
        trace = fixture(); trace["events"] = [e for e in trace["events"] if e["stage"] != "post_offer_reactor_end"]
        report = analyze(result(), trace)
        self.assertEqual(report["status"], "UNKNOWN")

    def test_capacity_calibration_and_duplicate_anchor_are_invalid(self):
        for mutate in (lambda t: t.update(capacity=1), lambda t: t.update(schema_version=True),
                       lambda t: t.update(cpu_clock_calibration_ns=[]),
                       lambda t: t["events"].append(dict(t["events"][-1]))):
            trace = fixture()
            mutate(trace)
            self.assertEqual(analyze(result(), trace)["status"], "UNKNOWN")

    def test_complete_retry_preserves_first_attempt(self):
        trace = fixture()
        trace["events"][-1]["time_ns"] = 1090
        trace["events"][-1]["cpu_time_ns"] = 190
        trace["events"][-1:-1] = [
            {"time_ns": 1071 + i, "cpu_time_ns": 171 + i, "stage": stage, "sequence": 1}
            for i, stage in enumerate(STAGES[2:8])]
        trace["capacity"] = len(trace["events"])
        report = analyze(result(), trace)
        self.assertEqual(report["included_trials"], 1, report)
        self.assertEqual(report["aggregate_medians_ns"]["wall"]["post_offer_reactor"], 10)

    def test_blocked_first_offer_is_explicitly_excluded(self):
        trace = fixture()
        events = trace["events"]
        start = next(i for i, e in enumerate(events) if e["sequence"] == 1 and e["stage"] == "pre_offer_reactor_start")
        events[start:start] = [
            {"time_ns": 1011 + i, "cpu_time_ns": 101 + i, "stage": stage, "sequence": 1}
            for i, stage in enumerate(STAGES[2:6])]
        # Keep sequential CPU samples monotonic across both attempts.
        for i, event in enumerate(events):
            event["cpu_time_ns"] = i
        trace["capacity"] = len(events)
        report = analyze(result(), trace)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual(report["rows"][0]["exclusion"], "first_offer_blocked")

    def test_trailing_pre_drive_can_receive_echo_before_retry(self):
        trace = fixture()
        trace["events"][-1:-1] = [
            {"time_ns": 1071 + i, "cpu_time_ns": 107, "stage": stage, "sequence": 1}
            for i, stage in enumerate(STAGES[2:4])]
        trace["capacity"] = len(trace["events"])
        self.assertEqual(analyze(result(), trace)["included_trials"], 1)


if __name__ == "__main__":
    unittest.main()
