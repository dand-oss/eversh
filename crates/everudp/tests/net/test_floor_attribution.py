#!/usr/bin/env python3
"""Unit tests for analyze_floor_attribution.py.

Fixtures intentionally model the public trace schema rather than importing
the benchmark runner.  A real completed trace is exercised when the frozen
measurement directory is available.
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import analyze_floor_attribution as analyzer  # noqa: E402


def _event(elapsed: int, stage: str, sequence: int | None, thread: str = "ThreadId(1)") -> dict:
    return {
        "elapsed_ns": elapsed,
        "stage": stage,
        "sequence": sequence,
        "thread": thread,
        "rust_allocation_requests": None,
    }


def fixture(trials: int = 2) -> tuple[dict, dict, dict]:
    client_events = [_event(1, "bootstrap_start", None), _event(2, "bootstrap_complete", None)]
    server_events = [_event(1, "bootstrap_complete", None)]
    clock = 10
    for seq in range(trials + 1):
        # Sequence zero is the warmup and has no public result boundary.
        client_events.extend(
            [
                _event(clock, "terminal_read", seq),
                _event(clock + 1, "wire_encoded", seq),
                _event(clock + 2, "protocol_offer", seq),
                _event(clock + 3, "callback_enter", None),
                _event(clock + 4, "wire_decoded", seq),
                _event(clock + 6, "sink_accepted", seq),
                _event(clock + 7, "callback_exit", None),
            ]
        )
        server_events.extend(
            [
                _event(clock, "callback_enter", None),
                _event(clock + 1, "wire_decoded", seq),
                _event(clock + 3, "wire_encoded", seq),
                _event(clock + 4, "callback_exit", seq),
            ]
        )
        clock += 10
    result = {
        "schema_version": 1,
        "trials": trials,
        "gap_ms": 100,
        "transcript_failures": 0,
        "samples_us": [1] * trials,
        "public_clock": "CLOCK_MONOTONIC; local host and time namespace only",
        "benchmark_pid": 1234,
        "public_boundaries": [
            {"trial": trial, "send_ns": trial * 1000, "accepted_ns": trial * 1000 + 1}
            for trial in range(trials)
        ],
    }
    def wrap(events: list[dict]) -> dict:
        return {
            "schema_version": 1,
            "clock_domain": "process-relative-monotonic",
            "pid": 10,
            "overflow": False,
            "valid": True,
            "capacity": max(64, len(events)),
            "events": events,
        }
    return result, {"diagnostic_only": True, "run_succeeded": True, "trace": wrap(client_events)}, wrap(server_events)


class AttributionTests(unittest.TestCase):
    def test_legacy_trace_has_no_aligned_handoff_measurements(self) -> None:
        report = analyzer.analyze(*fixture())
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual(report["local_handoffs"]["status"], "UNAVAILABLE")
        self.assertEqual(report["local_handoffs"]["rows"], [])

    def test_invalid_alignment_cannot_produce_attribution(self) -> None:
        result, client, server = fixture()
        result["clock_identity"] = {"boot_id": "00000000-0000-0000-0000-000000000000",
                                    "time_namespace_dev": 4, "time_namespace_ino": 5}
        client["trace"]["clock_alignment"] = {"valid": False}
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "UNKNOWN", report)
        self.assertEqual(report["rows"], [])

    def test_clock_read_reference_is_preserved_without_subtraction(self) -> None:
        result, client, server = fixture()
        reference = {"clock": "CLOCK_THREAD_CPUTIME_ID",
                     "method": "back-to-back-thread-clock-read-deltas",
                     "thread": "ThreadId(1)", "samples_ns": [123] * 64}
        client["trace"]["cpu_clock_calibration"] = reference
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual(report["cpu_clock_calibration"]["client"], reference)
        self.assertIsNone(report["cpu_clock_calibration"]["server"])

    def test_malformed_clock_reference_fails_closed(self) -> None:
        for field, value in (("clock", "CLOCK_MONOTONIC"), ("method", "unknown"),
                             ("thread", ""), ("samples_ns", [1] * 63),
                             ("samples_ns", [True] * 64), ("samples_ns", [-1] * 64),
                             ("samples_ns", [2**64] * 64)):
            result, client, server = fixture()
            reference = {"clock": "CLOCK_THREAD_CPUTIME_ID",
                         "method": "back-to-back-thread-clock-read-deltas",
                         "thread": "ThreadId(1)", "samples_ns": [123] * 64}
            reference[field] = value
            client["trace"]["cpu_clock_calibration"] = reference
            self.assertEqual(analyzer.analyze(result, client, server)["status"], "UNKNOWN")

    def test_sender_thread_cpu_is_separate_from_wall_time(self) -> None:
        result, client, server = fixture()
        client["trace"]["events"].extend([
            dict(_event(50, "udp_send_poll", None), thread_cpu_ns=100),
            dict(_event(60, "udp_send_poll_accepted", None), thread_cpu_ns=106),
        ])
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        row = report["sender_poll_intervals"]["client"]["intervals"][0]
        self.assertEqual(row["duration_ns"], 10)
        self.assertEqual(row["thread_cpu_duration_ns"], 6)

    def test_protocol_calls_require_context_and_cpu_pairs(self) -> None:
        for invalid in (None, "connection", "cpu", "regression", "outcome"):
            with self.subTest(invalid=invalid):
                result, client, server = fixture()
                begin = dict(_event(50, "protocol_transmit_start", None), connection=2, thread_cpu_ns=100)
                end = dict(_event(60, "protocol_transmit_ready", None), connection=2, thread_cpu_ns=106)
                if invalid == "connection":
                    end["connection"] = 3
                elif invalid == "cpu":
                    end["thread_cpu_ns"] = None
                elif invalid == "regression":
                    end["thread_cpu_ns"] = 99
                elif invalid == "outcome":
                    end["stage"] = "protocol_transmit_start"
                client["trace"]["events"].extend([begin, end])
                report = analyzer.analyze(result, client, server)
                self.assertEqual(report["status"], "UNKNOWN" if invalid else "DIAGNOSTIC", report)
                if not invalid:
                    row = report["protocol_poll_intervals"]["client"]["intervals"][0]
                    self.assertEqual((row["connection"], row["thread_cpu_duration_ns"]), (2, 6))

    def test_bad_sender_cpu_is_not_silently_ignored(self) -> None:
        for value in (None, -1, True, 99):
            result, client, server = fixture()
            client["trace"]["events"].extend([
                dict(_event(50, "udp_send_poll", None), thread_cpu_ns=100),
                dict(_event(60, "udp_send_poll_accepted", None), thread_cpu_ns=value),
            ])
            self.assertEqual(analyzer.analyze(result, client, server)["status"], "UNKNOWN")

    def test_sender_poll_intervals_are_process_activity_not_trials(self) -> None:
        result, client, server = fixture()
        events = client["trace"]["events"]
        for time, outcome in ((50, "accepted"), (60, "blocked"), (70, "error")):
            events.extend([_event(time, "udp_send_poll", None),
                           _event(time + 2, "udp_send_poll_" + outcome, None)])
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        polls = report["sender_poll_intervals"]["client"]
        self.assertEqual(polls["outcomes"], {"accepted": 1, "blocked": 1, "error": 1})
        self.assertEqual([row["duration_ns"] for row in polls["intervals"]], [2, 2, 2])
        self.assertTrue(all("sequence" not in row for row in polls["intervals"]))
        self.assertFalse(report["sender_poll_intervals"]["server"]["available"])
        self.assertFalse(report["integration_authorized"])

    def test_sender_poll_interleaved_threads_remain_separate(self) -> None:
        result, client, server = fixture()
        client["trace"]["events"].extend([
            _event(50, "udp_send_poll", None, "a"),
            _event(51, "udp_send_poll", None, "b"),
            _event(53, "udp_send_poll_accepted", None, "b"),
            _event(57, "udp_send_poll_blocked", None, "a"),
        ])
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        intervals = report["sender_poll_intervals"]["client"]["intervals"]
        self.assertEqual([(row["thread"], row["duration_ns"]) for row in intervals],
                         [("b", 2), ("a", 7)])

    def test_malformed_sender_pairs_fail_closed(self) -> None:
        cases = [
            [_event(50, "udp_send_poll", None)],
            [_event(50, "udp_send_poll_accepted", None)],
            [_event(50, "udp_send_poll", None), _event(51, "udp_send_poll", None)],
            [_event(50, "udp_send_poll", None), _event(51, "connection_driver_poll", None),
             _event(52, "udp_send_poll_accepted", None)],
            [_event(50, "udp_send_poll", None, "a"),
             _event(51, "udp_send_poll_accepted", None, "b")],
            [_event(50, "udp_send_poll", 1), _event(51, "udp_send_poll_accepted", None)],
        ]
        for suffix in cases:
            with self.subTest(suffix=suffix):
                result, client, server = fixture()
                client["trace"]["events"].extend(suffix)
                report = analyzer.analyze(result, client, server)
                self.assertEqual(report["status"], "UNKNOWN", report)
                self.assertEqual(report["rows"], [])

    def test_connection_scoped_queue_to_driver_service(self) -> None:
        result, client, server = fixture()
        original = server["events"]
        events = original[:1]
        for offset in range(1, len(original), 4):
            callback = original[offset:offset + 4]
            start = callback[0]["elapsed_ns"]
            def marker(time, stage):
                return dict(_event(time, stage, None), connection=2)
            events.extend([marker(start - 1, "inline_callback_enter"), *callback,
                           marker(start + 4, "inline_callback_exit"),
                           marker(start + 5, "inline_response_queued"),
                           marker(start + 6, "inline_driver_wake_requested"),
                           marker(start + 8, "connection_driver_service")])
        server["events"] = events
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual(report["server_scheduling"]["eligible_trials"], 2)
        self.assertEqual(report["rows"][0]["server_queue_to_driver_service_ns"], 3)
        self.assertEqual(report["rows"][0]["server_wake_request_to_driver_service_ns"], 2)
        queued = [e for e in events if e["stage"] == "inline_response_queued"]
        queued[1]["stage"] = "inline_response_blocked"
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["server_scheduling"]["eligible_trials"], 1)
        self.assertIsNone(report["rows"][0]["server_queue_to_driver_service_ns"])
        exit_event = next(e for e in events if e["stage"] == "inline_callback_exit")
        exit_event["connection"] = 3
        self.assertEqual(analyzer.analyze(result, client, server)["status"], "UNKNOWN")

    def test_resource_window_requires_declared_post_warmup_bounds(self) -> None:
        result, client, server = fixture()
        window = {"valid": True, "scope": "RUSAGE_SELF", "window": "after-warmup-to-export",
                  "started_elapsed_ns": 17, "finished_elapsed_ns": 40,
                  "user_cpu_ns": 1, "system_cpu_ns": 2, "voluntary_context_switches": 3,
                  "involuntary_context_switches": 0, "lifetime_max_rss_kib": 100}
        client["trace"]["resource_window"] = window
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual(report["resource_windows"]["client"], window)
        self.assertIsNone(report["resource_windows"]["server"])
        for key, value in (("valid", False), ("user_cpu_ns", -1), ("scope", "RUSAGE_CHILDREN"),
                           ("started_elapsed_ns", 0), ("started_elapsed_ns", 25), ("finished_elapsed_ns", 35)):
            with self.subTest(key=key):
                client["trace"]["resource_window"] = dict(window, **{key: value})
                self.assertEqual(analyzer.analyze(result, client, server)["status"], "UNKNOWN")

    def test_corrupt_contract_variants_fail_closed(self) -> None:
        for mutation in ("missing_warmup", "null_sequence", "nested_callback", "cross_thread", "overlapping_public", "bool_trial", "unknown_stage"):
            with self.subTest(mutation=mutation):
                result, client, server = fixture()
                events = client["trace"]["events"]
                if mutation == "missing_warmup":
                    client["trace"]["events"] = [e for e in events if e["sequence"] != 0]
                elif mutation == "null_sequence":
                    next(e for e in events if e["stage"] == "retry" or e["stage"] == "terminal_read")["sequence"] = None
                elif mutation == "nested_callback":
                    enters = [i for i, e in enumerate(events) if e["stage"] == "callback_enter"]
                    exits = [i for i, e in enumerate(events) if e["stage"] == "callback_exit"]
                    events[exits[0]]["stage"] = "callback_enter"
                    events[enters[1]]["stage"] = "callback_exit"
                elif mutation == "cross_thread":
                    next(e for e in events if e["stage"] == "callback_exit")["thread"] = "ThreadId(2)"
                elif mutation == "overlapping_public":
                    result["public_boundaries"][1] = dict(result["public_boundaries"][0], trial=1)
                elif mutation == "bool_trial":
                    result["public_boundaries"][0]["trial"] = False
                else:
                    events[0]["stage"] = "invented"
                report = analyzer.analyze(result, client, server)
                self.assertEqual(report["status"], "UNKNOWN", report)
                self.assertEqual(report["rows"], [])

    def test_archived_loss_and_no_loss_blocks(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[4] / "docs/release-evidence/20260907-everudp-attribution-e727820/measurements"
        for loss, block, retries, eligible in ((0, 1, 0, 200), (0, 2, 0, 200), (5, 1, 14, 187), (5, 2, 33, 174)):
            with self.subTest(loss=loss, block=block):
                directory = root / f"loss{loss}-block{block}-traced/everudp-floor"
                report = analyzer.analyze_paths(*(directory / name for name in ("result.json", "client-trace.json", "client-trace.json.server.json")))
                self.assertEqual(report["status"], "DIAGNOSTIC", report)
                self.assertEqual(len(report["rows"]), 200)
                self.assertEqual(sum(row["retry_count"] for row in report["rows"]), retries)
                self.assertEqual(sum(row["residual_eligible"] for row in report["rows"]), eligible)
                self.assertFalse(report["attribution_complete"])

    def test_valid_fixture_is_diagnostic_only_and_maps_warmup(self) -> None:
        result, client, server = fixture()
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "DIAGNOSTIC")
        self.assertEqual(report["qualification"], "NOT_APPLICABLE")
        self.assertFalse(report["integration_authorized"])
        self.assertEqual([row["sequence"] for row in report["rows"]], [1, 2])
        self.assertEqual(report["rows"][0]["residual_transport_driver_client_ns"], 2)

    def test_missing_stage_fails_closed(self) -> None:
        result, client, server = fixture()
        client["trace"]["events"] = [event for event in client["trace"]["events"] if not (event["stage"] == "wire_encoded" and event["sequence"] == 1)]
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertEqual(report["rows"], [])

    def test_overflow_fails_closed(self) -> None:
        result, client, server = fixture()
        client["trace"]["overflow"] = True
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "UNKNOWN")

    def test_allocator_regression_fails_closed(self) -> None:
        result, client, server = fixture()
        events = client["trace"]["events"]
        for event in events:
            event["rust_allocation_requests"] = {"calls": event["elapsed_ns"], "requested_bytes": event["elapsed_ns"]}
        events[-1]["rust_allocation_requests"]["calls"] = 0
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "UNKNOWN")

    def test_malformed_public_boundary_fails_closed(self) -> None:
        result, client, server = fixture()
        result["public_boundaries"][0]["accepted_ns"] += 1000
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "UNKNOWN")

    def test_sequence_offset_fails_closed(self) -> None:
        result, client, server = fixture()
        for event in client["trace"]["events"]:
            if event["stage"] == "terminal_read" and event["sequence"] == 1:
                event["sequence"] = 2
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "UNKNOWN")

    def test_retry_excludes_residual_but_keeps_offer_to_sink(self) -> None:
        result, client, server = fixture()
        events = client["trace"]["events"]
        index = next(i for i, event in enumerate(events) if event["stage"] == "protocol_offer" and event["sequence"] == 1)
        retry = copy.deepcopy(events[index])
        retry["stage"] = "retry"
        retry["elapsed_ns"] += 1
        events.insert(index + 1, retry)
        # Keep timestamps monotonic after the inserted retry.
        for left, right in zip(events, events[1:]):
            if right["elapsed_ns"] < left["elapsed_ns"]:
                right["elapsed_ns"] = left["elapsed_ns"]
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "DIAGNOSTIC")
        row = report["rows"][0]
        self.assertEqual(row["retry_count"], 1)
        self.assertIsNone(row["residual_transport_driver_client_ns"])
        self.assertIsNotNone(row["protocol_offer_to_sink_accepted_ns"])

    def test_duplicate_sink_is_rejected(self) -> None:
        result, client, server = fixture()
        events = client["trace"]["events"]
        index = next(i for i, event in enumerate(events) if event["stage"] == "sink_accepted" and event["sequence"] == 1)
        duplicate = copy.deepcopy(events[index])
        duplicate["elapsed_ns"] += 1
        events.insert(index + 1, duplicate)
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "UNKNOWN")

    def test_duplicate_decode_after_sink_is_counted_not_packet_attributed(self) -> None:
        result, client, server = fixture()
        events = client["trace"]["events"]
        index = next(i for i, event in enumerate(events) if event["stage"] == "sink_accepted" and event["sequence"] == 1)
        duplicate = copy.deepcopy(next(event for event in events if event["stage"] == "wire_decoded" and event["sequence"] == 1))
        duplicate["elapsed_ns"] = events[index]["elapsed_ns"] + 1
        events[index + 2:index + 2] = [
            _event(duplicate["elapsed_ns"], "callback_enter", None),
            duplicate,
            _event(duplicate["elapsed_ns"], "callback_exit", None),
        ]
        report = analyzer.analyze(result, client, server)
        self.assertEqual(report["status"], "DIAGNOSTIC", report)
        self.assertEqual(report["rows"][0]["duplicate_decode_count"], 1)
        self.assertIsNone(report["rows"][0]["residual_transport_driver_client_ns"])

    def test_real_completed_trace_schema_when_available(self) -> None:
        configured = os.environ.get("EVERUDP_ATTRIBUTION_FIXTURE")
        if not configured:
            self.skipTest("set EVERUDP_ATTRIBUTION_FIXTURE to run a completed-trace integration fixture")
        root = pathlib.Path(configured)
        paths = [root / name for name in ("result.json", "client-trace.json", "client-trace.json.server.json")]
        if not all(path.is_file() for path in paths):
            self.skipTest("completed attribution fixture is not available")
        values = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
        report = analyzer.analyze(*values)
        self.assertEqual(report["status"], "DIAGNOSTIC")
        self.assertEqual(len(report["rows"]), values[0]["trials"])


if __name__ == "__main__":
    unittest.main()
