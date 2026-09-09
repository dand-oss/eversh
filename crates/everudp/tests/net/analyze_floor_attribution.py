#!/usr/bin/env python3
"""Fail-closed attribution of the opt-in everudp floor timing traces.

This is a diagnostic report, not a qualification analyzer.  Trace clocks are
process-relative monotonic clocks, so timestamps from the client and server
are never subtracted.  Server and client *durations* may be compared for a
unique request, as a conservative same-host attribution aid.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter, defaultdict
from typing import Any, Iterable

from clock_alignment import analyze_handoffs


CLOCK_DOMAIN = "process-relative-monotonic"
SCHEMA_VERSION = 1
PROTOCOL_STAGES = frozenset({"protocol_transmit_start", "protocol_transmit_ready", "protocol_transmit_idle"})
CPU_STAGES = PROTOCOL_STAGES | frozenset({"udp_send_poll", "udp_send_poll_accepted", "udp_send_poll_blocked", "udp_send_poll_error"})
CONTEXT_STAGES = frozenset({"connection_driver_service", "inline_callback_enter", "inline_callback_exit",
                            "inline_response_queued", "inline_response_blocked", "inline_driver_wake_requested"})
STAGES = frozenset(
    {
        "bootstrap_start",
        "bootstrap_complete",
        "terminal_read",
        "protocol_offer",
        "wire_encoded",
        "callback_enter",
        "callback_exit",
        "wire_decoded",
        "sink_accepted",
        "retry",
        "buffer_blocked",
        "udp_receive_poll_ready",
        "udp_receive_copy_complete",
        "connection_driver_poll",
        "udp_send_poll",
        "udp_send_poll_accepted",
        "udp_send_poll_blocked",
        "udp_send_poll_error",
    })
SEQUENCED_CLIENT = ("terminal_read", "wire_encoded", "protocol_offer", "wire_decoded", "sink_accepted")
SEQUENCED_SERVER = ("wire_decoded", "wire_encoded")
NOQ_CORE_STAGES = frozenset(
    {
        "connection_driver_poll",
        "udp_receive_poll_ready",
        "udp_receive_copy_complete",
        "udp_send_poll",
        "udp_send_poll_accepted",
    }
)


class TraceInvalid(ValueError):
    """A malformed or incomplete trace that must not produce attribution."""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _read_json(path: str | pathlib.Path) -> Any:
    try:
        with pathlib.Path(path).open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TraceInvalid(f"cannot read JSON {path}: {exc}") from exc


def _trace_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TraceInvalid(f"{label}: trace must be an object")
    if "trace" in value:
        # Client files have a wrapper; a server export is the bare object.
        if set(value) - {"diagnostic_only", "run_succeeded", "trace"}:
            raise TraceInvalid(f"{label}: unknown wrapper fields")
        if value.get("diagnostic_only") is not True or value.get("run_succeeded") is not True:
            raise TraceInvalid(f"{label}: diagnostic run did not succeed")
        value = value["trace"]
    if not isinstance(value, dict):
        raise TraceInvalid(f"{label}: nested trace must be an object")
    return value


def validate_trace(value: Any, label: str) -> dict[str, Any]:
    """Validate schema, event order/types and allocator snapshots.

    The returned object is the normalized trace.  No best-effort repair is
    performed: unknown stages, malformed events, clock regressions, capacity
    overflow, and allocator regressions all invalidate evidence.
    """
    trace = _trace_object(value, label)
    required = {"schema_version", "clock_domain", "pid", "overflow", "valid", "capacity", "events"}
    missing = required - set(trace)
    if missing:
        raise TraceInvalid(f"{label}: missing fields {sorted(missing)}")
    if trace["schema_version"] != SCHEMA_VERSION:
        raise TraceInvalid(f"{label}: unsupported schema_version")
    if trace["clock_domain"] != CLOCK_DOMAIN:
        raise TraceInvalid(f"{label}: timestamps are not process-relative monotonic")
    if not _is_int(trace["pid"]) or trace["pid"] <= 0:
        raise TraceInvalid(f"{label}: invalid pid")
    if not isinstance(trace["overflow"], bool) or not isinstance(trace["valid"], bool):
        raise TraceInvalid(f"{label}: valid/overflow must be booleans")
    if trace["overflow"] or not trace["valid"]:
        raise TraceInvalid(f"{label}: recorder marked capture invalid")
    if not _is_int(trace["capacity"]) or trace["capacity"] <= 0:
        raise TraceInvalid(f"{label}: invalid capacity")
    events = trace["events"]
    if not isinstance(events, list) or len(events) > trace["capacity"]:
        raise TraceInvalid(f"{label}: event count exceeds capacity or is not a list")
    previous_time = -1
    allocation_mode: bool | None = None
    previous_alloc: tuple[int, int] | None = None
    previous_cpu: dict[str, int] = {}
    normalized: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise TraceInvalid(f"{label}: event {index} is not an object")
        if set(event) - {"connection", "thread_cpu_ns"} != {"elapsed_ns", "stage", "sequence", "thread", "rust_allocation_requests"}:
            raise TraceInvalid(f"{label}: event {index} has malformed fields")
        elapsed = event["elapsed_ns"]
        if not _is_int(elapsed) or elapsed < 0 or elapsed < previous_time:
            raise TraceInvalid(f"{label}: event {index} timestamp is invalid or regressed")
        previous_time = elapsed
        stage = event["stage"]
        if not isinstance(stage, str) or stage not in STAGES | CONTEXT_STAGES | PROTOCOL_STAGES:
            raise TraceInvalid(f"{label}: event {index} has unknown stage")
        connection = event.get("connection")
        if stage in CONTEXT_STAGES | PROTOCOL_STAGES:
            if not _is_int(connection) or connection < 0:
                raise TraceInvalid(f"{label}: contextual event lacks connection identity")
        elif connection is not None:
            raise TraceInvalid(f"{label}: unexpected connection identity")
        sequence = event["sequence"]
        if sequence is not None and (not _is_int(sequence) or sequence < 0):
            raise TraceInvalid(f"{label}: event {index} has invalid sequence")
        thread = event["thread"]
        if not isinstance(thread, str) or not thread:
            raise TraceInvalid(f"{label}: event {index} has invalid thread")
        cpu = event.get("thread_cpu_ns")
        if cpu is not None:
            if stage not in CPU_STAGES or not _is_int(cpu) or cpu < previous_cpu.get(thread, 0):
                raise TraceInvalid(f"{label}: invalid or regressing thread CPU timestamp")
            previous_cpu[thread] = cpu
        alloc = event["rust_allocation_requests"]
        present = alloc is not None
        if allocation_mode is None:
            allocation_mode = present
        elif allocation_mode != present:
            raise TraceInvalid(f"{label}: allocator snapshot presence changes")
        if present:
            if not isinstance(alloc, dict) or set(alloc) != {"calls", "requested_bytes"}:
                raise TraceInvalid(f"{label}: event {index} has malformed allocator counters")
            calls, requested = alloc["calls"], alloc["requested_bytes"]
            if not _is_int(calls) or calls < 0 or not _is_int(requested) or requested < 0:
                raise TraceInvalid(f"{label}: event {index} has invalid allocator counters")
            current = (calls, requested)
            if previous_alloc is not None and current[0] < previous_alloc[0]:
                raise TraceInvalid(f"{label}: allocator call counter regressed")
            if previous_alloc is not None and current[1] < previous_alloc[1]:
                raise TraceInvalid(f"{label}: allocator byte counter regressed")
            previous_alloc = current
        normalized.append({"elapsed_ns": elapsed, "stage": stage, "sequence": sequence, "thread": thread, "alloc": alloc, "connection": connection, "thread_cpu_ns": cpu})
    return {**trace, "events": normalized, "allocator_present": bool(allocation_mode)}


def _by_stage_seq(events: Iterable[dict[str, Any]], stage: str) -> dict[int, list[dict[str, Any]]]:
    result: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["stage"] == stage and event["sequence"] is not None:
            result[event["sequence"]].append(event)
    return result


def _interval(start: dict[str, Any], end: dict[str, Any]) -> int | None:
    if start["thread"] != end["thread"] or end["elapsed_ns"] < start["elapsed_ns"]:
        return None
    return end["elapsed_ns"] - start["elapsed_ns"]


def _require_sequences(trace: dict[str, Any], stages: Iterable[str], trial_count: int, label: str) -> None:
    expected = set(range(0, trial_count + 1))
    for stage in stages:
        actual = set(_by_stage_seq(trace["events"], stage))
        missing = expected - actual
        unexpected = actual - expected - {0}
        if missing or unexpected:
            raise TraceInvalid(f"{label}: {stage} sequence range mismatch (missing={sorted(missing)[:5]}, unexpected={sorted(unexpected)[:5]})")


def _require_one_per_public_sequence(trace: dict[str, Any], stages: Iterable[str], trial_count: int, label: str) -> None:
    expected = set(range(0, trial_count + 1))
    for stage in stages:
        grouped = _by_stage_seq(trace["events"], stage)
        for sequence in expected:
            if len(grouped.get(sequence, [])) != 1:
                raise TraceInvalid(f"{label}: {stage} must occur exactly once for sequence {sequence}")


def _validate_client_order(trace: dict[str, Any], trial_count: int) -> None:
    grouped = {stage: _by_stage_seq(trace["events"], stage) for stage in SEQUENCED_CLIENT}
    for sequence in range(0, trial_count + 1):
        ordered = [grouped[stage][sequence][0] for stage in ("terminal_read", "wire_encoded", "protocol_offer")]
        decoded = grouped["wire_decoded"][sequence]
        sink = grouped["sink_accepted"][sequence][0]
        if any(_interval(left, right) is None for left, right in zip(ordered, ordered[1:])):
            raise TraceInvalid(f"client: application stage order invalid for sequence {sequence}")
        if not decoded or _interval(ordered[-1], decoded[0]) is None or _interval(decoded[0], sink) is None:
            raise TraceInvalid(f"client: decode/sink order invalid for sequence {sequence}")


def _validate_callback_contract(trace: dict[str, Any], role: str, trial_count: int) -> None:
    """Check callback enter/exit pairing without assigning noQ markers.

    The application callback has one invocation for warmup sequence zero and
    each public sequence.  On the client both callback markers deliberately
    carry no sequence (they are process-local boundaries); on the server the
    exit marker carries the decoded sequence while enter remains unsequenced.
    Ordering is checked by event position, not by cross-process time.
    """
    events = trace["events"]
    enters = [i for i, event in enumerate(events) if event["stage"] == "callback_enter"]
    exits = [i for i, event in enumerate(events) if event["stage"] == "callback_exit"]
    expected = trial_count + 1
    # Retransmission/retry paths can invoke the callback more than once for a
    # sequence.  We require at least warmup + public coverage, then let the
    # per-trial report mark duplicate occurrences ineligible for subtraction.
    if len(enters) != len(exits) or len(enters) < expected:
        raise TraceInvalid(f"{role}: callback enter/exit count mismatch")
    for index, (enter, exit_) in enumerate(zip(enters, exits)):
        if enter >= exit_ or (index and enter <= exits[index - 1]):
            raise TraceInvalid(f"{role}: nested or inverted callbacks")
        if len({event["thread"] for event in events[enter:exit_ + 1]}) != 1:
            raise TraceInvalid(f"{role}: callback spans multiple threads")
    if role == "client":
        if any(events[i]["sequence"] is not None for i in enters + exits):
            raise TraceInvalid("client: callback markers must be unsequenced")
        # The callback reads a response and writes the local sink before exit.
        for enter, exit_ in zip(enters, exits):
            if enter >= exit_:
                raise TraceInvalid("client: callback exit precedes enter")
            between = events[enter + 1 : exit_]
            decoded = [event for event in between if event["stage"] == "wire_decoded"]
            sinks = [event for event in between if event["stage"] == "sink_accepted"]
            if len(decoded) != 1 or len(sinks) > 1:
                raise TraceInvalid("client: callback must decode one response and accept at most once")
            if sinks and (sinks[0]["sequence"] != decoded[0]["sequence"] or _interval(decoded[0], sinks[0]) is None):
                raise TraceInvalid("client: callback decoded/sink mismatch")
            if not sinks and not any(event["stage"] == "sink_accepted" and event["sequence"] == decoded[0]["sequence"] for event in events[:enter]):
                raise TraceInvalid("client: unaccepted response is not a duplicate")
            # A duplicate decode after the sink is a valid callback that does
            # not accept the payload again; exactly one sink per sequence is
            # enforced separately by _require_one_per_public_sequence.
    elif role == "server":
        if any(events[i]["sequence"] is not None for i in enters):
            raise TraceInvalid("server: callback enter markers must be unsequenced")
        exit_sequences = [events[i]["sequence"] for i in exits]
        if any(sequence is None for sequence in exit_sequences):
            raise TraceInvalid("server: callback exits must carry a sequence")
        expected_sequences = set(range(expected))
        if not expected_sequences.issubset(exit_sequences):
            raise TraceInvalid("server: callback exits omit a warmup/public sequence")
        for enter, exit_ in zip(enters, exits):
            if enter >= exit_:
                raise TraceInvalid("server: callback exit precedes enter")
            sequence = events[exit_]["sequence"]
            between = events[enter + 1 : exit_]
            decoded = [event for event in between if event["stage"] == "wire_decoded" and event["sequence"] == sequence]
            encoded = [event for event in between if event["stage"] == "wire_encoded" and event["sequence"] == sequence]
            if len(decoded) != 1 or len(encoded) != 1:
                raise TraceInvalid("server: callback does not contain one decoded/encoded pair")
            if _interval(decoded[0], encoded[0]) is None:
                raise TraceInvalid("server: callback encode precedes decode")
    else:
        raise TraceInvalid(f"unknown callback role {role}")


def _allocation_window(trace: dict[str, Any]) -> dict[str, int] | None:
    values = [e["alloc"] for e in trace["events"] if e["alloc"] is not None]
    if not values:
        return None
    first, last = values[0], values[-1]
    return {
        "calls": last["calls"] - first["calls"],
        "requested_bytes": last["requested_bytes"] - first["requested_bytes"],
    }


def _trial_summary(client: dict[str, Any], server: dict[str, Any], trial_count: int) -> list[dict[str, Any]]:
    ce = client["events"]
    se = server["events"]
    cstage = {stage: _by_stage_seq(ce, stage) for stage in SEQUENCED_CLIENT}
    sstage = {stage: _by_stage_seq(se, stage) for stage in SEQUENCED_SERVER}
    rows: list[dict[str, Any]] = []
    for trial in range(trial_count):
        seq = trial + 1  # sequence zero is the pty-bench warmup
        read = cstage["terminal_read"][seq][0]
        encoded = cstage["wire_encoded"][seq][0]
        offers = cstage["protocol_offer"][seq]
        decodes = cstage["wire_decoded"][seq]
        sinks = cstage["sink_accepted"][seq]
        terminal_to_wire = _interval(read, encoded)
        # The first accepted sink is authoritative; later decodes are allowed,
        # but a second sink means the local sink accepted duplicate output.
        sink = sinks[0]
        prior_offers = [event for event in offers if event["elapsed_ns"] <= sink["elapsed_ns"]]
        prior_decodes = [event for event in decodes if event["elapsed_ns"] <= sink["elapsed_ns"]]
        offer = prior_offers[0] if prior_offers else None
        decoded = prior_decodes[0] if prior_decodes else None
        offer_to_sink = _interval(offer, sink) if offer else None
        decoded_to_sink = _interval(decoded, sink) if decoded else None
        server_decodes, server_encodes = sstage["wire_decoded"][seq], sstage["wire_encoded"][seq]
        server_duration = _interval(server_decodes[0], server_encodes[0]) if len(server_decodes) == len(server_encodes) == 1 else None
        retry_count = sum(1 for event in ce if event["stage"] == "retry" and event["sequence"] == seq)
        duplicate_decodes = max(0, len(decodes) - 1)
        duplicate_sinks = max(0, len(sinks) - 1)
        residual = None
        residual_eligible = False
        if retry_count == 0 and duplicate_decodes == 0 and duplicate_sinks == 0 and server_duration is not None and offer_to_sink is not None:
            if server_duration <= offer_to_sink:
                residual = offer_to_sink - server_duration
                residual_eligible = True
        rows.append(
            {
                "trial": trial,
                "sequence": seq,
                "terminal_read_to_wire_encoded_ns": terminal_to_wire,
                "protocol_offer_to_sink_accepted_ns": offer_to_sink,
                "wire_decoded_to_sink_accepted_ns": decoded_to_sink,
                "server_wire_decoded_to_wire_encoded_ns": server_duration,
                "residual_transport_driver_client_ns": residual,
                "residual_eligible": residual_eligible,
                "retry_count": retry_count,
                "duplicate_decode_count": duplicate_decodes,
                "duplicate_sink_count": duplicate_sinks,
                "same_thread_intervals": all(value is not None for value in (terminal_to_wire, offer_to_sink, decoded_to_sink)),
            }
        )
    return rows


def _server_scheduling(trace: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Measure uniquely bracketed response queue/wake-to-driver service.

    Connection handles are process-local. This is readiness-to-service, NOT
    packet transmission or a claim that a wake request caused an OS wakeup.
    Multiple callbacks/queues before service are deliberately unassigned.
    """
    events = trace["events"]
    if not any(e["stage"] in CONTEXT_STAGES for e in events):
        return {"available": False, "reason": "historical trace lacks connection context"}
    callbacks = []
    opened = None
    for index, event in enumerate(events):
        if event["stage"] == "inline_callback_enter":
            if opened is not None:
                raise TraceInvalid("server: nested transport callbacks")
            opened = index
        elif event["stage"] == "inline_callback_exit":
            if opened is None:
                raise TraceInvalid("server: unmatched transport callback exit")
            begin = events[opened]
            if begin["connection"] != event["connection"] or begin["thread"] != event["thread"]:
                raise TraceInvalid("server: transport callback context mismatch")
            inner = events[opened + 1:index]
            decoded = [e for e in inner if e["stage"] == "wire_decoded"]
            encoded = [e for e in inner if e["stage"] == "wire_encoded"]
            if len(decoded) != 1 or len(encoded) != 1 or decoded[0]["sequence"] != encoded[0]["sequence"]:
                raise TraceInvalid("server: transport callback lacks unique application response")
            if any(e["thread"] != begin["thread"] for e in inner):
                raise TraceInvalid("server: interleaved callback threads")
            callbacks.append((decoded[0]["sequence"], index, event["connection"]))
            opened = None
    if opened is not None:
        raise TraceInvalid("server: unclosed transport callback")
    counts = Counter(seq for seq, _, _ in callbacks)
    if set(counts) != set(range(len(rows) + 1)):
        raise TraceInvalid("server: incomplete transport callback coverage")
    eligible = 0
    for row in rows:
        row["server_queue_to_driver_service_ns"] = None
        row["server_wake_request_to_driver_service_ns"] = None
        seq = row["sequence"]
        if counts[seq] != 1 or not row["residual_eligible"]:
            continue
        _, exit_index, connection = next(c for c in callbacks if c[0] == seq)
        following = [e for e in events[exit_index + 1:]
                     if e["connection"] == connection and e["stage"] in CONTEXT_STAGES]
        # Exactly the expected queue -> endpoint wake request -> driver
        # service progression. A pending/repeated/in-driver callback is not
        # assigned by searching past intervening work.
        expected = ["inline_response_queued", "inline_driver_wake_requested", "connection_driver_service"]
        if [e["stage"] for e in following[:3]] != expected:
            continue
        queue, wake, service = following[:3]
        queue_delay = _interval(queue, service)
        wake_delay = _interval(wake, service)
        if queue_delay is None or wake_delay is None:
            continue
        row["server_queue_to_driver_service_ns"] = queue_delay
        row["server_wake_request_to_driver_service_ns"] = wake_delay
        eligible += 1
    return {"available": True, "eligible_trials": eligible,
            "semantics": "same-connection response readiness to first driver service; not specific UDP transmission or actual task-wakeup latency"}


def _poll_intervals(trace: dict[str, Any], role: str, protocol: bool = False) -> dict[str, Any]:
    """Pair synchronous poll boundaries, without inventing packet identity.

    poll_send does not yield between its entry and outcome markers. Other
    threads may interleave, but intervening activity on the same thread means
    the instrumentation contract is not sufficient to attribute that call.
    """
    start_stage = "protocol_transmit_start" if protocol else "udp_send_poll"
    outcomes = ({"protocol_transmit_" + name: name for name in ("ready", "idle")} if protocol
                else {"udp_send_poll_" + name: name for name in ("accepted", "blocked", "error")})
    pending: dict[str, dict[str, Any]] = {}
    intervals = []
    for event in trace["events"]:
        stage, thread = event["stage"], event["thread"]
        if stage == start_stage or stage in outcomes:
            if event["sequence"] is not None:
                raise TraceInvalid(f"{role}: sender marker unexpectedly has sequence identity")
        if stage == start_stage:
            if thread in pending:
                raise TraceInvalid(f"{role}: nested sender poll")
            pending[thread] = event
        elif stage in outcomes:
            begin = pending.pop(thread, None)
            if begin is None:
                raise TraceInvalid(f"{role}: sender outcome without same-thread poll")
            duration = _interval(begin, event)
            if duration is None:
                raise TraceInvalid(f"{role}: invalid sender interval")
            if begin["connection"] != event["connection"]:
                raise TraceInvalid(f"{role}: poll connection identity changed")
            before, after = begin["thread_cpu_ns"], event["thread_cpu_ns"]
            if (before is None) != (after is None) or (protocol and before is None):
                raise TraceInvalid(f"{role}: incomplete poll CPU timestamps")
            cpu_duration = after - before if before is not None else None
            if cpu_duration is not None and cpu_duration < 0:
                raise TraceInvalid(f"{role}: poll CPU timestamp regressed")
            row = {"thread": thread, "started_elapsed_ns": begin["elapsed_ns"],
                   "duration_ns": duration, "thread_cpu_duration_ns": cpu_duration,
                   "outcome": outcomes[stage]}
            if protocol:
                row["connection"] = begin["connection"]
            intervals.append(row)
        elif thread in pending:
            raise TraceInvalid(f"{role}: intervening activity inside sender poll")
    if pending:
        raise TraceInvalid(f"{role}: unfinished sender poll")
    return {
        "available": bool(intervals),
        "scope": "whole-trace-including-warmup-and-control",
        "semantics": "same-thread synchronous protocol poll wall time; not per-trial attribution" if protocol else "same-thread synchronous userspace sender poll wall time, including instrumentation and scheduling; not pure syscall/CPU cost, wire transmission or per-trial attribution",
        "thread_cpu_semantics": "CLOCK_THREAD_CPUTIME_ID delta including recorder/clock overhead; null for historical traces. CPU and wall clocks are sampled separately; do not infer exact descheduling time by subtraction.",
        "outcomes": dict(Counter(row["outcome"] for row in intervals)),
        "intervals": intervals,
    }


def _clock_calibration(trace: dict[str, Any], role: str) -> dict[str, Any] | None:
    reference = trace.get("cpu_clock_calibration")
    if reference is None:
        return None  # Historical traces have no clock-read reference.
    if not isinstance(reference, dict) or set(reference) != {"clock", "method", "thread", "samples_ns"}:
        raise TraceInvalid(f"{role}: malformed clock reference")
    if reference["clock"] != "CLOCK_THREAD_CPUTIME_ID" or reference["method"] != "back-to-back-thread-clock-read-deltas":
        raise TraceInvalid(f"{role}: unsupported clock reference")
    if not isinstance(reference["thread"], str) or not reference["thread"]:
        raise TraceInvalid(f"{role}: clock reference lacks thread identity")
    samples = reference["samples_ns"]
    if not isinstance(samples, list) or len(samples) != 64 or any(
        not _is_int(value) or not 0 <= value < 2**64 for value in samples
    ):
        raise TraceInvalid(f"{role}: invalid clock reference samples")
    return reference


def _resource_window(trace: dict[str, Any], role: str, trials: int) -> dict[str, Any] | None:
    window = trace.get("resource_window")
    if window is None:
        return None  # Historical traces did not capture process resources.
    counters = {"started_elapsed_ns", "finished_elapsed_ns", "user_cpu_ns", "system_cpu_ns",
                "voluntary_context_switches", "involuntary_context_switches", "lifetime_max_rss_kib"}
    if not isinstance(window, dict) or set(window) != counters | {"valid", "scope", "window"}:
        raise TraceInvalid(f"{role}: malformed resource window")
    if window["valid"] is not True or window["scope"] != "RUSAGE_SELF" or window["window"] != "after-warmup-to-export":
        raise TraceInvalid(f"{role}: unsupported or invalid resource window")
    if any(not _is_int(window[key]) or window[key] < 0 for key in counters):
        raise TraceInvalid(f"{role}: invalid resource counter")
    start, end = window["started_elapsed_ns"], window["finished_elapsed_ns"]
    edge = "sink_accepted" if role == "client" else "wire_encoded"
    before = _by_stage_seq(trace["events"], edge)[0][0]["elapsed_ns"]
    first_stage = "terminal_read" if role == "client" else "wire_decoded"
    first = _by_stage_seq(trace["events"], first_stage)[1][0]["elapsed_ns"]
    last = _by_stage_seq(trace["events"], edge)[trials][-1]["elapsed_ns"]
    if not before <= start <= first or end < last or end < start:
        raise TraceInvalid(f"{role}: resources do not enclose post-warmup trials")
    return window


def analyze(result_value: Any, client_value: Any, server_value: Any) -> dict[str, Any]:
    """Return a diagnostic-only attribution report.

    Invalid input returns ``status=UNKNOWN`` with no trial measurements.  A
    valid report always uses ``status=DIAGNOSTIC``; it is never a PASS result.
    """
    errors: list[str] = []
    try:
        if not isinstance(result_value, dict):
            raise TraceInvalid("result: object required")
        if not _is_int(result_value.get("schema_version")) or result_value.get("schema_version") != SCHEMA_VERSION:
            raise TraceInvalid("result: unsupported schema_version")
        trials = result_value.get("trials")
        samples = result_value.get("samples_us")
        boundaries = result_value.get("public_boundaries")
        if not _is_int(trials) or trials <= 0 or not isinstance(samples, list) or len(samples) != trials:
            raise TraceInvalid("result: trials/samples_us mismatch")
        if not isinstance(boundaries, list) or len(boundaries) != trials:
            raise TraceInvalid("result: public_boundaries mismatch")
        if result_value.get("public_clock") != "CLOCK_MONOTONIC; local host and time namespace only":
            raise TraceInvalid("result: unsupported public clock")
        if not _is_int(result_value.get("transcript_failures")) or result_value["transcript_failures"] != 0:
            raise TraceInvalid("result: transcript failures present")
        previous_send = previous_accepted = -1
        for i, boundary in enumerate(boundaries):
            if not _is_int(samples[i]) or samples[i] <= 0:
                raise TraceInvalid(f"result: malformed sample {i}")
            if not isinstance(boundary, dict) or set(boundary) != {"trial", "send_ns", "accepted_ns"}:
                raise TraceInvalid(f"result: malformed public boundary {i}")
            if not _is_int(boundary["trial"]) or boundary["trial"] != i or not _is_int(boundary["send_ns"]) or not _is_int(boundary["accepted_ns"]):
                raise TraceInvalid(f"result: malformed public boundary {i}")
            if boundary["send_ns"] < 0 or boundary["accepted_ns"] < 0 or boundary["accepted_ns"] < boundary["send_ns"]:
                raise TraceInvalid(f"result: boundary {i} regresses")
            if boundary["send_ns"] < previous_accepted or boundary["accepted_ns"] < previous_accepted:
                raise TraceInvalid(f"result: public boundaries are not monotonic at {i}")
            previous_send = boundary["send_ns"]
            previous_accepted = boundary["accepted_ns"]
            expected_us = (boundary["accepted_ns"] - boundary["send_ns"] + 999) // 1000
            if samples[i] != expected_us:
                raise TraceInvalid(f"result: sample {i} disagrees with public boundary")
        client = validate_trace(client_value, "client")
        server = validate_trace(server_value, "server")
        for role, trace in (("client", client), ("server", server)):
            sequenced = set(SEQUENCED_CLIENT if role == "client" else SEQUENCED_SERVER)
            sequenced.add("retry" if role == "client" else "callback_exit")
            for event in trace["events"]:
                if event["stage"] in sequenced:
                    if event["sequence"] is None or event["sequence"] > trials:
                        raise TraceInvalid(f"{role}: required sequence missing or out of range")
                elif event["sequence"] is not None:
                    raise TraceInvalid(f"{role}: unexpected sequence on unsequenced stage")
        _require_sequences(client, SEQUENCED_CLIENT, trials, "client")
        _require_sequences(server, SEQUENCED_SERVER, trials, "server")
        _require_one_per_public_sequence(client, ("terminal_read", "wire_encoded", "protocol_offer", "sink_accepted"), trials, "client")
        _validate_client_order(client, trials)
        _validate_callback_contract(client, "client", trials)
        _validate_callback_contract(server, "server", trials)
        resources = {role: _resource_window(trace, role, trials)
                     for role, trace in (("client", client), ("server", server))}
        calibrations = {role: _clock_calibration(trace, role)
                        for role, trace in (("client", client), ("server", server))}
        rows = _trial_summary(client, server, trials)
        try:
            handoffs = analyze_handoffs(result_value, client)
        except ValueError as exc:
            raise TraceInvalid(f"local clock alignment: {exc}") from exc
        scheduling = _server_scheduling(server, rows)
        sender_polls = {role: _poll_intervals(trace, role)
                        for role, trace in (("client", client), ("server", server))}
        protocol_polls = {role: _poll_intervals(trace, role, protocol=True)
                          for role, trace in (("client", client), ("server", server))}
        if any(row["terminal_read_to_wire_encoded_ns"] is None or row["protocol_offer_to_sink_accepted_ns"] is None for row in rows):
            raise TraceInvalid("trace: required same-thread interval is unavailable")
        return {
            "status": "DIAGNOSTIC",
            "architecture_decision": "UNKNOWN",
            "attribution_complete": False,
            "residual_assumption": "Unique request, same-host clock rate and causal containment; not network-only. Caller must establish same-host topology independently.",
            "qualification": "NOT_APPLICABLE",
            "integration_authorized": False,
            "trials": trials,
            "warmup_sequence": 0,
            "trace_clock_domain": CLOCK_DOMAIN,
            "resource_windows": resources,
            "local_handoffs": handoffs,
            "cpu_clock_calibration": calibrations,
            "cpu_clock_calibration_semantics": "Startup reference on the recorded thread; back-to-back clock-read deltas only, not total recorder overhead. Raw call measurements are not adjusted or reduced by this reference.",
            "server_scheduling": scheduling,
            "sender_poll_intervals": sender_polls,
            "protocol_poll_intervals": protocol_polls,
            "resource_semantics": "Per-process after-warmup-to-export CPU/context-switch deltas, including gaps/control activity; excludes children. RSS is lifetime high-water, not window allocation or live memory.",
            "client_event_counts": dict(Counter(event["stage"] for event in client["events"])),
            "server_event_counts": dict(Counter(event["stage"] for event in server["events"])),
            "client_allocator_window": _allocation_window(client),
            "server_allocator_window": _allocation_window(server),
            "noq_marker_completeness": {
                "client": sorted(NOQ_CORE_STAGES & {event["stage"] for event in client["events"]}),
                "server": sorted(NOQ_CORE_STAGES & {event["stage"] for event in server["events"]}),
                "required": sorted(NOQ_CORE_STAGES),
                "complete": all(
                    NOQ_CORE_STAGES.issubset({event["stage"] for event in trace["events"]})
                    for trace in (client, server)
                ),
            },
            "allocator_semantics": "process-window request counters; not native allocations or stage-exclusive attribution",
            "noq_marker_semantics": "sequence=null markers are aggregate process activity and are not assigned to packets or trials",
            "rows": rows,
        }
    except TraceInvalid as exc:
        errors.append(str(exc))
        return {
            "status": "UNKNOWN",
            "qualification": "NOT_APPLICABLE",
            "integration_authorized": False,
            "errors": errors,
            "rows": [],
        }


def analyze_paths(result_path: str | pathlib.Path, client_path: str | pathlib.Path, server_path: str | pathlib.Path) -> dict[str, Any]:
    try:
        return analyze(_read_json(result_path), _read_json(client_path), _read_json(server_path))
    except TraceInvalid as exc:
        return {"status": "UNKNOWN", "qualification": "NOT_APPLICABLE", "integration_authorized": False, "errors": [str(exc)], "rows": []}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result")
    parser.add_argument("client_trace")
    parser.add_argument("server_trace")
    parser.add_argument("-o", "--output", type=pathlib.Path)
    args = parser.parse_args(argv)
    report = analyze_paths(args.result, args.client_trace, args.server_trace)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    return 0 if report["status"] == "DIAGNOSTIC" else 2


if __name__ == "__main__":
    raise SystemExit(main())
