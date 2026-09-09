"""Strict correlation of the opt-in production path traces.

This is diagnostic only.  It deliberately keeps signed handoff intervals and
never turns separate input/output sequences into a single latency estimate.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from analyze_poll_turns import _sample_check  # noqa: E402
from clock_alignment import _validated_boundaries  # noqa: E402

CAPACITY = 32_768
PUBLIC_CLOCK = "CLOCK_MONOTONIC; local host and time namespace only"
TRACE_CLOCK = "CLOCK_MONOTONIC"
UINT64_MAX = (1 << 64) - 1
BOOT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CLIENT_STAGES = {
    "client_input_queued",
    "client_input_written",
    "client_output_staged",
    "client_output_accepted",
}
GATEWAY_STAGES = {
    "gateway_input_prepared",
    "gateway_input_accepted",
    "gateway_output_queued",
}


def _u64(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT64_MAX:
        raise ValueError(f"{label}: expected u64")
    return value


def _identity(value: Any, label: str) -> tuple[str, int, int]:
    if not isinstance(value, dict) or set(value) != {"boot_id", "time_namespace_dev", "time_namespace_ino"}:
        raise ValueError(f"{label}: malformed identity")
    boot = value["boot_id"]
    if not isinstance(boot, str) or BOOT_ID.fullmatch(boot) is None:
        raise ValueError(f"{label}: invalid boot id")
    return boot, _u64(value["time_namespace_dev"], f"{label}.dev"), _u64(
        value["time_namespace_ino"], f"{label}.ino"
    )


def _trace(value: Any, role: str) -> tuple[tuple[str, int, int], list[dict[str, Any]]]:
    if not isinstance(value, dict):
        raise ValueError(f"{role}: expected object")
    required = {
        "schema_version", "diagnostic_only", "clock", "valid", "overflow",
        "pid", "boot_id", "namespace_dev", "namespace_ino", "events",
    }
    if set(value) != required:
        raise ValueError(f"{role}: malformed top-level fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["diagnostic_only"] is not True:
        raise ValueError(f"{role}: unsupported schema")
    if value["clock"] != TRACE_CLOCK or value["valid"] is not True or value["overflow"] is not False:
        raise ValueError(f"{role}: invalid trace status")
    _u64(value["pid"], f"{role}.pid")
    if value["pid"] == 0:
        raise ValueError(f"{role}: invalid pid")
    identity = _identity(
        {
            "boot_id": value["boot_id"],
            "time_namespace_dev": value["namespace_dev"],
            "time_namespace_ino": value["namespace_ino"],
        },
        role,
    )
    events = value["events"]
    if not isinstance(events, list) or not events or len(events) > CAPACITY:
        raise ValueError(f"{role}: invalid event count")
    allowed = CLIENT_STAGES if role == "client" else GATEWAY_STAGES
    previous = -1
    normalized: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        if not isinstance(event, dict) or set(event) != {"stage", "epoch", "sequence", "time_ns"}:
            raise ValueError(f"{role}: malformed event {index}")
        stage = event["stage"]
        if not isinstance(stage, str) or stage not in allowed:
            raise ValueError(f"{role}: invalid stage")
        epoch = _u64(event["epoch"], f"{role}.epoch")
        sequence = _u64(event["sequence"], f"{role}.sequence")
        time_ns = _u64(event["time_ns"], f"{role}.time_ns")
        if time_ns < previous:
            raise ValueError(f"{role}: timestamp regression")
        previous = time_ns
        normalized.append({"stage": stage, "epoch": epoch, "sequence": sequence, "time_ns": time_ns})
    return identity, normalized


def _in_window(time_ns: int, boundary: dict[str, int]) -> bool:
    return boundary["send_ns"] <= time_ns <= boundary["accepted_ns"]


def _unique_stage(events: list[dict[str, Any]], stage: str) -> None:
    seen: set[tuple[int, int]] = set()
    for event in events:
        if event["stage"] != stage:
            continue
        key = (event["epoch"], event["sequence"])
        if key in seen:
            raise ValueError(f"duplicate {stage} marker")
        seen.add(key)


def analyze(client: dict[str, Any], gateway: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Correlate client/gateway markers against public benchmark boundaries."""
    if not isinstance(result, dict) or result.get("public_clock") != PUBLIC_CLOCK:
        raise ValueError("result: unsupported public clock")
    public_identity = _identity(result.get("clock_identity"), "result.clock_identity")
    client_identity, client_events = _trace(client, "client")
    gateway_identity, gateway_events = _trace(gateway, "gateway")
    if client_identity != gateway_identity or client_identity != public_identity:
        raise ValueError("trace/result clock identities differ")
    _, boundaries = _validated_boundaries(result)
    _sample_check(result, boundaries)

    c_by_stage = {stage: [e for e in client_events if e["stage"] == stage] for stage in CLIENT_STAGES}
    _unique_stage(client_events, "client_input_queued")
    _unique_stage(client_events, "client_output_staged")
    _unique_stage(client_events, "client_output_accepted")
    _unique_stage(gateway_events, "gateway_input_accepted")
    _unique_stage(gateway_events, "gateway_output_queued")
    measured_rows: list[dict[str, Any]] = []
    used_client_events: set[int] = set()
    for boundary in boundaries:
        queued = [e for e in c_by_stage["client_input_queued"] if _in_window(e["time_ns"], boundary)]
        staged = [e for e in c_by_stage["client_output_staged"] if _in_window(e["time_ns"], boundary)]
        if len(queued) != 1 or len(staged) != 1:
            raise ValueError(f"trial {boundary['trial']}: missing or ambiguous client markers")
        q, s = queued[0], staged[0]
        key_in = (q["epoch"], q["sequence"])
        key_out = (s["epoch"], s["sequence"])
        written = [e for e in c_by_stage["client_input_written"] if (e["epoch"], e["sequence"]) == key_in and e["time_ns"] >= q["time_ns"]]
        if not written:
            raise ValueError(f"trial {boundary['trial']}: input was never written")
        accepted_out = [e for e in c_by_stage["client_output_accepted"] if (e["epoch"], e["sequence"]) == key_out and e["time_ns"] >= s["time_ns"]]
        if len(accepted_out) != 1:
            raise ValueError(f"trial {boundary['trial']}: output acceptance is missing or duplicated")
        prepared = [e for e in gateway_events if e["stage"] == "gateway_input_prepared" and (e["epoch"], e["sequence"]) == key_in and e["time_ns"] >= q["time_ns"]]
        accepted = [e for e in gateway_events if e["stage"] == "gateway_input_accepted" and (e["epoch"], e["sequence"]) == key_in and e["time_ns"] >= q["time_ns"]]
        queued_out = [e for e in gateway_events if e["stage"] == "gateway_output_queued" and (e["epoch"], e["sequence"]) == key_out]
        if not prepared or len(accepted) != 1 or len(queued_out) != 1:
            raise ValueError(f"trial {boundary['trial']}: missing or duplicated gateway markers")
        used_client_events.update(id(e) for e in (q, s))
        out_accept = accepted_out[0]
        if accepted[0]["time_ns"] < min(e["time_ns"] for e in prepared):
            raise ValueError(f"trial {boundary['trial']}: gateway input accepted before preparation")
        if queued_out[0]["time_ns"] < accepted[0]["time_ns"]:
            raise ValueError(f"trial {boundary['trial']}: output queued before input accepted")
        if queued_out[0]["time_ns"] > s["time_ns"]:
            raise ValueError(f"trial {boundary['trial']}: output queued after client staging")
        if written[0]["time_ns"] > s["time_ns"]:
            raise ValueError(f"trial {boundary['trial']}: first input write follows client staging")
        if any(e["time_ns"] > accepted[0]["time_ns"] for e in prepared):
            raise ValueError(f"trial {boundary['trial']}: preparation follows committed input")
        next_boundary = boundaries[boundary["trial"] + 1] if boundary["trial"] + 1 < len(boundaries) else None
        if next_boundary is not None and out_accept["time_ns"] >= next_boundary["send_ns"]:
            raise ValueError(f"trial {boundary['trial']}: output acceptance crosses next public send")
        measured_rows.append({
            "trial": boundary["trial"],
            "input": {"epoch": key_in[0], "sequence": key_in[1], "queued_ns": q["time_ns"], "written_ns": [e["time_ns"] for e in written], "prepared_ns": [e["time_ns"] for e in prepared], "accepted_ns": accepted[0]["time_ns"]},
            "output": {"epoch": key_out[0], "sequence": key_out[1], "gateway_queued_ns": queued_out[0]["time_ns"], "staged_ns": s["time_ns"], "accepted_ns": out_accept["time_ns"]},
            "stream_handoff_ns": prepared[0]["time_ns"] - written[0]["time_ns"],
            "output_handoff_ns": out_accept["time_ns"] - boundary["accepted_ns"],
        })
    unmatched = [e for e in c_by_stage["client_input_queued"] + c_by_stage["client_output_staged"] if id(e) not in used_client_events]
    if any(e["time_ns"] >= boundaries[0]["send_ns"] for e in unmatched):
        raise ValueError("unmatched client anchor after warmup")
    warmup = len(unmatched)
    return {"status": "DIAGNOSTIC", "qualification": False, "rows": measured_rows, "warmup_client_markers": warmup}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    parser.add_argument("gateway", type=Path)
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    def load(path: Path) -> Any:
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("JSON input exceeds bounded size")
        return json.loads(path.read_text(), object_pairs_hook=reject_duplicate_keys)

    print(json.dumps(analyze(*(load(path) for path in (args.client, args.gateway, args.result))), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
