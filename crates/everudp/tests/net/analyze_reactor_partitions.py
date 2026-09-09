"""Validate phase timings against the existing reactor-work contract.

Partitions are nested in a single observed step; differences from its outer
duration are unattributed intervals, not proven overhead or removable cost.
"""
from copy import deepcopy

from analyze_reactor_work import analyze as analyze_work, _uint

PHASES = ("pump", "send", "segment", "receive", "event_drain")


def analyze(result, trace):
    try:
        if not isinstance(trace, dict) or type(trace.get("schema_version")) is not int:
            raise ValueError("invalid partition schema")
        if trace["schema_version"] != 2 or trace.get("protocol") != "everudp-reactor-partitions-v2":
            raise ValueError("unsupported partition schema")
        base = deepcopy(trace)
        base["schema_version"] = 1
        base["protocol"] = "everudp-reactor-work-v1"
        by_sequence = {}
        for event in base["events"]:
            if event.get("kind") != "step":
                continue
            partitions = event.pop("partitions")
            if not isinstance(partitions, dict) or set(partitions) != {"valid", "overflow", "phases"}:
                raise ValueError("unexpected partition fields")
            if partitions["valid"] is not True or partitions["overflow"] is not False:
                raise ValueError("invalid partition recording")
            phases = partitions["phases"]
            if not isinstance(phases, dict) or set(phases) != set(PHASES):
                raise ValueError("unexpected phase set")
            for phase, totals in phases.items():
                if not isinstance(totals, dict) or set(totals) != {"calls", "wall_ns", "cpu_ns"}:
                    raise ValueError("unexpected phase totals")
                for key, value in totals.items():
                    _uint(value, f"{phase}.{key}")
                if totals["calls"] == 0 and (totals["wall_ns"] or totals["cpu_ns"]):
                    raise ValueError("uncalled phase has duration")
            for phase, counter in (("pump", "pump_drive_calls"), ("send", "send_attempts"),
                                   ("receive", "receive_calls")):
                if phases[phase]["calls"] != event[counter]:
                    raise ValueError("phase calls disagree with operation counts")
            if phases["event_drain"]["calls"] != 1:
                raise ValueError("step must have exactly one caller event drain")
            if phases["pump"]["calls"] != event["result"]["work"]:
                raise ValueError("pump calls disagree with turn count")
            if not 1 <= phases["pump"]["calls"] <= 64:
                raise ValueError("phase turn count outside reactor budget")
            if phases["segment"]["calls"] + phases["send"]["calls"] != phases["pump"]["calls"]:
                raise ValueError("send/segment branches disagree with turn count")
            if phases["receive"]["calls"] > phases["segment"]["calls"]:
                raise ValueError("receive without a segment check")
            if event["retained_gro_segments_delivered"] > phases["segment"]["calls"]:
                raise ValueError("delivered segments exceed processing calls")
            remainder = {}
            for clock, begin, end in (("wall_ns", "begin_time_ns", "end_time_ns"),
                                      ("cpu_ns", "begin_cpu_time_ns", "end_cpu_time_ns")):
                elapsed = _uint(event[end], end) - _uint(event[begin], begin)
                summed = sum(value[clock] for value in phases.values())
                if summed > elapsed:
                    raise ValueError("phase totals exceed enclosing interval")
                remainder[clock] = elapsed - summed
            by_sequence.setdefault(event["sequence"], []).append({
                "phases": phases, "unattributed_ns": remainder,
            })
        report = analyze_work(result, base)
        if report["status"] != "DIAGNOSTIC":
            return report
        for pair in report["initial_post_offer_pairs"]:
            timings = by_sequence[pair["sequence"]]
            pair["initial_post_offer"].update(timings[0])
            pair["following_loop_top"].update(timings[1])
        report["partition_limitation"] = (
            "Same-step phase sums exclude inter-phase instrumentation and other work. "
            "Unattributed intervals are not causal overhead; do not subtract independent medians."
        )
        return report
    except (ValueError, KeyError, TypeError, IndexError, AttributeError) as error:
        return {"status": "UNKNOWN", "qualification": "NOT_APPLICABLE", "rows": [], "reason": str(error)}
