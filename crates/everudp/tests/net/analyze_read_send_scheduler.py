"""Attribute scheduler off-CPU gaps inside the observed read-to-send edge.

This is deliberately diagnostic.  The scheduler trace is an exported view of
task switches, not an exclusive CPU measurement: kernel, interrupt, tracing,
and other unobserved work may be present in either interval.  Every IO row from
``io_trial_windows.analyze_client`` is retained, including its exclusions.
"""

from statistics import median

from io_trial_windows import analyze_client


_U64_MAX = (1 << 64) - 1


def _strict_int(value, *, minimum=0, maximum=_U64_MAX):
    if type(value) is not int or value < minimum or value > maximum:
        raise ValueError("invalid scheduler integer")
    return value


def _scheduler_events(scheduler, target_pid):
    if type(scheduler) is not dict or set(scheduler) != {"schema_version", "clock", "pid", "events"}:
        raise ValueError("invalid scheduler schema")
    if type(scheduler["schema_version"]) is not int or scheduler["schema_version"] != 1:
        raise ValueError("invalid scheduler schema version")
    if scheduler["clock"] != "CLOCK_MONOTONIC":
        raise ValueError("scheduler clock is not monotonic")
    if type(scheduler["pid"]) is not int or scheduler["pid"] <= 0 or scheduler["pid"] != target_pid:
        raise ValueError("scheduler target pid differs from capture")
    events = scheduler["events"]
    if type(events) is not list or len(events) < 2:
        raise ValueError("scheduler requires at least two events")
    parsed = []
    previous = None
    for event in events:
        if type(event) is not dict or set(event) != {"time_ns", "prev_pid", "next_pid"}:
            raise ValueError("invalid scheduler event schema")
        timestamp = _strict_int(event["time_ns"])
        previous_pid = _strict_int(event["prev_pid"], minimum=0)
        next_pid = _strict_int(event["next_pid"], minimum=0)
        # PID 0 is the Linux idle task and is valid as the non-target side.
        if previous_pid == next_pid or target_pid not in (previous_pid, next_pid):
            raise ValueError("scheduler switch is not a target transition")
        if previous is not None and timestamp <= previous:
            raise ValueError("scheduler timestamp regresses")
        previous = timestamp
        parsed.append({"time_ns": timestamp, "prev_pid": previous_pid, "next_pid": next_pid})
    return parsed


def _off_cpu(events, start, end, target_pid):
    """Return target off-CPU time for switches strictly inside [start, end]."""
    if any(event["time_ns"] in (start, end) for event in events):
        raise ValueError("scheduler switch touches an IO boundary")
    interior = [event for event in events if start < event["time_ns"] < end]
    state = "running"
    off_cpu = 0
    switched_out = None
    for event in interior:
        if event["prev_pid"] == target_pid:
            if state != "running":
                raise ValueError("impossible scheduler switch chain")
            state = "off_cpu"
            switched_out = event["time_ns"]
        elif event["next_pid"] == target_pid:
            if state != "off_cpu" or switched_out is None:
                raise ValueError("impossible scheduler switch chain")
            off_cpu += event["time_ns"] - switched_out
            state = "running"
            switched_out = None
        else:  # schema validation should make this unreachable.
            raise ValueError("scheduler switch does not involve target")
    if state != "running":
        raise ValueError("incomplete scheduler switch chain")
    return off_cpu


def analyze(result, io_export, capture, scheduler):
    """Join public IO windows to a strict scheduler export.

    Invalid scheduler evidence makes the complete report ``UNKNOWN``.  A
    valid scheduler trace that does not cover one IO edge produces an explicit
    per-row exclusion, preserving the IO analyzer's existing exclusions.
    """
    try:
        io_report = analyze_client(result, io_export, capture)
        if io_report["status"] != "DIAGNOSTIC":
            return io_report
        identity = capture["identity"]
        target_pid = identity["pid"]
        if capture.get("clock") != "CLOCK_MONOTONIC":
            raise ValueError("capture clock is not monotonic")
        if type(scheduler) is not dict or scheduler.get("clock") != capture["clock"]:
            raise ValueError("capture and scheduler clocks differ")
        events = _scheduler_events(scheduler, target_pid)
        coverage = (events[0]["time_ns"], events[-1]["time_ns"])
        rows = []
        for source in io_report["rows"]:
            row = dict(source)
            if source["status"] != "included":
                rows.append(row)
                continue
            interval = source["intervals_ns"]["stdin_exit_to_first_successful_send_enter"]
            start, end = interval
            if start < coverage[0] or end > coverage[1]:
                row.update(status="excluded", exclusion="outside_scheduler_coverage")
                rows.append(row)
                continue
            if end < start:
                raise ValueError("invalid IO scheduler interval")
            off_cpu = _off_cpu(events, start, end, target_pid)
            wall = end - start
            if off_cpu > wall:
                raise ValueError("scheduler off-CPU interval exceeds IO interval")
            row.update(scheduled_wall_ns=wall - off_cpu, off_cpu_ns=off_cpu)
            rows.append(row)
        included = [row for row in rows if row["status"] == "included"]
        duration_keys = set()
        for row in included:
            duration_keys.update(row.get("durations_ns", {}))
        medians = {key: median(row["durations_ns"][key] for row in included)
                   for key in duration_keys}
        if included:
            medians["scheduled_wall_ns"] = median(row["scheduled_wall_ns"] for row in included)
            medians["off_cpu_ns"] = median(row["off_cpu_ns"] for row in included)
        return {**io_report, "rows": rows, "included_trials": len(included),
                "median_durations_ns": medians,
                "median_scheduled_wall_ns": medians.get("scheduled_wall_ns"),
                "median_off_cpu_ns": medians.get("off_cpu_ns"),
                "scheduler_pid": target_pid,
                "scheduler_coverage_ns": list(coverage),
                "limitation": "Observed scheduler switches only; scheduled wall and off-CPU intervals are not exclusive CPU or network measurements."}
    except (ValueError, TypeError, KeyError, IndexError) as error:
        return {"status": "UNKNOWN", "qualification": "NOT_APPLICABLE", "rows": [],
                "reason": str(error)}
