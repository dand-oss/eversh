"""Keep syscall observations within public trial windows, without packet guessing.

Successful network syscalls can carry QUIC ACKs or retries, not necessarily the
terminal byte. This export deliberately retains all of them and does not label
the time between endpoints as exclusive network, scheduler or CPU time.
"""
from analyze_poll_turns import _sample_check
from clock_alignment import _identity, _validated_boundaries
from syscall_pairs import pair_syscalls
from statistics import median


def _terminal_fd_aliases(capture):
    """Return the explicitly captured stdin/stdout descriptor aliases.

    Production terminal endpoints may duplicate their descriptors before the
    trace starts.  The capture writer records those aliases so edge selection
    can remain exact.  Older captures have no map and retain the historical
    descriptors 0 and 1.  A present map is deliberately strict: silently
    falling back to 0/1 would select an unrelated descriptor and invalidate
    the attribution.
    """
    if "terminal_fds" not in capture:
        return [0], [1]
    aliases = capture["terminal_fds"]
    if type(aliases) is not dict or set(aliases) != {"stdin", "stdout"}:
        raise ValueError("invalid terminal descriptor aliases")
    result = []
    for name in ("stdin", "stdout"):
        values = aliases[name]
        if type(values) is not list or not values:
            raise ValueError("invalid terminal descriptor aliases")
        if any(type(fd) is not int or fd < 0 for fd in values):
            raise ValueError("invalid terminal descriptor aliases")
        if len(set(values)) != len(values):
            raise ValueError("invalid terminal descriptor aliases")
        result.append(values)
    return result[0], result[1]


def analyze(result, export, capture):
    try:
        _, boundaries = _validated_boundaries(result)
        _sample_check(result, boundaries)
        identity = _identity(result.get("clock_identity"), "public clock")
        if capture.get("status") != "DIAGNOSTIC" or capture.get("clock") != "CLOCK_MONOTONIC":
            raise ValueError("unvalidated capture clock")
        _terminal_fd_aliases(capture)
        target = capture["identity"]
        pid = target["pid"]
        if type(pid) is not int or pid <= 0 or target["tids"] != [pid]:
            raise ValueError("capture must identify exactly one thread")
        if target["boot_id"] != identity["boot_id"] or target["time_namespace"] != [
                identity["time_namespace_dev"], identity["time_namespace_ino"]]:
            raise ValueError("capture and public clock identity differ")
        paired = pair_syscalls(export)
        lower, upper = paired["coverage_ns"]
        rows = []
        for boundary in boundaries:
            start, end = boundary["send_ns"], boundary["accepted_ns"]
            row = {"trial": boundary["trial"], "window_ns": [start, end]}
            if start < lower or end > upper:
                row.update(status="excluded", exclusion="outside_capture_coverage")
                rows.append(row)
                continue
            if any(start <= partial["time_ns"] <= end for partial in paired["partial_edges"]):
                row.update(status="excluded", exclusion="partial_syscall_edge")
                rows.append(row)
                continue
            calls = []
            for call in paired["pairs"]:
                if call["exit_ns"] <= start or call["enter_ns"] >= end:
                    continue
                calls.append({**call,
                    "window_overlap_ns": [max(start, call["enter_ns"]), min(end, call["exit_ns"])],
                    "crosses_boundary": call["enter_ns"] < start or call["exit_ns"] > end,
                    "successful": call["ret"] > 0})
            row.update(status="included", calls=calls)
            rows.append(row)
        return {"status": "DIAGNOSTIC", "qualification": "NOT_APPLICABLE",
                "target_pid": pid, "rows": rows,
                "included_trials": sum(row["status"] == "included" for row in rows),
                "limitation": "Syscall-observed intervals only; network calls may be ACKs or retries."}
    except (ValueError, KeyError, TypeError) as error:
        return {"status": "UNKNOWN", "qualification": "NOT_APPLICABLE", "rows": [],
                "reason": str(error)}


def analyze_client(result, export, capture):
    """Select observable local edges; never infer the contents of a network call."""
    report = analyze(result, export, capture)
    if report["status"] != "DIAGNOSTIC":
        return report
    stdin_fds, stdout_fds = _terminal_fd_aliases(capture)
    rows = []
    for window in report["rows"]:
        row = {key: value for key, value in window.items() if key != "calls"}
        if window["status"] != "included":
            rows.append(row)
            continue
        calls = window["calls"]
        reads = [c for c in calls if c["syscall"] == "read" and c["fields"]["fd"] in stdin_fds and c["ret"] > 0]
        writes = [c for c in calls if c["syscall"] == "write" and c["fields"]["fd"] in stdout_fds and c["ret"] > 0]
        reason = None
        if len(reads) != 1 or len(writes) != 1:
            reason = "nonunique_terminal_edges"
        elif reads[0]["ret"] != 1 or writes[0]["ret"] != 1:
            reason = "non_single_byte_terminal_edge"
        elif reads[0]["crosses_boundary"] or writes[0]["crosses_boundary"]:
            reason = "terminal_edge_crosses_boundary"
        elif reads[0]["exit_ns"] > writes[0]["enter_ns"]:
            reason = "terminal_edge_order"
        if reason:
            row.update(status="excluded", exclusion=reason)
            rows.append(row)
            continue
        read, write = reads[0], writes[0]
        sends = [c for c in calls if c["syscall"] in ("sendmsg", "sendmmsg", "sendto")
                 and c["ret"] > 0 and c["enter_ns"] >= read["exit_ns"]
                 and c["exit_ns"] <= write["enter_ns"] and not c["crosses_boundary"]]
        if not sends:
            row.update(status="excluded", exclusion="no_successful_send_between_terminal_edges")
        elif len({c["fields"]["fd"] for c in sends}) != 1:
            row.update(status="excluded", exclusion="multiple_network_descriptors")
        else:
            first = sends[0]
            start, end = window["window_ns"]
            intervals = {
                "public_send_to_stdin_enter": [start, read["enter_ns"]],
                "stdin_exit_to_first_successful_send_enter": [read["exit_ns"], first["enter_ns"]],
                "stdout_syscall": [write["enter_ns"], write["exit_ns"]],
                "stdout_exit_to_public_accept": [write["exit_ns"], end],
            }
            row.update(intervals_ns=intervals,
                       durations_ns={key: end - start for key, (start, end) in intervals.items()},
                       observed_successful_send_calls=len(sends), first_send_syscall=first["syscall"])
        rows.append(row)
    included = [row for row in rows if row["status"] == "included"]
    return {"status": "DIAGNOSTIC", "qualification": "NOT_APPLICABLE",
            "target_pid": report["target_pid"], "rows": rows,
            "included_trials": len(included),
            "median_durations_ns": {key: median(row["durations_ns"][key] for row in included)
                                    for key in included[0]["durations_ns"]} if included else {},
            "limitation": "Observed edges only, not terminal-packet identity or exclusive CPU/scheduler time; do not add stage medians."}
