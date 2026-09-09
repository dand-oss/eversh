"""Pair single-thread, payload-free syscall exports without guessing lost edges.

An unmatched first exit and last enter are capture-boundary exclusions only.
All other gaps, nesting or mismatched edges invalidate the entire capture.
Durations are observed syscall intervals, not CPU or scheduling measurements.
"""

_FIELDS = {
    "read": {"fd", "count"}, "write": {"fd", "count"},
    "poll": {"nfds", "timeout_msecs"},
    "sendmsg": {"fd", "flags"}, "recvmsg": {"fd", "flags"},
    "sendmmsg": {"fd", "vlen", "flags"},
    "recvmmsg": {"fd", "vlen", "flags"},
    "sendto": {"fd", "len", "flags", "addr_len"},
    "recvfrom": {"fd", "size", "flags"},
}


def _integer(value, minimum=0, maximum=(1 << 64) - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid integer field")
    return value


def pair_syscalls(export):
    """Return complete pairs plus explicit partial capture edges; raise on invalidity."""
    if not isinstance(export, dict) or set(export) != {"schema_version", "events"}:
        raise ValueError("invalid export envelope")
    if type(export["schema_version"]) is not int or export["schema_version"] != 1:
        raise ValueError("unsupported export version")
    events = export["events"]
    if not isinstance(events, list) or not events:
        raise ValueError("empty capture")
    pairs, partial = [], []
    pending = None
    previous = -1
    for index, event in enumerate(events):
        if not isinstance(event, dict) or set(event) != {"time_ns", "event", "fields"}:
            raise ValueError("invalid event shape")
        now = _integer(event["time_ns"])
        if now < previous:
            raise ValueError("timestamp regression")
        previous = now
        name = event["event"]
        if not isinstance(name, str) or not name.startswith("syscalls:sys_"):
            raise ValueError("unknown event")
        edge, separator, syscall = name[len("syscalls:sys_"):].partition("_")
        if not separator or edge not in ("enter", "exit") or syscall not in _FIELDS:
            raise ValueError("unknown syscall edge")
        fields = event["fields"]
        expected = _FIELDS[syscall] if edge == "enter" else {"ret"}
        if not isinstance(fields, dict) or set(fields) != expected:
            raise ValueError("unexpected syscall fields")
        for key, value in fields.items():
            if key == "ret":
                _integer(value, -(1 << 63), (1 << 63) - 1)
            elif key == "timeout_msecs":
                _integer(value, -(1 << 31), (1 << 31) - 1)
            else:
                _integer(value)
        if edge == "enter":
            if pending is not None:
                raise ValueError("nested syscall on a single-thread capture")
            pending = (syscall, now, dict(fields))
            continue
        if pending is None:
            if index != 0:
                raise ValueError("unpaired noninitial exit")
            partial.append({"edge": "initial_exit", "syscall": syscall, "time_ns": now})
            continue
        call, start, arguments = pending
        if call != syscall:
            raise ValueError("mismatched syscall exit")
        ret = fields["ret"]
        cap = arguments.get("count") if call in ("read", "write") else arguments.get("vlen")
        if call == "sendto":
            cap = arguments["len"]
        elif call == "recvfrom" and not arguments["flags"] & 0x20:  # Linux MSG_TRUNC
            cap = arguments["size"]
        if cap is not None and ret > cap:
            raise ValueError("return exceeds requested count")
        pairs.append({"syscall": call, "enter_ns": start, "exit_ns": now,
                      "fields": arguments, "ret": ret})
        pending = None
    if pending is not None:
        partial.append({"edge": "final_enter", "syscall": pending[0], "time_ns": pending[1]})
    return {"pairs": pairs, "partial_edges": partial,
            "coverage_ns": [events[0]["time_ns"], events[-1]["time_ns"]]}
