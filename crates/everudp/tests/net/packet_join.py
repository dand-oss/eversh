"""Fail-closed correlation of a terminal operation with QUIC packet events.

This module is deliberately a diagnostic primitive.  It joins immutable packet
identifiers and byte ranges; it never guesses a join from timestamp proximity
and it does not inspect payloads.
"""

from __future__ import annotations

from typing import Any


_TX = {
    "packet_transmit_poll",
    "packet_transmit_blocked",
    "packet_transmit_error",
    "packet_transmit_accepted",
}
_SPACES = {1, 2, 3}
_UINT62 = (1 << 62) - 1


def _event(event: Any, name: str) -> tuple[int, list[int]]:
    if not isinstance(event, dict) or set(event) != {"event", "time_ns", "values"}:
        raise ValueError(f"{name}: malformed event")
    if event["event"] != name or type(event["time_ns"]) is not int or event["time_ns"] < 0:
        raise ValueError(f"{name}: malformed event")
    values = event["values"]
    if not isinstance(values, list) or any(type(value) is not int or value < 0 for value in values):
        raise ValueError(f"{name}: malformed values")
    return event["time_ns"], values


def _events(events: Any) -> list[dict[str, Any]]:
    if not isinstance(events, list):
        raise ValueError("events: expected list")
    for event in events:
        if not isinstance(event, dict) or not isinstance(event.get("event"), str):
            raise ValueError("events: malformed event")
    return events


def _packet(event: dict[str, Any], name: str) -> tuple[int, list[int]]:
    time_ns, values = _event(event, name)
    arity = {"packet_built": 7, "packet_authenticated": 7,
             "stream_sent": 8, "stream_received": 8}[name]
    if len(values) != arity:
        raise ValueError(f"{name}: invalid arity")
    if name in {"packet_built", "packet_authenticated"}:
        if values[3] not in _SPACES or values[1] == 0 or values[5] == 0:
            raise ValueError(f"{name}: invalid packet identity")
        if values[2] > _UINT62 or values[4] > _UINT62 or values[4] + values[5] > _UINT62:
            raise ValueError(f"{name}: invalid packet range")
    else:
        if values[1] == 0 or values[3] not in _SPACES or values[2] > _UINT62:
            raise ValueError(f"{name}: invalid stream identity")
        if values[4] > _UINT62 or values[5] > _UINT62 or values[6] > _UINT62:
            raise ValueError(f"{name}: invalid stream range")
        if values[5] + values[6] > _UINT62 or values[7] not in (0, 1):
            raise ValueError(f"{name}: invalid stream range")
        if values[6] == 0 and values[7] != 1:
            raise ValueError(f"{name}: empty stream range must be FIN")
    return time_ns, values


def _tx(event: dict[str, Any]) -> tuple[int, list[int]]:
    time_ns, values = _event(event, event.get("event", ""))
    if len(values) != 4 or values[1] == 0 or values[2] == 0:
        raise ValueError("transmit: invalid values")
    return time_ns, values


def _interval_union(intervals: list[tuple[int, int]]) -> tuple[int, int] | None:
    """Return covered prefix if intervals cover one contiguous operation."""
    if not intervals:
        return None
    intervals.sort()
    start, end = intervals[0]
    for left, right in intervals[1:]:
        if left > end:
            return None
        end = max(end, right)
    return start, end


def _unique_operation_generations(events: list[dict[str, Any]]) -> set[int]:
    generations = set()
    ends = {}
    connections: set[int] = set()
    for event in events:
        if event.get("event") != "operation":
            continue
        time_ns, values = _event(event, "operation")
        if len(values) != 7 or values[1] > _UINT62 or values[5] > _UINT62 or values[6] == 0:
            raise ValueError("operation: invalid values")
        if values[5] + values[6] > _UINT62:
            raise ValueError("operation: range overflow")
        connections.add(values[0])
        key = tuple(values[:5])
        if key in generations:
            raise ValueError("operation generation is ambiguous")
        generations.add(key)
        stream_key = tuple(values[:2])
        if stream_key in ends and values[5] != ends[stream_key]:
            raise ValueError("operation stream offset reset or missing range")
        ends[stream_key] = values[5] + values[6]
        if time_ns < 0:  # retained as an explicit invariant for typed callers
            raise ValueError("operation: invalid timestamp")
    return connections


def correlate_operation(
    sender_events: list[dict[str, Any]],
    receiver_events: list[dict[str, Any]],
    operation: dict[str, Any],
    receiver_boundary_ns: int,
) -> dict[str, int]:
    """Join one sender operation to the packet that completes its RX coverage.

    ``sender_events`` and ``receiver_events`` must have passed the strict
    packet-sidecar validator.  A ValueError means the evidence is ambiguous or
    incomplete; callers must not discard such a trial as a successful sample.
    """
    sender = _events(sender_events)
    receiver = _events(receiver_events)
    op_time, op_values = _event(operation, "operation")
    if len(op_values) != 7 or type(receiver_boundary_ns) is not int or receiver_boundary_ns < 0:
        raise ValueError("operation: malformed boundary")
    op_conn, op_stream, op_epoch, op_sequence, op_kind, op_start, op_len = op_values
    if op_stream > _UINT62 or op_start > _UINT62 or op_len == 0 or op_start + op_len > _UINT62:
        raise ValueError("operation: invalid range")
    op_end = op_start + op_len

    sender_connections = _unique_operation_generations(sender)
    receiver_connections = _unique_operation_generations(receiver)
    for events, connections in ((sender, sender_connections), (receiver, receiver_connections)):
        connections.update(e["values"][0] for e in events
                           if e["event"] in {"packet_built", "packet_authenticated",
                                             "stream_sent", "stream_received"})
    if len(sender_connections) > 1 or len(receiver_connections) > 1:
        raise ValueError("multiple connection generations")
    if sender_connections and op_conn not in sender_connections:
        raise ValueError("operation connection is not present")

    # The operation must be the exact recorded anchor, not a caller-created
    # timestamp/range that happens to resemble one.
    anchors = []
    for event in sender:
        if event.get("event") != "operation":
            continue
        time_ns, values = _event(event, "operation")
        if values == op_values and time_ns == op_time:
            anchors.append(event)
    if len(anchors) != 1:
        raise ValueError("operation anchor is missing or ambiguous")

    built: dict[tuple[int, int, int], tuple[int, list[int]]] = {}
    for event in sender:
        if event.get("event") != "packet_built":
            continue
        time_ns, values = _packet(event, "packet_built")
        key = (values[0], values[3], values[2])
        if key in built:
            raise ValueError("duplicate built packet number")
        built[key] = (time_ns, values)

    tx_by_cookie: dict[int, list[tuple[str, int, list[int]]]] = {}
    for event in sender:
        if event.get("event") not in _TX:
            continue
        time_ns, values = _tx(event)
        tx_by_cookie.setdefault(values[1], []).append((event["event"], time_ns, values))

    def tx_chain(packet_time: int, packet: list[int]) -> tuple[int, int]:
        cookie, packet_offset, packet_len = packet[1], packet[4], packet[5]
        records = tx_by_cookie.get(cookie, [])
        accepted = [(time, values) for kind, time, values in records if kind == "packet_transmit_accepted"]
        if len(accepted) != 1:
            raise ValueError("packet transmit acceptance is missing or duplicated")
        accepted_time, accepted_values = accepted[0]
        if accepted_values[0] != packet[0] or any(values != accepted_values for _, _, values in records):
            raise ValueError("transmit cookie metadata changed")
        polls = [(time, values) for kind, time, values in records if kind == "packet_transmit_poll" and time <= accepted_time]
        if not polls:
            raise ValueError("packet transmit poll is missing")
        poll_time, poll_values = max(polls, key=lambda item: item[0])
        if poll_values != accepted_values:
            raise ValueError("final transmit poll metadata differs from acceptance")
        if packet_offset + packet_len > accepted_values[2]:
            raise ValueError("built packet exceeds accepted datagram")
        segment = accepted_values[3]
        if segment and ((packet_offset // segment) != ((packet_offset + packet_len - 1) // segment)):
            raise ValueError("built packet crosses GSO segment")
        if packet_time > poll_time or poll_time > accepted_time:
            raise ValueError("sender packet chronology is invalid")
        return poll_time, accepted_time

    sent: dict[tuple[int, int, int, int, int, int, int], tuple[int, list[int]]] = {}
    for event in sender:
        if event.get("event") != "stream_sent":
            continue
        time_ns, values = _packet(event, "stream_sent")
        key = (values[0], values[3], values[2], values[4], values[5], values[6], values[7])
        if key in sent:
            raise ValueError("duplicate sender stream range")
        sent[key] = (time_ns, values)

    datagrams: dict[int, tuple[int, int]] = {}
    auth: dict[tuple[int, int, int, int], tuple[int, list[int]]] = {}
    received_ranges: list[tuple[int, list[int], int]] = []
    for event in receiver:
        name = event.get("event")
        if name == "datagram_received":
            time_ns, values = _event(event, name)
            if len(values) != 2 or values[0] == 0 or values[1] == 0 or values[0] in datagrams:
                raise ValueError("duplicate or malformed received datagram")
            datagrams[values[0]] = (time_ns, values[1])
        elif name == "packet_authenticated":
            time_ns, values = _packet(event, name)
            key = (values[0], values[1], values[3], values[2])
            if key in auth:
                # Duplicate PN authentication is valid only when it arrived
                # under another UDP cookie; same-cookie duplication is corrupt.
                if auth[key][1][1] == values[1]:
                    raise ValueError("duplicate packet authentication")
            auth[key] = (time_ns, values)
        elif name == "stream_received":
            time_ns, values = _packet(event, name)
            received_ranges.append((time_ns, values, len(received_ranges)))

    candidates: list[dict[str, int]] = []
    intervals: list[tuple[int, int]] = []
    seen_rx: set[tuple[int, int, int, int, int, int, int]] = set()
    for rx_time, rx, _ in sorted(received_ranges, key=lambda item: item[0]):
        rx_conn, rx_cookie, pn, space, stream, offset, length, fin = rx
        identity = (rx_conn, rx_cookie, pn, space, stream, offset, length, fin)
        if identity in seen_rx:
            raise ValueError("duplicate receiver stream range")
        seen_rx.add(identity)
        if stream != op_stream or offset >= op_end or offset + length <= op_start:
            continue
        sender_key = (op_conn, space, pn, stream, offset, length, fin)
        if sender_key not in sent:
            raise ValueError("receiver stream range has no exact sender frame")
        built_time, built_values = built.get((op_conn, space, pn), (None, None))
        if built_values is None or built_values[1] != sent[sender_key][1][1]:
            raise ValueError("sender stream frame has no exact built packet")
        if built_values[1] != sent[sender_key][1][1] or built_values[3] != space:
            raise ValueError("sender stream packet mismatch")
        poll_time, accepted_time = tx_chain(built_time, built_values)
        datagram = datagrams.get(rx_cookie)
        packet_auth = auth.get((rx_conn, rx_cookie, space, pn))
        if datagram is None or packet_auth is None:
            raise ValueError("receiver packet identity is incomplete")
        datagram_time, datagram_bytes = datagram
        auth_time, auth_values = packet_auth
        if auth_values[4] + auth_values[5] > datagram_bytes:
            raise ValueError("authenticated packet exceeds received datagram")
        if auth_values[5] != built_values[5]:
            raise ValueError("sent and authenticated packet lengths differ")
        if not (op_time <= built_time <= poll_time <= datagram_time <= auth_time <= rx_time <= receiver_boundary_ns):
            raise ValueError("packet causality timestamps are invalid")
        left, right = max(op_start, offset), min(op_end, offset + length)
        if left < right:
            intervals.append((left, right))
            candidates.append({"packet_number": pn, "number_space": space, "stream": stream,
                               "operation_start": op_start, "operation_end": op_end,
                               "built_ns": built_time, "poll_ns": poll_time,
                               "accepted_ns": accepted_time, "received_ns": datagram_time,
                               "authenticated_ns": auth_time, "stream_received_ns": rx_time,
                               "receiver_boundary_ns": receiver_boundary_ns})
        if _interval_union(intervals) == (op_start, op_end):
            return candidates[-1]
    raise ValueError("operation byte range is incompletely covered")
