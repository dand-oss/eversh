#!/usr/bin/env python3
"""Validate and account for packet counters from a single root netem qdisc.

The network qualification harness records ``tc -s qdisc show`` before and
after each timed window.  This module deliberately selects only the qdisc
whose descriptor contains the ``root`` marker.  A child qdisc may have its
own counters, but summing it with its parent would count the same packet
twice.  The selected root must be a ``netem`` qdisc and must have exactly one
well-formed ``Sent ... pkt (dropped ..., ...)`` statistics line.

Public API (standard library only):

``parse_root_netem(text)``
    Return :class:`QdiscCounters` for one ``tc`` snapshot, or raise
    :class:`PacketAccountingError` when the snapshot is missing, ambiguous,
    malformed, or names a non-netem root.

``derive_attempt_delta(before, after)``
    Validate qdisc identity and monotonic counters and return a
    :class:`AttemptDelta`.  An attempt is one packet counted by ``Sent`` or
    by netem's ``dropped`` counter; both deltas are retained separately.

``account_packet_attempts(before_client, after_client, before_server,
after_server)``
    Parse both directions and return :class:`PacketAccounting`.  The total
    attempt count is required to be non-zero so a packet ratio cannot be
    reported with a zero denominator.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping


class PacketAccountingError(ValueError):
    """Raised when a qdisc snapshot cannot support authoritative accounting."""


@dataclass(frozen=True)
class QdiscCounters:
    """Counters and stable identity for the selected root qdisc.

    ``identity`` includes the qdisc kind, handle, root marker, and all
    configuration tokens except the kernel's volatile ``refcnt`` value.  It
    therefore detects a qdisc replacement while allowing harmless reference
    count changes between the two window boundaries.
    """

    kind: str
    handle: str
    identity: tuple[str, ...]
    sent_bytes: int
    sent_packets: int
    dropped_packets: int

    @property
    def attempts(self) -> int:
        """Return packets sent plus packets dropped by netem."""

        return self.sent_packets + self.dropped_packets


@dataclass(frozen=True)
class AttemptDelta:
    """Monotonic sent/drop deltas for one direction."""

    sent_packets: int
    dropped_packets: int

    @property
    def attempts(self) -> int:
        """Return the number of packet attempts in the measured window."""

        return self.sent_packets + self.dropped_packets


@dataclass(frozen=True)
class PacketAccounting:
    """Windowed packet attempts for client and server egress directions."""

    client: AttemptDelta
    server: AttemptDelta

    @property
    def total_sent_packets(self) -> int:
        return self.client.sent_packets + self.server.sent_packets

    @property
    def total_dropped_packets(self) -> int:
        return self.client.dropped_packets + self.server.dropped_packets

    @property
    def total_attempts(self) -> int:
        """Return the non-zero denominator used for packet ratios."""

        return self.client.attempts + self.server.attempts


_QDISC_RE = re.compile(
    r"^\s*qdisc\s+(?P<kind>\S+)\s+(?P<handle>\S+)(?:\s+(?P<attrs>.*?))?\s*$"
)
_SENT_RE = re.compile(
    r"\bSent\s+(?P<bytes>\d+)\s+bytes\s+"
    r"(?P<packets>\d+)\s+(?:pkt|pkts|packet|packets)\b"
)
_DROPPED_RE = re.compile(r"\bdropped\s+(?P<packets>\d+)\b")


@dataclass(frozen=True)
class _QdiscRecord:
    kind: str
    handle: str
    attrs: tuple[str, ...]
    body: tuple[str, ...]

    @property
    def is_root(self) -> bool:
        return "root" in self.attrs

    @property
    def identity(self) -> tuple[str, ...]:
        # ``refcnt`` changes as interfaces/users reference a qdisc.  It is
        # not an identity change; all other header tokens identify the
        # selected qdisc and its configured netem instance.
        stable_attrs: list[str] = []
        index = 0
        while index < len(self.attrs):
            token = self.attrs[index]
            if token == "refcnt" and index + 1 < len(self.attrs):
                index += 2
                continue
            stable_attrs.append(token)
            index += 1
        return (self.kind, self.handle, *stable_attrs)


def _records(text: str) -> list[_QdiscRecord]:
    if not isinstance(text, str):
        raise TypeError("qdisc snapshot must be text")

    records: list[_QdiscRecord] = []
    current: tuple[str, str, tuple[str, ...], list[str]] | None = None
    for line in text.splitlines():
        if line.lstrip().startswith("qdisc"):
            match = _QDISC_RE.match(line)
            if match is None:
                raise PacketAccountingError("malformed qdisc descriptor")
            if current is not None:
                kind, handle, attrs, body = current
                records.append(_QdiscRecord(kind, handle, attrs, tuple(body)))
            attrs = tuple((match.group("attrs") or "").split())
            current = (match.group("kind"), match.group("handle"), attrs, [])
            continue
        if current is not None:
            current[3].append(line)

    if current is not None:
        kind, handle, attrs, body = current
        records.append(_QdiscRecord(kind, handle, attrs, tuple(body)))
    return records


def parse_root_netem(text: str) -> QdiscCounters:
    """Parse exactly one root ``netem`` qdisc from ``tc -s`` output.

    Child qdiscs are intentionally ignored after root selection.  This is
    what prevents hierarchy double counting when a root netem has a child
    queueing discipline with another ``Sent`` line.
    """

    records = _records(text)
    if not records:
        raise PacketAccountingError("missing qdisc descriptor")

    roots = [record for record in records if record.is_root]
    if not roots:
        raise PacketAccountingError("missing root qdisc")
    if len(roots) != 1:
        raise PacketAccountingError("ambiguous root qdisc")
    root = roots[0]
    if root.kind != "netem":
        raise PacketAccountingError(f"wrong root qdisc: expected netem, got {root.kind}")

    sent_lines = [line for line in root.body if re.search(r"\bSent\b", line)]
    if len(sent_lines) != 1:
        raise PacketAccountingError("missing or ambiguous root qdisc statistics")
    sent_match = _SENT_RE.search(sent_lines[0])
    dropped_match = _DROPPED_RE.search(sent_lines[0])
    if sent_match is None or dropped_match is None:
        raise PacketAccountingError("malformed root qdisc statistics")

    sent_bytes = int(sent_match.group("bytes"))
    sent_packets = int(sent_match.group("packets"))
    dropped_packets = int(dropped_match.group("packets"))
    if sent_bytes < 0 or sent_packets < 0 or dropped_packets < 0:
        raise PacketAccountingError("negative qdisc counter")
    return QdiscCounters(
        kind=root.kind,
        handle=root.handle,
        identity=root.identity,
        sent_bytes=sent_bytes,
        sent_packets=sent_packets,
        dropped_packets=dropped_packets,
    )


def derive_attempt_delta(before: QdiscCounters, after: QdiscCounters) -> AttemptDelta:
    """Validate two snapshots and derive sent-plus-drop packet attempts."""

    if before.identity != after.identity:
        raise PacketAccountingError("qdisc identity changed during measured window")
    if after.sent_bytes < before.sent_bytes:
        raise PacketAccountingError("sent byte counter regressed")
    if after.sent_packets < before.sent_packets:
        raise PacketAccountingError("sent packet counter regressed")
    if after.dropped_packets < before.dropped_packets:
        raise PacketAccountingError("dropped packet counter regressed")
    return AttemptDelta(
        sent_packets=after.sent_packets - before.sent_packets,
        dropped_packets=after.dropped_packets - before.dropped_packets,
    )


def account_packet_attempts(
    before_client: str,
    after_client: str,
    before_server: str,
    after_server: str,
) -> PacketAccounting:
    """Account sent-plus-dropped attempts for both egress directions.

    The four arguments are raw ``tc -s qdisc show`` snapshots for client and
    server, captured before and after the same timed window.  A zero total
    attempt count is rejected because it cannot provide a meaningful packet
    ratio denominator.
    """

    client = derive_attempt_delta(
        parse_root_netem(before_client), parse_root_netem(after_client)
    )
    server = derive_attempt_delta(
        parse_root_netem(before_server), parse_root_netem(after_server)
    )
    result = PacketAccounting(client=client, server=server)
    if result.total_attempts == 0:
        raise PacketAccountingError("zero packet-attempt denominator")
    return result


def account_directions(
    before: Mapping[str, str], after: Mapping[str, str]
) -> PacketAccounting:
    """Mapping-friendly wrapper using ``client`` and ``server`` direction keys."""

    try:
        return account_packet_attempts(
            before["client"], after["client"], before["server"], after["server"]
        )
    except KeyError as error:
        raise PacketAccountingError(f"missing qdisc direction: {error.args[0]}") from error
