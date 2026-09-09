# everudp v4 single-layer reliable QUIC DATAGRAM spike

Status: closed negative at the mandatory stage-zero floor; production actor
integration prohibited by this contract | Last updated: 2026-09-07

The portable fat-LTO candidate `b91b75b` completed two reversed 200-trial
blocks per loss cell with zero transcript failures. Its floor medians were
406 us versus zmosh's 412 us at 0% loss (0.9854x), and 426.5 us versus
462.5 us at 5% loss (0.9222x). Both miss the frozen 0.90x cutoff.
The complete hashed receipt, raw samples, build provenance, resource records,
and impairment counters are preserved under
`docs/release-evidence/20260907-everudp-floor-b91b75b`.
The better loss-tail result (3,581 us versus 50,557 us p95) does not override
the median gate. The production epic and its qualification/review work remain
incomplete. These measurements close this implementation of V4; they do not
prove that all QUIC implementations are intrinsically slower.

This contract follows the immutable v3 failure at
`docs/release-evidence/20260906-everudp-quic-datagram-8761a70`. The v3
candidate delivered every byte exactly once, but sending both a speculative
DATAGRAM and an authoritative stream record immediately produced p50 ratios
of `1.805x` at 0% loss and `1.884x` at 5% loss against frozen zmosh custom
UDP. That architecture is closed.

V4 tests one different proposition: retain QUIC authentication, encryption,
congestion control, migration, and path validation, but give terminal records
one application-reliable DATAGRAM data plane rather than two simultaneous
delivery mechanisms. This is a bounded development spike, not permission to
ship, release, tag, merge, push, or deploy everudp.

## 1. Non-negotiable boundaries

- SSH remains bootstrap and recovery control only. No terminal payload may
  cross SSH or TCP after bootstrap.
- QUIC TLS 1.3, mutual certificate admission, pinned gateway SPKI, invitation
  binding, association identity, migration, and reconnect remain unchanged.
- There is no terminal parser, screen model, prediction, local echo,
  snapshot, semantic replay, scrollback protocol, WebRTC, relay, or 0-RTT
  terminal data.
- The everpty broker remains canonical session, child, lock, signal,
  metadata, and cleanup owner. The revocable direct-PTY lease remains the
  gateway hot path and must retain its existing recovery boundary.
- Sink commit remains the only delivery commit: input advances only after the
  complete operation reaches the PTY; output advances only after complete
  local stdout acceptance.
- Input is never silently dropped. Output overrun retains the existing
  future-only epoch/GAP behavior and never stalls the PTY.

The v3 `datagram-spike` feature and receipt remain intact. V4 uses a distinct
`reliable-datagram-spike` feature which includes the shared v3 DATAGRAM/noQ
plumbing. `datagram-spike` alone selects the closed v3 behavior; when the v4
feature is also enabled, explicit `cfg` precedence disables every v3 sender,
receiver, duplicate filter, and stream fallback before v4 behavior is enabled.
This keeps the workspace's required `--all-features` build valid without
confusing the two exact qualification feature sets.

## 2. Data-plane decision

Every ordered terminal operation is initially transmitted once as an
authenticated QUIC DATAGRAM. No immediate reliable-stream duplicate is sent.
The sender retains the encoded operation in a bounded immutable replay pool
until a sink-committed cumulative acknowledgement retires it. Loss is repaired
by application retransmission of that retained record on the same or a resumed
QUIC association. V4 retains immutable encoded records with the ACK snapshot
present when each operation was created; it does not rewrite retained bytes.
Only newly encoded data carries the newest piggyback ACK, while delayed or
forced ACK-only frames carry later acknowledgement progress. Records come from
a bounded owned-buffer pool and no hot-path `Bytes::copy_from_slice` is allowed.

Input and output keep independent epoch and absolute sequence spaces:

- Input kinds: bytes, resize, signal, and input-close.
- Output kinds: bytes, ownership, and exit.
- Large byte runs are split into complete records no larger than the fixed
  DATAGRAM payload cap; raw terminal bytes permit chunk boundaries without a
  terminal model.
- The reliable control stream carries client/server hello, GAP, takeover,
  kill, detach, link status, and terminal protocol errors. It carries no
  healthy-path terminal bytes.

The receiver delivers only `next_expected`. A bounded fixed-slot reorder
window retains valid future records. Duplicate, stale-epoch, outside-window,
wrong-direction, and malformed records change no delivery state.

## 3. Wire format

The v4 DATAGRAM is canonical and fixed-header:

`version | direction | kind | flags | epoch | sequence | ack_epoch | ack_base | ack_bits | payload_length | payload`

- V4 negotiates the distinct `everudp-rdgram/1` ALPN and uses wire-version
  byte `4`; a v1/v2/v3 peer therefore fails during negotiation or decoding
  before terminal traffic rather than confusing the two data planes.
- Version, direction, kind, and flags are one byte each.
- Epoch, sequence, acknowledgement epoch, acknowledgement base, and selective
  acknowledgement bits are unsigned 64-bit network-order integers.
- Payload length is an unsigned 16-bit network-order integer.
- `ack_base` is the next opposite-direction sequence durably accepted by its
  sink. Only records below it may leave the replay ring.
- `ack_bits` describes up to 64 valid future records currently held in the
  same live association's reorder window. It suppresses redundant same-link
  retransmission but never retires replay storage. It is forgotten on a new
  QUIC connection or process generation.
- Bit zero names sequence `ack_base`, bit one names `ack_base + 1`, through bit
  63. A set bit whose addition overflows or names an operation the sender has
  not sequenced is a protocol error. Reordered ACKs below the already applied
  cumulative base are nonfatal no-ops; a cumulative base beyond the sender's
  next sequence is a protocol error. A valid ACK is applied after complete
  frame validation even when that frame's data operation is a duplicate.
- An ACK-only frame has the ACK-only flag, no sequence-bearing operation, and
  an empty payload. Its kind, data epoch, and data sequence fields must all be
  zero. It is best effort and never induces another ACK by itself.
- Reserved flag bits, noncanonical empty/data combinations, oversized
  payloads, and arithmetic overflow are rejected before allocation.
- The receiver validates the entire datagram and opposite-direction ACK before
  mutating either direction. Authenticated malformed shape, conflicting
  duplicate, or ACK-ahead closes the link with a bounded protocol cause.
  Stale/duplicate/outside-window data is nonfatal and schedules the current ACK
  subject to the same-base rate limit. Epoch changes occur only through the
  authenticated hello/GAP protocol, never from an unsolicited data datagram.

The encoded cap is fixed at 1,070 bytes: a 46-byte header plus at most 1,024
payload bytes, always below the 1,200-byte safe initial MTU. Both hellos require
this capability. A path whose current noQ maximum falls below 1,070 bytes is a
temporary link failure; an already sequenced operation is never rechunked.
All buffers, replay slots, reorder slots, and per-poll work are fixed and
bounded before peer-controlled input is accepted.

## 4. Acknowledgement and retransmission

Newly encoded opposite-direction data piggybacks the newest sink-committed ACK. In
the interactive echo case, the output record acknowledges the input record;
there is no separate gateway ACK-before-output packet. The next input can
acknowledge output.

When no opposite-direction record becomes available, one cumulative ACK-only
frame is scheduled after a 1 ms delayed-ACK interval. Queue pressure, orderly
shutdown, ownership, exit, and reconnect handshake flush the current ACK
without waiting. Multiple commits coalesce into one ACK state; ACK-only loss
is harmless because it is repeated after a duplicate or retransmission.

Each unacknowledged sender slot records its latest transmit time and attempt
count outside the encoded replay payload. Initial send is immediate. Missing
records are retried by one bounded sweep using an RTO at least twice noQ's
current path RTT and never below path RTT plus the 1 ms ACK bound, with a 2 ms
absolute floor, deterministic per-association jitter, and exponential backoff
capped at 60 s. Before the first path sample, the locked 100 ms initial RTT is
used. Migration clears same-path timing and takes a fresh sample. Eight offers
is the global gateway wake budget, not a per-association budget; a round-robin
cursor gives the writer/PTY first service and then bounded observer shares.
DATAGRAM buffer pressure never blocks PTY draining or stdin.
QUIC remains responsible for congestion and path validation; everudp does not
bypass its send API or create a raw UDP side channel.

The sender uses selective bits only to skip records known present in the
current receiver reorder window. A SACK lease begins with the first valid SACK
for one cumulative-base generation and expires after at most one current-link
RTO without cumulative progress. Further ACKs with the same `ack_base` cannot
renew that lease. After expiry the cumulative head and other due records are
re-probed at their bounded backoff intervals until `ack_base` advances. Thus a
lost final ACK-only frame cannot suppress retransmission forever and an
authenticated peer cannot pin replay storage by repeating one SACK. Cumulative
`ack_base` is the sole retirement authority. On hard reconnect, both sides
discard selective state, exchange durable cumulative positions in the existing
hello, and immediately offer all retained unacknowledged records from
`ack_base` onward.

One serialized per-connection sender owns every v4 data and ACK-only offer.
It checks noQ's DATAGRAM buffer space and calls `send_datagram` without an
intervening await only when the complete frame fits, so no accepted offer can
evict an older unsent frame. It records an attempt only after `Ok(())`.
Backpressure retains the due record and arms a bounded non-busy retry wake; it
neither spins nor advances replay state.

## 5. Failure and lifecycle behavior

- Live migration keeps the same association and replay state.
- Hard connection loss remains temporary forever. Reconnect backoff and the
  authenticated SSH recovery probe remain unchanged.
- A client process restart cannot resume an in-memory association. It uses an
  authenticated replacement/takeover generation, reports any ambiguous input,
  and starts future-only with a visible GAP; no exact-replay claim is made
  without a separately reviewed persistent client-state design. A gateway
  crash likewise never guesses whether unacknowledged input reached the PTY;
  it reports the ambiguous count and starts a new input generation exactly as
  the existing contract requires.
- Output replay overrun resets the output epoch, stops v4 data sends, and
  explicitly closes the current QUIC connection with the existing temporary
  output-resume-required cause. The gateway drains/discards PTY output until
  the next completed resume handshake. The client receives exactly one GAP
  notice and only future-epoch bytes.
- A full input replay queue stops stdin polling until cumulative ACK progress
  frees capacity. Retransmission metadata cannot enlarge that queue.
- Each observer has independent acknowledgement/retry/reorder state. A slow
  or dead observer is gapped or retired independently and cannot stall the
  writer or PTY.
- Detach carries an input epoch and final sequence watermark on the reliable
  control stream. The gateway applies it only after the PTY sink's cumulative
  input position reaches that watermark. Kill, forced takeover, and local
  cancellation may cut the barrier short only with an explicit ambiguous-input
  count; control arrival alone never silently abandons earlier DATAGRAM input.
- Exit and ownership are ordered output operations. After committing either,
  the client sends a terminal-only reliable `ACK_CHECKPOINT` with direction,
  epoch, and cumulative base. The gateway applies it and returns a reliable
  `CHECKPOINT_APPLIED`; normal client exit/ownership release waits for that
  application-level receipt. This checkpoint does not carry terminal bytes or
  replace healthy-path DATAGRAM ACKs.
- A named 60-second terminal-drain deadline starts when the PTY exits. The
  gateway retires an association after its checkpoint, immediately retires a
  protocol-failed observer, and forcibly retires any remaining disconnected or
  slow association at the deadline. No observer can keep a dead PTY gateway
  alive indefinitely.

## 6. Mandatory stage-zero QUIC floor

The independent review established that v3 already put its immediate
DATAGRAM ahead of the stream duplicate, so deleting the later duplicate alone
cannot credibly remove the measured 344/397 microsecond deficit. Before any
production actor integration, build an authenticated floor containing only:

- the locked mutual-TLS/pinned-SPKI noQ connection and distinct V4 ALPN;
- one sequenced client DATAGRAM, one gateway echo DATAGRAM, duplicate
  suppression, and a 2 ms minimum retry sufficient to survive finite loss;
- the frozen compiled local `pty-bench` public-send/acceptance boundary, with
  no SSH, PTY broker, remote PTY, replay pool, or application ACK in the timed
  path. Setup and authentication finish before the warm-up marker.

Run two 200-trial reversed blocks (`floor,zmosh-udp` and
`zmosh-udp,floor`) independently in both 0% and 5% symmetric-loss cells, using
the frozen zmosh custom-UDP SHA, CPU/governor controls, 100 ms gaps, disjoint
seeds, and zero transcript failures. This deliberately gives noQ every
advantage: if either cell's floor p50 exceeds `0.90x` zmosh, hash-seal the miss
and close V4 without wiring reliability into everudp. If the floor passes,
component timestamps must account for at least the prior 344/397 microsecond
deficit before actor work proceeds; otherwise V4 scope must first add a fused
endpoint/application receive path and allocation removal or select another
QUIC core.

## 7. Implementation shape

1. Add pure `reliable_datagram` wire/state modules: canonical codec, replay
   transmit metadata, receive reorder window, ACK reducer, RTO calculator,
   and bounded work scheduler. Start with exhaustive table/property tests.
2. Run and seal the mandatory stage-zero floor. Do not start actor integration
   unless it passes the preceding cutoff.
3. Add `reliable-datagram-spike` as an extension of `datagram-spike`; keep
   v1/v2 default behavior and the closed v3-only behavior unchanged. Freeze a
   locked experimental transport profile with the distinct ALPN, mandatory
   mode/version and 1,070-byte capability echoed in both hellos, QUIC
   DATAGRAMs enabled, and zero incoming unidirectional streams.
4. Integrate the client input/output sinks. Preserve raw-mode restoration,
   signal ordering, local output backpressure, reconnect status, and exact
   delivery gates.
5. Integrate the gateway and direct PTY lease. Piggyback committed input ACK
   on output before any ACK-only timer can fire; preserve observer fairness,
   takeover, GAP, and terminal-exit handling.
6. Add timer and reconnect integration with a global fixed per-poll work
   budget and round-robin association cursor. Add the detach barrier,
   ACK-checkpoint exchange, and terminal-drain deadline.
   Packet tracing must show no immediate stream duplicate and no ACK-only
   feedback loop.
7. Build the exact feature candidate with
   `EVERUDP_CARGO_FEATURES=cli,reliable-datagram-spike`; seal the feature list,
   source/tree, binaries, tools, and frozen zmosh identities.

## 8. Required verification

Pure/model tests cover every truncation, wrong version/direction/kind/flag,
stale and future epoch, duplicate, reorder permutation inside and outside the
window, ACK regression/ahead, selective-bit mapping, ACK loss, retransmission
backoff, sequence overflow, queue exhaustion, and reconnect reset. State-model
tests assert:

- a sink sees each ordered operation exactly once;
- replay retirement never exceeds sink-committed `ack_base`;
- selective acknowledgement alone never destroys recoverable data;
- a lost final cumulative ACK after a prior SACK expires the SACK lease and
  causes repeated head probes until convergence;
- input ACK never precedes a complete PTY write;
- output ACK never precedes complete stdout acceptance;
- loss of any finite set of data or ACK frames eventually converges exactly
  once only while the retained epoch and both process generations survive
  within queue bounds;
- output overrun converges to exactly one GAP plus future bytes, while gateway
  replacement converges to explicit ambiguous-input reporting rather than an
  exact-replay claim;
- memory and work remain within frozen bounds under a hostile peer.

Process/network gates inject independent data and ACK loss, 0/1/5/10/25%
symmetric loss, jitter, duplication, reorder, MTU reduction, IPv4/IPv6,
address/interface change, sleep/wake, 5- and 30-minute total loss, gateway
death, client restart, takeover, slow observers, output overrun, and final
exit. Existing everpty/everssh/everudp tests and both fuzz boundaries remain
green. An eight-hostile-observer gate proves writer/PTY service and terminal
exit are not starved. V3-only, V4-only, and `--all-features` traces prove exact
feature precedence, zero v4 terminal streams, and QUIC/UDP-only payloads.

Before expensive qualification, two reversed development blocks must provide
at least 200 observations per implementation in each 0% and 5% cell with zero
transcript failures. The same frozen zmosh sources, raw-PTY fixture, 100 ms
trial gap, public-send timer boundary, qdisc accounting, and disjoint seeds
apply. V4 proceeds only if:

- everudp p50 is at most `0.90x` frozen zmosh custom UDP in both cells; and
- steady-state one-byte packet count is no more than `1.60x` zmosh custom UDP.

Packet count is the summed client/server egress qdisc packet delta, including
retransmissions, QUIC ACKs, keepalives, and netem-dropped attempts, divided by
the exact accepted trial count. It is computed per block and loss cell; pooled
results cannot hide a failing cell. Every receipt also records allocations,
user/system CPU, voluntary/involuntary context switches, and component
timestamps at terminal read, noQ offer, UDP send/receive, sink acceptance, and
public output acceptance.

A miss is hash-sealed and closes V4 before productionization. A pass permits
an independent security/reliability review and a separate hardening bead; it
does not amend or erase any earlier failure receipt.
