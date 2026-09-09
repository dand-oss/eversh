# everudp v3 QUIC DATAGRAM fast-lane experiment

Status: closed negative experiment at `8761a70`; not a production or release contract | Last updated: 2026-09-06

This contract follows the negative v2 direct-PTY result sealed at
`docs/release-evidence/20260906-everudp-direct-lease-dfb39bb`. It authorizes one
bounded attempt to remove reliable-stream delivery latency without abandoning QUIC,
TLS authentication, exact delivery, or resume. Nothing in this document converts the
existing v1 or v2 failure receipts into a pass.

## 1. Decision boundary

The experiment adds a speculative QUIC DATAGRAM copy of eligible terminal records.
The existing ordered QUIC streams remain the authoritative delivery and replay path.
This is not a raw UDP side channel: both copies use the same mutually authenticated
TLS 1.3 QUIC connection, connection keys, congestion controller, path validation, and
migration state.

Still forbidden are terminal parsing, prediction, local echo, virtual screens,
snapshots, semantic replay, WebRTC, relays, 0-RTT terminal data, and SSH/TCP terminal
payload. The everpty broker remains canonical session and child owner. The revocable
direct-PTY lease remains an experimental latency primitive and does not become a
production default unless this contract passes.

## 2. Delivery model

For an eligible small `Input` or `Output` record, the sender:

1. assigns the same epoch and absolute sequence used by the authoritative stream;
2. retains the stream record in the existing bounded replay queue;
3. sends one best-effort DATAGRAM copy; and
4. sends the authoritative stream copy without waiting for or retrying the DATAGRAM.

The receiver feeds both arrivals into one sequence gate. Whichever valid copy arrives
first may be delivered to the sink. The sink commit advances the receiver watermark
exactly once; the later copy is a duplicate and is consumed without a second PTY or
stdout write. A DATAGRAM send never advances a delivery, replay, or acknowledgement
watermark. If it is lost, reordered, duplicated, congestion-dropped, or unsupported,
the reliable stream produces the same behavior as v2.

Acknowledgement remains application-level and cumulative: input only after the full
ordered operation reaches the PTY, output only after local stdout accepts every byte.
Reconnect and resume use only retained stream records and committed watermarks. No
DATAGRAM is replayed across a connection generation.

## 3. Wire and bounds

The experimental DATAGRAM has a fixed header:

`version | direction | kind | epoch | sequence | payload_length | payload`

- Version, direction, and kind are one byte each.
- Epoch and sequence are unsigned 64-bit network-order integers.
- Payload length is an unsigned 16-bit network-order integer.
- Only `Input` and `Output` kinds are accepted.
- The total encoded record must fit noQ's current `max_datagram_size` and an everudp
  cap of 1,024 payload bytes. Larger records are stream-only.
- Resize, signal, input-close, detach, kill, ownership, GAP, exit, link status,
  handshakes, and all acknowledgements remain stream-only.
- Datagram receive and send buffers are bounded by the existing per-association limits;
  there is no attacker-sized allocation or unbounded retry queue.

A datagram with a wrong version, direction, kind, epoch, length, association state, or
sequence window is discarded. It does not close a healthy connection unless noQ itself
reports a terminal protocol failure. This prevents an unreliable hint from weakening
the authoritative stream.

## 4. Ordering races

The delivery gate has four outcomes:

- `next`: stage and commit the complete record once;
- `duplicate`: discard it and emit/repeat only the cumulative acknowledgement required
  by the authoritative protocol;
- `future`: retain no speculative payload; wait for the missing authoritative sequence;
- `stale epoch` or malformed: discard without changing state.

Only the exact next sequence can take the fast lane. A future DATAGRAM is not buffered,
because buffering would duplicate replay state and permit reordering pressure. The
stream later supplies it in order. Stream-first and DATAGRAM-first arrivals therefore
converge on identical state.

## 5. Congestion and fallback

The fast copy is optional on every record. `UnsupportedByPeer`, `Disabled`, `TooLarge`,
or local DATAGRAM-buffer pressure silently selects the already queued stream copy.
Congestion never blocks stdin or PTY draining merely to preserve a speculative copy.
At most one DATAGRAM copy is attempted per eligible authoritative record, with no
application retransmission.

The sender queues the DATAGRAM before the stream copy so it can occupy the earliest
packet, but it must not delay the stream to manufacture benchmark wins. The benchmark
records packet counts and qdisc drops so doubled traffic and hidden timers remain
visible. A production decision may lower the 1,024-byte cap if amplification or
congestion evidence requires it.

## 6. Security and reliability gates

Unit/model tests cover round trips, truncation at every byte, invalid lengths, wrong
direction/kind/version/epoch, stale/duplicate/future sequences, stream-first and
DATAGRAM-first races, and datagram-disabled peers. Integration gates force DATAGRAM
loss, duplication, reorder, and stream loss independently; all must produce exact-once
ordered sink bytes with the existing replay, reconnect, output-GAP, input-backpressure,
observer, and lease-revocation behavior.

The hostile gate verifies bounded CPU/memory under malformed and future DATAGRAMs.
Packet/process tracing must still prove that terminal data after bootstrap uses only
the authenticated QUIC UDP socket and never SSH/TCP. Existing v1/v2 tests remain green.

## 7. Performance decision gate

Use the frozen compiled raw-PTY fixture, public-send to exact-local-acceptance timing,
CPU controls, and zmosh sources from v2. Development seeds must be disjoint from all
prior tuning and qualification seeds. Run at least 200 observations per implementation
in symmetric zero and five percent loss cells with reversed candidate order and zero
transcript failures.

The exact build sets `EVERUDP_CARGO_FEATURES=cli,datagram-spike`, and that
feature list is part of the sealed build provenance. A default `cli` build is
not evidence for this experiment.

Both cells must show everudp p50 no greater than `0.90x` frozen custom-zmosh UDP before
any productionization. A miss is hash-sealed and closes this architecture. A pass only
authorizes a separate production-hardening bead; it does not authorize M6 acceptance,
release, versioning, tagging, merging, pushing, or fleet rollout.

## 8. Closed result

The exact candidate `8761a7059add297ad19218ea63f4fa3998c7d6c8` passed all
200 exact-transcript observations per implementation per cell, but failed the
latency threshold in both cells:

- 0% symmetric loss: everudp 686 us versus zmosh UDP 380 us, or `1.805x`;
- 5% symmetric loss: everudp 761 us versus zmosh UDP 404 us, or `1.884x`.

The immutable negative receipt is
`docs/release-evidence/20260906-everudp-quic-datagram-8761a70`. This
architecture is closed. Its immediate speculative DATAGRAM and immediate
authoritative stream copy nearly doubled steady-state packet work and did not
remove noQ's remaining receive/application scheduling cost. Any hedged send,
application-ACK piggybacking, or single-reliability-layer design requires a
new contract and bead.
