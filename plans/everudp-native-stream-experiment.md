# Bounded native reliable-stream experiment

Status: bounded experiment reviewed; not production integration approval.
Bead: `eversh-5fc.49`. Source inventory: `664ca54`.

## Question and prior evidence

Does a single owner of terminal readiness, UDP readiness and the pinned QUIC
protocol engine reduce the reliable-stream scheduling cost enough to justify
a separate production integration proposal?

Production LTO confirmation measured p50 ratios versus frozen zmosh UDP of
1.5479 at no loss and 1.5172 at 5% loss. Compiler improvements alone did not pass.
Production stream-flush, stream-receive and stream-pump studies kept the normal
noQ drivers; they did not establish parity. Native single-owner studies used
the reliable-datagram floor, not production reliable streams, and failed their
unchanged floor gates. None is evidence that this new combination will pass.

Existing attribution identifies driver/application scheduling boundaries, but
does not prove recoverable savings. This is a discriminating experiment, not
a promised speedup or a reason to repeat generic tracing.

## Scope and matched control

Implement a disposable `everudp-stream-floor` example with two explicit runtime
modes: ordinary noQ drivers and native single-owner noq-proto. Use the same
application state machine, record codec, buffers, authentication, stream layout,
terminal edge and public benchmark fixture in both modes. Do not compare a raw
native echo against production actors and attribute every difference to runtime.

Use one bidirectional control stream and one unidirectional stream per direction,
matching the production topology. Terminal data uses reliable STREAM frames
only; QUIC DATAGRAM is disabled. Use a distinct experimental ALPN, reject extra
streams, and preserve ordered framing and exact output identity. No remote PTY,
application replay or migration is claimed by this lower-bound echo experiment.
The common compiled PTY benchmark fixture still measures the local terminal edge.

Reuse pinned noQ/noq-proto 1.1.1 and existing Rustls/ring configuration, TLS 1.3,
SPKI pinning, ephemeral client identity and authenticated one-use invitation
binding. Do not create new crypto, weaken verification, permit 0-RTT payloads,
or time application traffic before admission completes. Both modes must use the
same configuration builder and admission contract. Hostile pin/token/key/stream
tests must pass before any timed comparison.

Start from the existing floor socket/reactor and control-stream admission seams,
but add native stream events, receive consumption/flow-control credit, partial
stream writes and wakeups explicitly. The existing datagram pump is not a stream
adapter. Keep changes in an opt-in experiment with production defaults unchanged;
do not make `floor-single-owner` silently select a new transport. Any shared
helper extraction must keep existing feature combinations and tests working.

Do not reuse `floor-single-owner` as the feature switch: it transitively enables
`reliable-datagram-spike`/`datagram-spike`, changing the transport profile and ACK
policy. Introduce an independent stream-experiment feature with no datagram or
diagnostic features in its closure. Provide a dedicated stream-floor profile and
ALPN; assert datagrams=false, exact stream limits and matching ACK/GSO/flow-control
configuration at runtime and in the effective-config receipt. Reusing the existing
datagram-floor configuration builder is forbidden. If either runtime cannot
express the same profile, record HOLD before measuring.

Preserve socket and stream errors, pending-buffer ownership, EOF and final-delivery
handling, bounded per-turn work, timer service and nonblocking sink backpressure.
Do not hold protocol locks across terminal I/O or busy-spin while blocked. Tests
must force socket/stream/sink Pending, partial writes, clean EOF, mid-record EOF,
large exact transfers and control progress under sustained traffic. No timing
results count before these behavioral checks pass.

Native stream handling must account explicitly for Opened/Available, Readable,
Writable, Finished and Stopped events in the pinned API. Consumed receive chunks
must be finalized so flow-control credit and any resulting transmit work progress.
Test credit advancement, stopped/reset propagation and bounded event retention;
an ignored stream event is not a valid idle result. Both runtime modes use the
same maximum application read/write chunk sizes and retain partial operations;
do not let an ordinary-mode write-all loop introduce a different application
batching policy. This adapter is new work, not functionality already supplied
by the datagram reactor.

## Measurement contract

Build both modes from one clean SHA with portable fat LTO, one codegen unit,
opt-level 3, panic=unwind, empty Rust flags and identical crypto/MTU/ACK/GSO
settings. Record effective configuration and binary/tool/lock hashes. Do not
combine runtime changes with tuning or dependency upgrades. If native and
ordinary APIs cannot express an identical setting, stop and report the mismatch.

Use the existing public send-to-exact-accepted-response timer, complete transcript
oracle and compiled fixture. No shell/Python work in the timed path, no prediction,
terminal parser, datagram shortcut, injected repaint or baseline replacement.
Freeze CPU/governor/affinity, MTU, trial gaps and both egress netem seeds before
running; make no builds, edits or heavy analysis during timing.

Compare native stream, ordinary stream and frozen zmosh UDP
`dfc8395b5edcd237bf82712fbde879c6e8be7dfa` contemporaneously. Two reversed
200-trial blocks per implementation in each 0% and 5% symmetric-loss cell,
100 ms trial gaps, disjoint seeds from previous studies. Freeze seeds and exact
commands in the bead before measurement. Existing floor cutoff is unchanged:
native/UDP p50 <=0.90 in each cell, packet ratio <=1.60 in every block/cell,
and zero transcript errors. Report native/ordinary distributions separately;
do not claim runtime causality if that comparison does not support it.

Repair or reuse harness components only after checking their actual contracts.
The existing datagram-specific build/qualify scripts must not label this result
as a datagram run or certify a changed implementation from stale metadata.
In particular, `bench-performance-block.sh` currently allowlists four candidate
names and enforces its two-candidate floor set; `qualify-floor.sh` hardcodes
`everudp-floor` in its sample and packet accounting. Add explicit
`everudp-stream-native` and `everudp-stream-ordinary` identities and a separate
stream comparison entry point with regression tests, preserving historical
datagram and production candidate contracts. Do not alias either new mode to
`everudp-floor` or silently omit the matched ordinary-stream control.
Capture all raw samples, resource data, measured-window qdisc counters, source
identity and checksums. Missing or corrupt evidence is INVALID, not PASS.

## Stop conditions and handoff

One frozen comparison after correctness gates; a performance miss seals
NOT-ADOPTED and closes this experiment. No post-hoc threshold/seed/control changes
or unbounded tuning loop. An interrupted run seals available identity and failure
evidence rather than disappearing. A configuration mismatch or missing protocol
capability is a recorded HOLD with a specific missing requirement.

A floor pass is necessary, not sufficient, for a separate reviewed integration
proposal. Production still requires persistent gateway associations, bounded
replay/ACK/GAP semantics, authenticated resume, route migration, PTY ownership,
observers/takeover, recovery probes and status behavior. None may be replaced by
this echo harness. Final production qualification stays at 1,200 observations
per implementation/cell against both frozen zmosh baselines, p50 point <=1.00,
p50 upper-95 <=1.10 and p95 upper-95 <=1.00, plus exact-SHA reliability, security,
resource and independent max-review gates. Release and fleet rollout remain out
of scope.

## Review outcome

Luna's initial review withheld approval because the existing native-floor feature
implicitly enables datagrams and changes ACK/buffer configuration. The revised
contract requires an independent feature/profile, effective-configuration parity,
explicit stream lifecycle and receive-credit tests, matched chunking, and separate
harness identities. On re-review the outcome was `APPROVE_BOUNDED_EXPERIMENT`,
with no remaining contract blocker. This is not the final independent product
review and does not authorize integration of a failed or unqualified floor.
