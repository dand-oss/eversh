# Post-V4 architecture investigation

Status: diagnostic investigation reviewed; runtime replacement not approved | 2026-09-07

User authorization: investigate a new architecture with unchanged performance
thresholds, using Luna for delegated work. Bead: `eversh-5fc.18`.
This does not reopen V4, authorize release, or treat a floor as production.

## Evidence and uncertainty

The sealed V4 candidate `b91b75b` measured floor/zmosh UDP medians of
406/412 us at 0% loss and 426.5/462.5 us at 5% loss. Ratios 0.9854 and
0.9222 both fail the mandatory 0.90 ceiling. Zero transcript failures and
better loss tails do not override that failure. The floor has no remote PTY;
passing a future floor would still leave real product integration unproven.

The floor already used endpoint-side receive callbacks, pooled packet buffers,
portable fat LTO and immediate send flushing. Merely proposing those again
does not constitute a new architecture. `4b4fc52` removed an unsafe endpoint
flush that swallowed socket errors; the immutable benchmark predates that fix.

Source inspection shows a client future polling terminal readiness plus two
spawned noQ drivers (endpoint and connection), shared connection locking, and
notification between inline output acceptance and the awaiting client. Their
individual time costs are NOT measured. Endpoint receive handling copies each
UDP slice into owned `BytesMut` (`vendor/noq/src/endpoint.rs:970`); pooling
application frames does not remove this lower-layer allocation.
The 50 us buffer-pressure sleep in `send_retained` is conditional; it must not
be blamed for healthy-path latency without evidence that the branch executes.

Relevant sources: `crates/everudp/examples/everudp-floor.rs`,
`vendor/noq/src/connection.rs`, `vendor/noq/src/endpoint.rs`, and installed
`noq-proto` 1.1.1 endpoint/connection public APIs. No dependency upgrade is
part of this proposal.

## Leading hypothesis: one owner for transport and terminal readiness

Investigate a disposable single-owner event pump using the existing pinned
noq-proto engine. One owner handles UDP readiness, protocol events/timeouts,
terminal readiness, receive validation and sink progress without passing every
keystroke through separately scheduled endpoint, connection and application
tasks. This is a scheduling architecture hypothesis, not a measured speedup.

Keep the protocol implementation responsible for TLS, packet protection,
congestion control, loss/path validation and timers. Never substitute custom
crypto, raw unauthenticated UDP, prediction, or terminal parsing. Preserve
mutual admission, pinned SPKI, one-use invitations and no 0-RTT payloads.

The event pump must retain partial socket/sink writes, propagate I/O errors,
respect protocol transmit backpressure, and use fixed per-poll work budgets.
It must service timers and control traffic under saturated input/output and
must not busy-spin. Direct PTY ownership remains revocable and broker-owned.
Migrating application lifetime/resume into this owner is a later integration
question, not a shortcut around existing delivery and outage contracts.

Feasibility gate: noq-proto is protocol state, not a drop-in runtime. Map the
existing noQ socket, configuration/admission, endpoint routing and migration
integration before selecting a combined-driver refactor or a direct proto
adapter. Reuse existing TLS configuration and crypto integrations, never
reimplement them. This is not presumed to be a small or low-risk change.
Do not hold a shared QUIC-state lock over sink I/O; retain partial writes and
resume from sink readiness. The floor's current EAGAIN failure is not a valid
production backpressure contract.

## Discriminating sequence

1. Add bounded diagnostic tracing to the current safe floor, before replacing
   its runtime. Record local terminal read, protocol offer, UDP send/receive,
   sink acceptance and public benchmark acceptance, plus task wakeups,
   allocations after warmup, CPU and context switches. Use fixed-size trace
   storage; overflow invalidates attribution. Never log terminal contents or
   authentication secrets. Include process/thread/sequence identity. Cross-host
   subtraction requires measured clock alignment; otherwise report only local
   intervals. Trace overhead is measured in paired runs, not assumed free.
   Count callback calls, pending replies, blocked sends and UDP receive copies;
   measure callback-to-driver-to-transmit delay. Restoring immediate endpoint
   flush alone is excluded as a new architecture: sealed b91b75b already did it.
2. Establish whether scheduling/locking/copying costs plausibly provide the
   missing margin. Do not sum independent percentile values as though they
   were one request. Account per trial, then derive distributions. If attribution
   is incomplete, stop and report UNKNOWN rather than selecting a core by taste.
3. Only after reviewing that evidence, build a disposable single-owner floor
   with the same authentication and public timer/oracle boundaries. Keep the
   current safe floor as an architectural control and frozen zmosh UDP as the
   acceptance baseline. Hold compiler, crypto, MTU, batching and seeds constant.
   Do not combine a runtime rewrite with a transport/dependency upgrade.
4. Freeze the exact candidate and run the mandatory floor comparisons. A miss
   seals a negative result and closes this experiment before actor integration.
   A pass permits a separate reviewed integration proposal, not release.

## Evidence repairs required before any new PASS authority

- Old `qualify-floor.sh` only gates p50 and lacks allocation/component evidence.
  Do not reuse its PASS flag as authorization. Preserve historical receipts.
- Packet accounting must identify the specific egress qdisc and count sent plus
  netem-dropped attempts without summing parent/child counters twice. Use measured
  window boundaries excluding setup/warmup, and validate with deterministic
  no-loss and forced-drop fixtures. Store raw counters and the derived deltas.
- Enforce packet ratio <=1.60 per block and loss cell, not only a pooled total.
  Missing, regressing, zero-denominator or malformed counters invalidate the run.
- Distinguish FAIL (complete evidence, failed gate), INVALID (missing/corrupt
  evidence), and diagnostic runs. None authorizes production integration.
- Record source/tree, clean state, binary/tool hashes, feature set, CPU/governor,
  affinity, seeds, timer boundaries, raw samples and resource/trace evidence.
  Interrupted runs still seal their available identity and non-PASS receipt.

## Unchanged gates

Floor: two reversed 200-trial blocks per 0% and 5% symmetric-loss cell,
100 ms trial gaps, disjoint preregistered seeds, exact byte transcript,
zero errors, p50 ratio <=0.90 against frozen zmosh UDP
`dfc8395b5edcd237bf82712fbde879c6e8be7dfa`, and packet ceiling above.
Diagnostic tracing is not silently included/excluded from timed qualification;
freeze and report the build distinction and paired overhead measurements.

Production remains 1,200 observations per implementation/cell against both
that UDP baseline and zmosh QUIC
`21db4a4de6040b254531f2131b6f1c0cd146a7a1`: p50 point <=1.00,
p50 upper-95 <=1.10, p95 upper-95 <=1.00. All existing replay, outage,
security, resource, observer, gateway recovery and terminal-application gates
remain mandatory at the eventual exact candidate, followed by independent
review. Prior non-performance results cannot certify a rewritten runtime.

No lower thresholds, baseline substitution, prediction, relay, or SSH data
plane is introduced. Versioning, merge, push and fleet rollout remain excluded.

## Investigation review

Luna's read-only review at `4b4fc52` confirmed the driver split, explicit
receive copy and callback-under-lock sink behavior. The proposal incorporates
its client-future terminology, diagnostic counters, feasibility gate and
partial-sink-write requirements. Its suggested safe immediate-flush alternative
was rejected as new architecture because the failed b91b75b already measured
that scheduling optimization. Review approves diagnostic-first investigation,
not the unimplemented event pump or production acceptance.

### Decision checkpoint at `6dd6149`

The subsequent read-only pump review returned HOLD: the sealed measurements do
not yet identify a nonoverlapping, plausibly recoverable latency budget for a
single-owner rewrite. The historical V4 deficits are 35.2 us at no loss and
10.25 us at 5% loss; these are not measurements of the current safe floor.
Later paired blocks vary substantially, so those historical deficits must not
be treated as a precise current optimization target.

The input scheduling archive
`docs/release-evidence/20260907-everudp-input-schedule-b35097b` observes about
9–10 us more scheduled-to-read-entry time in the floor than zmosh in both
orders. That is descriptive, not proof of recoverable savings. Protocol and
sender entry/exit CPU measurements already exist in
`docs/release-evidence/20260907-everudp-protocol-cpu-30f2093`; adding the same
generic markers again would not close the attribution gap.

Current source inspection also narrows the architecture hypothesis:
`Endpoint` invokes `process_event_inline`, which applies the connection event,
forwards application events and runs the datagram callback synchronously under
the connection lock. The normal inline receive path therefore does not incur
the queued endpoint-to-connection handoff that a replacement might otherwise
claim to eliminate. Its receive-copy-to-callback span includes protocol work,
not just scheduling. Transmission still uses the connection driver so socket
errors remain observable.

The next decision must reconcile existing per-trial and synchronous-call
evidence before requesting more instrumentation. Any additional measurement
must name the missing boundary and a finite stop condition. Do not add stage
medians, treat whole-trace CPU samples as per-keystroke costs, or require proof
of an optimization before a bounded experiment can test it. HOLD does not
authorize a runtime rewrite and does not close production qualification.

### Reconciliation at `115c3da`: bounded experiment approved

After examining the existing markers and call path, Luna revised the decision
to APPROVE_EXPERIMENT, not production integration. The prior request for generic
driver entry/exit diagnostics is withdrawn: those measurements already exist.
The concrete remaining scheduling target is the post-callback response queue
to connection-driver service, plus input dispatch; normal inline receive does
not supply a queued handoff to remove. Existing per-trial scheduling spans can
identify the former without assigning aggregate protocol/sender CPU to packets.

Savings remain uncertain. The disposable single-owner floor is the bounded
discriminating experiment, not a claim that its architecture will pass. It must
preserve pinned protocol/configuration, authentication, socket error handling,
pending-buffer ownership, timers and bounded fairness. Keep the safe floor as
control and use the unchanged reversed-block floor gates above. A miss seals
NOT-ADOPTED and prohibits integration; a pass still requires a separate reviewed
production proposal. No additional generic tracing campaign is a prerequisite.
