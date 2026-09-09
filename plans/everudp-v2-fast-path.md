# everudp v2 direct-PTY fast-path contract

Status: closed after negative development proof | Last updated: 2026-09-06

This contract responds to the exact v1 M6 result at candidate
`9989564cff6ef9f1358aaf38516727ee76b6821d`. That candidate passed the functional,
security, replay, outage, migration, application, and resource gates, but it is not a
release: its loss-free median was 768 microseconds against the frozen custom-zmosh
median of 414 microseconds. The immutable receipt remains under
`docs/release-evidence/20260906-m6-9989564cff6e`.

The measured deficit is structural. The v1 path crosses the gateway Tokio reactor,
an encoded Unix-stream writer connection, the synchronous everpty broker poll loop,
and the same boundary again on output. The broker already writes newly received input
to the PTY in the same poll iteration. Small allocation or timer changes cannot
credibly recover the required 320--354 microseconds of median latency.

## 1. Unchanged invariants

- `everpty` remains the canonical owner of the session lock, child, PTY lifetime,
  metadata, signals, exit status, and cleanup.
- The everudp gateway remains a separate crash-isolated process. A gateway crash must
  not kill the PTY session.
- Terminal bytes use reliable ordered QUIC streams over UDP. There are no terminal
  datagrams, parsers, prediction, local echo, virtual screens, snapshots, semantic
  replay, relays, WebRTC, or SSH/TCP payload paths.
- Healthy delivery is exactly once and ordered. Input is acknowledged only after the
  complete operation reaches the PTY. Output is acknowledged only after the local sink
  accepts it. Existing bounded replay, backpressure, epoch, GAP, reconnect, invitation,
  pinning, and authorization contracts remain in force.
- The existing framed broker writer path remains the compatibility and recovery path.
  Failure to obtain a fast lease must never make an otherwise valid session unusable.

## 2. Revocable direct-PTY lease

After the ordinary same-UID writer handshake, an eligible gateway may request a
versioned fast-path lease. The request binds a random gateway generation to the
requesting process ID and Linux process start time. The broker checks `SO_PEERCRED`,
confirms that the request comes from the current exclusive writer, opens a pidfd for the
identified process, and allocates a monotonically increasing, nonzero lease ID.

Grant is a quiescent handoff:

1. The broker stops admitting new writer input and drains every already accepted input
   byte to the canonical PTY master.
2. It excludes the master from its own read/write poll set, duplicates the descriptor,
   and sends the duplicate with `SCM_RIGHTS` in a bounded ancillary-data record.
3. The gateway validates exactly one descriptor and the expected lease identity, wraps
   it in nonblocking `AsyncFd`, and commits the lease.
4. Only after commit may the gateway read or write the duplicated master. A timeout or
   malformed handoff closes the received descriptor and returns the broker to its safe
   path.

While committed, the gateway writes ordered input operations directly to the PTY and
commits the corresponding replay sequence only after the full nonblocking write. It
reads PTY output directly into reserved replay-slab storage before publishing the
operation to QUIC. This removes the framed Unix data hop and its second process wakeup.

The broker must never reclaim a lease merely because the control socket closes: file
descriptors can outlive sockets. It resumes PTY I/O only after a graceful
close-before-release exchange or pidfd-proven gateway death. Lease IDs and gateway
generations prevent an old release, pid reuse, or delayed control record from reclaiming
a newer lease.

## 3. Ordered control and observers

Resize and signal operations remain ordered with input. The gateway either applies an
operation safely through the leased master using the canonical everpty syscall helper,
or pauses later input until the broker acknowledges the control operation. No later
byte may overtake an earlier resize or signal.

Remote everudp observers remain inside the gateway and do not affect the lease. A
legacy local everpty/everssh observer requires broker fan-out, so its admission starts a
graceful revocation. The gateway stops PTY reads, drains any captured output into replay,
acknowledges release, and falls back to the existing framed writer edge before the
observer is granted. Detaching the observer may allow a fresh lease; there is no
in-place assumption that the old descriptor is current.

## 4. Death, overrun, and exit

Pidfd readiness is authoritative gateway-death evidence. On death the broker closes the
lease state and immediately drains/discards PTY output so the child cannot stall. A
replacement gateway receives a new generation and lease ID, never replays ambiguous
input from the dead process, and starts future-only output with exactly one GAP.

Child exit remains broker-authoritative. The broker reports the child outcome, while a
committed gateway drains final PTY bytes to the kernel boundary and completes an
explicit exit-drain exchange. Final output must precede the exit record. Timeouts favor
session cleanup and an explicit GAP/diagnostic over unbounded waiting.

## 5. Security and resource boundary

- Only the current same-UID exclusive writer can request a lease.
- Peer PID, process start time, gateway generation, and lease ID are all checked. PID
  alone is never an identity.
- An ancillary message must contain exactly one PTY descriptor, no truncation, no
  unknown control records, and no attacker-sized allocation. All rejected descriptors
  are closed.
- The received descriptor is nonblocking and close-on-exec. It is never exposed through
  the public CLI, logs, status records, environment, or child inheritance.
- At most one lease and one pidfd exist per broker. Handoff and release have bounded
  deadlines and do not expand the existing replay or observer caps.

## 6. Staged decision gates

The experiment is split so another two-hour exact M6 run is not started on a marginal
design.

### Development proof

Use the same compiled raw-PTY fixture, public send-to-local-acceptance timing boundary,
byte-exact oracle, frozen custom-zmosh source, CPU controls, and symmetric 0 and 5
percent loss cells as v1. Use disjoint development seeds and at least 200 observations
per implementation per cell. Both cells must have zero transcript failures and an
everudp/custom-zmosh p50 point ratio no greater than 0.90. A miss is sealed and stops
productionization.

The proof must also cover one active PTY consumer, monotonic lease identity, no ACK
before complete PTY acceptance, descriptor transfer rejection, control EOF while the
gateway remains alive, and gateway death before and after each handoff boundary.

### Production repair

If the development proof passes with margin, make the lease the preferred everudp path,
retain the framed fallback, and run the complete v1 suite plus lease-specific model,
fault, observer, final-output, descriptor-leak, hostile ancillary-data, and application
tests. Kill the gateway before and after transfer, commit, partial input, PTY write,
replay publication, and release.

### Exact qualification

Create a new clean candidate and rerun all of M6, including 1,200 observations per
candidate per cell and both frozen zmosh baselines. The original thresholds are
unchanged: p50 point ratio at most 1.00, p50 upper-95 at most 1.10, and p95 upper-95 at
most 1.00 in every comparison. Only a full PASS followed by a fresh independent
maximum-reasoning review can authorize a release epic, version, tag, merge, push, or
fleet rollout.

## 7. Rejected shortcuts

- Relabeling the custom-zmosh baseline, weakening thresholds, or shipping only because
  zmosh QUIC passed would change the product decision rather than fix the product.
- Embedding the gateway in the broker removes process-failure isolation and tangles the
  synchronous broker with the network runtime.
- Giving session ownership to the gateway duplicates hardened broker lifecycle logic
  and turns a gateway crash into a terminal-session crash.
- Shared-memory queues retain the cross-process wakeups and are a fallback only if the
  raw-PTY capability cannot be secured.
- QUIC datagrams and prediction violate the frozen terminal and delivery model and are
  unnecessary unless this lease experiment disproves the component latency budget.

## 8. Outcome

The lease experiment disproved that budget. Exact candidate `dfb39bb4705e5d49924a0751ece57c8f170e8336`
remained byte-correct but measured p50 ratios of `1.791x` at zero loss and `1.525x`
at five percent loss against frozen custom zmosh, versus the required `0.90x`.
The immutable negative receipt is
`docs/release-evidence/20260906-everudp-direct-lease-dfb39bb`.

The lease is therefore not productionized as the M6 repair under this contract. The
separately bounded QUIC DATAGRAM experiment is specified by
`plans/everudp-v3-quic-datagram-fast-lane.md`; it does not retroactively change this
receipt or v2's acceptance criteria.
