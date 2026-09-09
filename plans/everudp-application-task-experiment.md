# Application task ownership: causal follow-up

Bead: eversh-5fc.66. This follows the non-adopted delivery-handoff evidence
at docs/release-evidence/20260908-everudp-delivery-abccb1c.

## Evidence and hypothesis

Moving readability notification before transmit did not make the root application
consume before transmit: every captured directional window contains another driver
service between readability and application handling. The client and gateway run
inside the root block_on future (edge.rs), while noQ drivers are spawned tasks.
Locked Tokio1.53.1 polls the root at its outer-loop boundary and processes its
task batch before returning to that boundary. Root wake and scheduled-task wake
therefore have different service order.

First prove that distinction with a deterministic current-thread fixture: ensure
the application has registered a blocked reader, wake it from a driver poll,
self-wake the driver and return Pending, then record consume/transmit order.
Compare root application ownership with ordinary spawned-task ownership. This is
a scheduling test, not a benchmark or evidence of a production speedup.

## Proposed intervention, conditional on the causal test

An independent, default-off application-task-spike may move each long-lived client
or gateway application future into one ordinary Tokio task on the same existing
current-thread runtime. It adds no thread, timer, per-byte task, queue, allocation,
or terminal interpretation. Bootstrap-parent and broker preparation stay unchanged.
Do not use a separate LocalSet queue as a substitute for the ordinary task queue.

The root awaits the application task to completion. Retain terminal restoration,
owned descriptors, normal return codes, protocol/auth errors, and panic unwinding;
never silently detach the task or turn task cancellation into success. Client raw
mode activation remains after authentication. Gateway lifetime, invitations,
observer isolation, bounded replay and exact-delivery semantics remain unchanged.

Keep application-task ownership independent of stream-delivery-spike. The latter
is a separately measured prerequisite only if a real interaction is demonstrated;
do not fold either experiment into defaults on the strength of synthetic ordering.

## Verification before measurement

Require deterministic root-versus-task wake-order tests, feature-off regression,
feature-on library/process checks, security/admission/replay checks, and explicit
application result/panic/lifetime checks. Re-run affected tests for the combined
delivery/task mode. Do not weaken Send/lifetime constraints or add unsafe code to
make a role spawnable. Record a concrete ownership blocker if one is found.

Then freeze a bounded comparison protocol and exact source/build identities before
timing. It must distinguish task ownership alone from its delivery interaction,
reuse identical frozen control binaries where the harness can verify provenance,
and retain all negative results. No simultaneous builds, agents, or analysis.
The original full production performance/reliability/security/review gates remain
unchanged. A local ordering test or a small median gain is not acceptance.

## Frozen bounded follow-up schedule

After the focused checks pass, build one exact source SHA with these four
uninstrumented modes: A=`cli`, D=`cli,stream-delivery-spike`,
T=`cli,application-task-spike`, X=`cli,application-task-spike,stream-delivery-spike`.
Use one additional X build with preceding `path-packet-diagnostics` for a single
20-trial diagnostic capture (0% loss, seed212000001). The diagnostic capture is
not included in ordinary latency estimates.

All five builds reuse the five byte-identical control/fixture binaries from the
sealed ordinary /tmp/everudp-delivery-abccb1c-baseline-build bundle. Validate its
complete seal, source pins, current fixture source hashes and tool identities;
retain its original provenance in each new bundle. No per-variant control rebuild.

Each loss cell (0%, then5%) runs A,D,T,X,X,T,D,A, 200 trials per candidate/block,
for400 observations per mode/cell/candidate (9,600 ordinary responses overall).
Block index0..7 has seed212100001+100*cell_index+block_index. Rotate candidate
orders E,U,Q; Q,E,U; U,Q,E; E,Q,U by block_index modulo4, where E is everudp,
U pinned UDP zmosh, Q pinned QUIC zmosh. Keep CPUs40,42,44,46,100ms gaps and
the existing compiled fixture, topology, transport profile and exact transcript
oracle. Freeze all source/binary identities and the expanded runner before timing.

Retain all failures and do not substitute retries. Compare T against A, X against
D, and X against T, with control drift reported separately. Interpret the small
number of blocks as a bounded causal experiment, not the full production gate.
Require actual application-boundary improvement rather than marker movement;
all prior acceptance thresholds and final sampling remain unchanged.
