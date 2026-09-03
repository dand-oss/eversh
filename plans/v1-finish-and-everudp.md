# v1 finish and everudp roadmap plan

Status: Revision 6 — Sol max review PASS | Owners: `eversh-chl`,
`eversh-chl.4`, `eversh-chl.5`, `eversh-chl.6`, new everudp spike bead |
Updated: 2026-09-03

## 1. Objective and completion boundary

Finish the current product honestly, then decide with measurements whether a
direct-UDP terminal layer is worth building. The roadmap has Stage 0, four
implementation stages, and one cross-cutting evidence invariant:

0. **Stage 0 — qualification-framework preflight.** Implement the repaired
   exact-SHA qualification aggregator and its subgate wiring first. Milestone
   closures use milestone-specific exact-SHA receipts; the complete M5
   aggregator executes only after Stage B/C artifacts and documentation exist;
   all lower-level gates rerun at the final release SHA.
1. **Stage A — full contract reconciliation.** Revise every normative and
   user-facing statement, and every affected bead, so the release contract
   describes the qualified v2 association resume instead of contradicting it.
2. **Stage B — M4 composed-system qualification.** Prove the composed claim —
   `eversh` + real everpty + real everssh + system sshd — across real outages,
   with a criterion-to-test-to-receipt matrix; keep deterministic fake
   contract tests as a separate tier.
3. **Stage C — M5 release.** Execute the repaired qualification entry point
   so it cannot emit a false PASS, run the reconciled section-14 matrix at one
   exact SHA, freeze measured limits with an evidence table, package exactly
   three executables, and retain sanitized receipts outside ignored paths.
4. **Stage D — everudp spike.** Answer one preregistered, bounded question
   with measurements in an isolated non-member workspace; end in a recorded
   build/not-build decision. Production everudp is out of scope.
5. **Cross-cutting evidence invariant.** Durable exact-SHA receipts are a
   precondition of **every** bead closure and of publication, not a later
   cleanup stage. The qualification infrastructure is repaired before M3
   requalification; C5 prepares a release candidate only; publication happens
   only after the final evidence audit.

The roadmap is complete when M3/M4/M5 close with retained evidence, the revised
documents never claim behavior the binaries do not have, version-skew behavior
is exactly the fail-closed coordinated-upgrade contract actually implemented,
and the everudp decision is recorded with preregistered metrics.

## 2. Frozen sources and implementation evidence

| Source | Identity | Use |
| --- | --- | --- |
| Normative design | `plans/design.md` at this plan's reviewed base | Governs v1. Stage A revises the sections enumerated in §3 below; all other contracts stay locked. |
| Resume revision | `plans/everssh-resume-spike.md` | Historical proposal. Stage A converts it into an implemented-result record with the actual limits and compatibility policy. |
| Association implementation | `728dfd0`, `a0b31c1`, `a20a270`, `129db42`, `3b40356`, `ec5212e`, `e4e970f`, `fabaea3`, `731fbda`, `0205b98`, inclusive through `e845743` | Identity, sequential server, replay core/actors, production swap, supervisor retention, stall bounds, concurrent wire, v2 gate parsing. |
| Long-hold qualification | `adf5c3e`, `569ac61`, `e845743` | 360 s lease, retryable reconnect binds, 302 s IPv4 outage recovery, sustained holds, held-server reaping. |
| Existing gates | `crates/everssh/tests/net/{test-migration.sh,test-openssh.sh}`, `crates/eversh/tests/net/test-eversh-openssh.sh`, `fuzz/qualify-m5.sh` | Current per-layer/fake evidence floors; Stage B/C repair or supersede the composed and release entry points as specified. |
| M3–M5 acceptance | Beads `eversh-chl.4/5/6` and epic `eversh-chl` | Control closure. This plan supersedes obsolete functional criteria through the recorded design revision while preserving or strengthening every security and resource criterion. Stage A rewords their superseded one-shot language without weakening any security or resource criterion. |

Runtime PASS claims remain provisional until the repaired exact-SHA entry
point reruns them and retains sanitized receipts. No bead may close on the
provisional claims in this table.

## 3. Stage A: full contract and tracker reconciliation

The v2 association resume is implemented with provisional evidence and known
M3 deadline defects pending repair, but the normative and user-facing record
still describes the superseded one-shot contract. Stage A reconciles **all**
of it before any M4/M5 gate runs.

### A1. Normative design sections

Revise `plans/design.md` sections so no release criterion contradicts the
implemented two-mode behavior (standard migration on one connection; after
connection death, bounded association reconnect with cumulative ACKs and
capped opaque-byte replay). The complete audit list:

- §1 overview, §2 guarantees, §3 raw-primitive boundaries, and §4 hard rules:
  replace one-shot/no-retained-data wording with everpty's unchanged
  byte transparency plus everssh's bounded association replay.
- §6.1 one-shot server and §6.2 one ordered stream/no replay: distinguish the
  SSH stream contract (still exactly one ordered opaque stream) from the
  association layer (sequential connections, durable FIN, bounded replay).
- §6.3 runtime/migration/shutdown: migration keeps one QUIC connection; after
  connection death the bounded association lease/reconnect budget governs.
- §7 supervisor: `reconnecting` defers probes; terminal association failure
  invokes the existing bounded fresh-SSH probe/reattach path.
- §8 version policy: v2 wire/bootstrap is the current protocol; version or
  ALPN mismatch fails closed with a coordinated-upgrade diagnostic. There is
  **no automatic v1 fallback** and none is promised.
- §9 failure matrix, §11.3 diagrams/tests, §13 milestones, §14 release
  acceptance, §15 non-goals, and §16 checklist: replace "fresh attach rather
  than replay" with bounded-resume-then-fresh-attach; scope the replay
  exclusion to **unbounded or semantic** replay while keeping everpty
  replay-free and all terminal-state non-goals intact.
- §10 security model: replace one-shot-server-only language with the v2
  association authorization contract — bootstrap-bound association ID and
  client SPKI, same-key resume authentication, bounded replay, lease expiry,
  and secret scrubbing after Finalize.
- §11.4 supervisor tests: "raw commands and transfers are never replayed"
  becomes "eversh never launches a replacement OpenSSH operation; a live
  everssh association retransmits bounded opaque frames retained until
  cumulatively acknowledged; already-delivered duplicates are suppressed."

### A2. Historical and user-facing documents

Mark `plans/v2.md`, `plans/reference.md`, `docs/handoff-v1.md`, and other
superseded historical records as archived statements of their era, not current
contracts. Rewrite `plans/everssh-resume-spike.md` from proposal status into
an implemented-result record: configured 360 s lease (observed recovery 302 s
IPv4 / 22 s IPv6; production-scale expiry pending), ~350 s client budget, no
old-peer fallback, and fail-closed coordinated upgrades; its 24-hour proposal
and raw opt-out language are explicitly superseded. Update `README.md`,
`docs/install.md`, and release copy for the v2 ALPN/bootstrap strings,
configured 360 s lease, ~350 s client budget, 4
MiB/1,024-frame queues, backpressure semantics, and coordinated upgrades.
Audit source comments (including `supervisor.rs` episode docs) and
troubleshooting text for stale timeouts, `/1` ALPN strings, and status verbs.

### A3. M3 transport repair, bead reconciliation, and closure

First repair the known M3 transport defect so closure is honest: create
exactly one reconnect deadline per outage epoch before its first
route-selection/bind, reuse it across bind/connect retries, and clear it only
after successful resume. Add production terminal-expiry gates for both
100%-loss-with-route and complete route removal, plus an actor gate for two
sequential outages where the second receives a fresh budget. Then update the
epic and M3/M4/M5 bead language to distinguish supervisor-level operation
restart from bounded association byte retransmission. Requalify M3
(`eversh-chl.4`) under the revised contract with the existing transport gates
plus the new resume gates, close it, and only then open M4 closure. Stage 0's
aggregator implementation precedes this requalification so M3 closure carries
milestone-specific exact-SHA durable receipts. M4/M5 may not close while
their blocker M3 retains contradictory acceptance language.

Checkpoint: `rg` finds no live one-shot/no-replay release claim outside files
explicitly marked historical; every changed claim names a test or gate.

## 4. Stage B: M4 composed-system qualification

Two evidence tiers remain: deterministic **fake contract tests** (required by
design §11.4 for exact argv, Kitty, and partial-failure coverage) and new
**real composition tests** using combined `eversh`, real everssh, real
everpty, and the isolated system sshd. Neither tier substitutes for the
other. Wording fix throughout: eversh never launches a replacement OpenSSH
operation for raw SSH/forwarding/SFTP/SCP, although a live everssh association
retransmits bounded opaque frames retained until cumulatively acknowledged and
suppresses already-delivered duplicates.

### B0. Criterion-to-test-to-receipt matrix

Produce and freeze this matrix before implementation; each row names the
criterion, tier (fake/real), test file and case, exact pass assertion, and
receipt location. Required real-composition rows include:

- Atomic connect: concurrent `connect` for one name creates exactly one child;
  loser observes Busy or attaches per explicit policy; no duplicate brokers.
- Busy/takeover: implicit attach never revokes a writer; explicit takeover
  revokes the old owner visibly; both states remain visible.
- Missing/exited/hard-failed broker: probe distinguishes each; a gone broker
  is never restarted; clean child exit returns the real status.
- Raw SSH failure: exactly one outer OpenSSH process; no supervisor restart.
- Forwarding/SFTP/SCP: no replacement operation across terminal transport
  failure; each reports its own ordinary failure.
- Kitty: `KITTY_LISTEN_ON` honored, one reconnect per matching window, failed
  windows preserved, cleanly ended tabs closed, partial results aggregated.
  The fake-launcher row is the required release contract; a real-Kitty smoke
  row is optional diagnostic evidence only and never gates release.
- Standalone artifacts: installed standalone everpty and everssh execute the
  same roles as the combined binary.

### B1. Live-session outage continuity (real composition)

1. Start `eversh connect` to the isolated sshd with a named PTY session.
2. After established output, apply 100% path loss for at least 90 s while
   queuing bounded input; assert local eversh stays alive, status shows
   `reconnecting`, and no probe/bootstrap starts.
3. Restore within the lease; assert the same local process continues, queued
   input arrives exactly once, PTY session and local scrollback are unchanged,
   and no duplicate remote output appears.

### B2. Terminal fallback with implementation-true deadlines

The actor deadline/reset repairs and all transport expiry gates are completed
in Stage A3 before M3 closes; B2 consumes them and proves only the composed
supervisor behavior.

B2 itself records observed monotonic timestamps rather than asserting
predicted constants: `T_loss`, connection-death detection (~20 s stall plus
close/finalize slack), client budget exhaustion (~350 s later), the server's
renewed lease start (when resume acceptance begins, not the moment of
connection death), and actual server release. Sustain loss until at least
10 s **after observed** server release, then:

1. Assert local ssh exits at client-budget exhaustion and the supervisor
   begins its episode then.
2. The supervisor must explicitly wait the bounded old-association drain
   window (client-exit to observed server release, plus finalize slack)
   before interpreting probe results or spending fresh-bootstrap attempts;
   extend its episode deadline as a named measured limit if needed. Never
   shrink the association lease to fit the supervisor.
3. Assert fresh SSH reaches the still-live everpty broker, reattaches the same
   session, renders only future output, and delivers no old-association byte
   after the terminal transition.

### B3. Full matrix rerun

Run every fake-contract suite and every real-composition test on the exact
final diff; all existing eversh, everpty, and everssh suites remain green.

Checkpoint: the frozen matrix has no empty receipt cell; bead `eversh-chl.5`
closes only then.

## 5. Stage C: M5 release hardening

Stage C executes in the order C2 → C3 → C4 → C5 → C1: matrices, limits,
fixtures, and release-candidate preparation exist before the final aggregator
run consumes them.

### C1. Final qualification-aggregator execution

Execute the Stage-0-repaired `fuzz/qualify-m5.sh` aggregator at the release
SHA. Its implementation contract, built in Stage 0, is the single exact-SHA
entry point that:

- records the workspace SHA and refuses to run on a dirty tree;
- includes `fuzz_resume_handshake` (and every future resume/association
  target) in the fuzz matrix;
- invokes both root everssh network gates (`test-migration.sh`, including the
  302 s recovery case, and `test-openssh.sh`);
- invokes the repaired composed M4 gate and repairs/replaces
  `test-eversh-openssh.sh`'s stale ~40 s fresh-attach expectations against the
  360 s lease;
- runs documentation/compatibility and packaging checks; and
- emits PASS only when every subreceipt exists, matches the same SHA, and is
  green — skipping on missing root privileges, unavailable environments, or
  missing receipts is a FAIL, never a PASS.

### C2. Measured-limit evidence table

Publish a table with one row per bound and columns: configured value, semantic
start point, evidence class, and current status. Required rows: server
association lease 360 s, measured from entry into resume acceptance after
bounded peer-close/finalize handling; one client reconnect budget (~350 s)
per outage epoch, created before its first bind and reset only by successful
resume; 302 s observed recovery
(production IPv4 evidence; IPv6 currently 22 s); per-direction 4 MiB/1,024
frame queues; remote stall 20 s; drain 5 s; finalize 5 s; process/fd/task
ceilings; shutdown latency. Add gates for every currently unproven cell:
default-bound terminal expiry, near-bound (~350 s) recovery for IPv4 **and**
IPv6, byte-cap and frame-cap saturation in both directions, backpressure
without silent drops, and RSS/FD resource ceilings under held associations.

### C3. Mechanical section-14 matrix

Build one row per revised §14 criterion: exact command, environment and SHA,
pass rule, and retained evidence path. Name supported targets —
x86_64-unknown-linux-gnu on Ubuntu 22.04/24.04 and Debian 12, plus
aarch64-unknown-linux-gnu on Debian 12 under QEMU TCG (or native hardware
when available; cross-compilation alone is not runtime qualification) — and
define sanitizer, audit, licence, reproducibility, and packaging failures as
release-blocking. Update bead `eversh-chl.6` language to the reconciled
contract.

### C4. Version-skew matrix (fail-closed coordinated upgrades)

Pin the pre-v2 whole product to `43e80cc`, whose actual identities are binary
`everlink`, remote role `__everlink`, bootstrap prefix `everlink v1`, and ALPN
`eversh-link/1` (the `everssh`/`__everssh` rename arrived later at
`151d81e`). Require two distinct tests:

1. **Whole-product coordinated upgrade:** v2 client against `43e80cc` server
   and `43e80cc` client against v2 server. A renamed binary/role mismatch may
   fail before protocol negotiation; that ordinary failure must still produce
   the documented fail-closed operator diagnostic, never a fallback.
2. **Controlled protocol-edge fixture:** pinned old wire records/ALPN against
   the v2 protocol edge so bootstrap/ALPN mismatch itself is reached and
   diagnosed.

Both paths fail closed with component-and-version diagnostics. Document
coordinated upgrade as the operator requirement; do not implement or promise
automatic v1 compatibility in this roadmap.

### C5. Release-candidate preparation

Package exactly three executables reproducibly and prepare install, upgrade,
rollback, firewall, endpoint, and coordinated-version documentation without
promising relays, rendezvous, upload, prediction, scrollback recovery, or
automatic old-protocol fallback. **Publication occurs only after** the final
cross-cutting evidence audit confirms every §14 matrix row and closure receipt
at the release SHA.

## 6. Stage D: everudp spike (isolated, decision-only)

All screen models, prediction, reconciliation, terminal epochs, and terminal
acknowledgements live only in the optional everudp client/server layer. The
spike lives in a separate non-member `spikes/everudp` workspace with its own
lockfile; `eversh`, `everssh`, and `everpty` neither depend on it nor export
code to it, and the boundary gate continues to enforce exactly three
production binaries and a terminal-free production dependency graph. The
everpty attachment boundary is consumed, never modified.

### D1. State-model seam

Evaluate licensed Rust terminal-state options; specify the client-edge state
owner, server echo model, state epochs and acknowledgements, input policy
(including no-echo safety), resize, divergence detection, resynchronization,
and reset semantics before benchmarking.

### D2. Transport and reachability matrix

Compare identical terminal-state logic with prediction on/off over noq QUIC
datagrams and a specified encrypted-UDP substrate with equivalent AEAD/KDF,
nonce/anti-replay, MTU, traffic/amplification, congestion-control, loss
recovery, authenticated key-establishment/peer-identity, key-rotation,
CPU/RSS, and bandwidth ceilings. Include everssh/OpenSSH and Mosh controls,
plus a pinned-commit zmosh build attempt; if zmosh cannot be built, record
the exact blocker and make no zmosh comparison claim. Preregister
the deployment matrix before testing: direct IPv4, direct IPv6, full-cone,
restricted-cone, port-restricted-cone, and symmetric NAT; ZeroTier;
Tailscale; and UDP-blocked. For UDP-capable environments, fallback means one
bounded transition to everssh v2 with its normal handshake timeout and success
condition. The UDP-blocked row expects bounded, clearly diagnosed failure;
plain TCP OpenSSH may be noted as a separate user-driven choice, never an
automatic fallback. Use at least 20 attempts per environment and fix pass
ratios in the spike bead before testing.

### D3. Preregistered benchmark and decision

Before implementation, freeze: at 5% loss, success requires ≥50% reduction in
median and ≥33% reduction in p95 keystroke-to-correct-render versus everssh
v2; correction convergence p95 <300 ms; zero predicted-echo displays on
no-echo/password workloads; no correctness regression across resize,
full-screen, and tmux workloads; ≥30 trials per cell with reported
uncertainty; directional loss, reorder, jitter, and outage sweeps. Record the
build/not-build decision, production milestone shape, or stop recommendation
in the spike bead. The oracle for every workload is an independent terminal
state comparison against the authoritative PTY byte stream; visual similarity
alone is not correctness. everrtc remains only a documented fallback if this
matrix shows direct UDP cannot meet its preregistered reachability ratio.

## 7. Required gates

- Documentation: every live claim names evidence; historical records are
  explicitly superseded.
- Fast: `cargo fmt --all -- --check`; workspace check/test with all features;
  boundary and trait tests.
- Full: entire workspace suite; both root everssh network gates; repaired
  composed M4 gate; repaired exact-SHA M5 entry point; §14 matrix.
- Evidence: sanitized receipts and subreceipt hashes retained in Beads or a
  tracked release-evidence directory — never only under ignored `target/`.

## 8. Sol operating contract and review receipt

Sol reviews at max reasoning from a clean exact base against the authoritative
sources, bead criteria, and implementation state, reporting blocker/major/minor
findings with anchors and confidence. Findings are repaired before execution;
milestone closure requires a fresh independent review with zero blocker/major
findings. Sol does not implement, commit, push, close beads, or weaken the
design contract.

Review receipt — 2026-09-03 Sol max review of revision 1: **FAIL**, high
confidence; 3 blockers (incomplete contract reconciliation; false old-peer
fallback promise; false-PASS-capable M5 harness with a stale composed gate),
7 majors (M4 matrix gaps; B2 timeline; overstated limit evidence; unauditable
§14 closure; weak everudp boundary; unregistered benchmark; non-durable
receipts), and 3 minors (commit-range ambiguity; stale doc strings; qualitative
NAT criterion). Revision 2 repairs all findings; a fresh Sol verification pass
is required before execution.

Review receipt — 2026-09-03 Sol max verification of revision 2: **FAIL**,
high confidence; revision-1 repairs were confirmed, with 3 new blockers
(design §10/§11.4 and the resume-spike document remained unreconciled; B2's
timeline did not match deadline-start/renewal semantics or the no-route path;
evidence was ordered after milestone closure), 2 majors (premature "measured
360 s" wording; unfair/unsafe raw-UDP comparison), and 3 minors (conditional
Kitty row, ambiguous aarch64 target, self-certified revision status).
Revision 3 is intended to repair these findings and awaits fresh verification;
no passing review has yet been recorded.

Review receipt — 2026-09-03 Sol max verification of revision 3: **FAIL**,
high confidence; all revision-2 repairs were confirmed, with one remaining
blocker (C2 retained stale client/server clock semantics and overclaimed
"implemented and qualified" status), one major (qualification-framework repair
was conflated with final qualification execution), and three minors (ambiguous
per-attempt deadline wording; unnamed NAT/fallback models; unpinned
version-skew fixtures). Revision 4 adds Stage 0, corrects both clocks and the
provisional status, pins `43e80cc` as the older-peer fixture, names all NAT
models and the bounded everssh fallback, and awaits fresh verification.

Review receipt — 2026-09-03 Sol max verification of revision 4: **FAIL**,
high confidence; prior repairs were confirmed, with one blocker (M3 was
scheduled to close before the known no-route deadline defect was repaired),
two majors (replay wording described acknowledged rather than
retained-until-acknowledged frames; the `43e80cc` fixture was misidentified —
its real names are `everlink`/`__everlink`/`everlink v1`/`eversh-link/1`), and
three minors (duplicated Stage 0/C1 repair ownership; UDP-blocked fallback
could not use everssh; the stage list mixed an invariant with stages).
Revision 5 moves the transport repair and expiry gates into M3 closure, keeps
only composed supervisor proof in B2, corrects retransmission wording, records
the real v1 identities with whole-product and protocol-edge tests, moves
aggregator repair wholly into Stage 0, makes C1 final execution, defines
UDP-blocked as bounded diagnosed failure, and restructures the opening stage
list. It awaits fresh verification.

Review receipt — 2026-09-03 Sol max verification of revision 5: **PASS WITH
FINDINGS**, high confidence; zero blockers and zero majors. Sol verified the
M3 repair ordering, retransmission wording, `43e80cc` identities and split
fixtures, Stage 0/C1 ownership split, UDP-blocked honesty, and stage-list
structure. Three editorial minors (C1's physical placement, two stale
introductory labels, and overstated bead-preservation wording) were repaired
in revision 6; the reviewed revision-5 SHA-256 was
`48e52a5fae8cb5c55769ba4347502b102f7a990c0a640aa363731f544952fa11`.

## 9. Explicitly out of scope

Production everudp/everrtc, WebRTC dependencies, v1 protocol fallback, relays
or rendezvous, remote binary upload, always-on gateways, 24-hour holds without
an idle soak, terminal state in everpty or everssh, scrollback recovery,
second runtimes, and any release claim not backed by a retained exact-SHA
receipt.
