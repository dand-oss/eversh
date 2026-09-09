# Empty replay cursor exit regression

Fix: `c8906c6514a5bde3a255da4e0b09a1b838b05c8a`.
Scope: Bead `eversh-5fc.46`, not final product qualification.

An output ACK could empty the replay queue before the reliable output sender
polled it. The sender advanced its cursor only when a retained record existed,
then attempted to copy an already retired sequence. `SequenceGap` retired the
writer association before the PTY Exit was queued. The client consequently
reconnected rather than receiving the remote exit status.

The retained diagnostic failure records `active-permanent-error`,
`error-queue-sequence-gap`, `gateway-queue-exit`, then
`gateway-terminal-empty`. It was captured with temporary fixed-label diagnostic
changes subsequently committed in `b6db1d1`; it is not an exact-SHA qualification
run. Earlier broker-handshake and terminal-ACK hypotheses were ruled out.

The deterministic actor regression acknowledges the last queued record before
reliable flush and then delivers a future Exit. Before the fix it failed with
`Association(Queue(SequenceGap))`; after the fix all three actor tests passed
with both CLI-only and all-feature builds. A receiver completion signal prevents
the regression itself from racing connection close against delivery.

All 30 post-fix CPU-40 process trials passed. Command per trial:
`taskset -c 40 cargo test -p everudp --test process --all-features --locked active_writer_rejects_non_takeover_without_udp_fallback_code --quiet`.
These diagnostic trials used the fixed source before its checkpoint commit;
they are race-reproduction evidence, not latency measurements.

At the clean fix SHA, `cargo test --workspace --all-features --locked --quiet`
completed with exit 0 (session 9731); complete output is `workspace.log`.
Strict all-target/all-feature everudp Clippy and formatting checks also passed.
A focused Luna source review found no actionable defect, but is not the required
independent max-reasoning release review. Forced partial-write/ACK interleaving
is not directly exercised by the new regression.

The frozen zmosh performance gates and final exact-SHA reliability, security,
and independent-review qualification remain outstanding. No release or rollout
is claimed.
