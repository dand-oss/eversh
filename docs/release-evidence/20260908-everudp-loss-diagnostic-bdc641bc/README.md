# One loss-tail diagnostic, not qualification

Bead eversh-5fc.67. Source bdc641bcaae699cc0122336ebe21504ae9e7571b,
combined task-ownership and delivery-handoff mode plus packet diagnostics.
Binary531b1c17d7c2773c867375a57eb384d205fd403bc7cc71a8057d12afdfa494e3.
Build provenance retained; full original build identity is also in the preceding
task-bdc641bc archive. No source or profile changes were made for this capture.

Protocol frozen in Beads before execution:200 trials per candidate,5% symmetric
loss,seed212200001,order everudp,zmosh-udp,zmosh-quic,CPUs40,42,44,46,100ms
gaps. All three tracing flags enabled. Same sealed control/fixture binaries as
the factorial experiment. No builds, agents or analysis during measurement.
All600 responses passed exact-transcript checks; no retry. Original capture seal
reverified. This is instrumented diagnosis, not an uninstrumented comparison.

The strict packet analyzer accepts all200 rows. Descriptive everudp p50/p95:
564/3874us, maximum7203us. This does not replace the earlier outlying block,
establish significance, or show that the previously observed tail is resolved.

The12 slowest trials each contain repeated transmissions of the same stream
range on one direction. Earlier packet numbers are absent from the receiver's
authenticated-packet trace; a later transmission completes delivery. Examples:

| Trial | End-to-end us | Direction | Packet number at us after reservation; receiver observed |
|---|---:|---|---|
| 63 | 7203 | input | 240 at24.8,no;243 at3358.4,no;246 at6634.7,yes |
| 161 | 4713 | output | 580 at30.9,no;583 at3709.1,yes |
| 23 | 4194 | input | 95 at40.3,no;98 at3697.0,yes |
| 98 | 4097 | input | 369 at40.8,no;372 at3523.8,yes |
| 101 | 4096 | input | 383 at56.2,no;386 at3499.7,yes |
| 83 | 4044 | output | 307 at32.6,no;310 at3531.6,yes |

The long reservation-to-completion-build spans therefore include retransmission
waiting; they are not packet-construction CPU costs. After the final packet of
trial63, STREAM receipt to application is50.6us and output delivery completes
without another retransmission. The observed losses explain this capture's
longest delays, but not the prior uninstrumented27.8ms block-p95 outlier: that
block has no packet trace, so its mechanism remains unproven.

The remaining no-loss public-send-to-input-queue interval cannot be attributed
to QUIC from current markers. It spans fixture write to PTY, kernel readiness,
Tokio scheduling, stdin read, selector dispatch and queue push. Existing noQ I/O
markers do not split terminal readiness/read costs. Further boundary evidence is
needed before changing that path. Product defaults and frozen gates are unchanged.
