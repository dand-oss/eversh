# Bounded input-ACK wire scheduling experiment

Bead eversh-5fc.83. This is an isolated, default-off experiment, not a new
production transport profile or a relaxation of any acceptance gate.

The retained zero-loss trace at
`docs/release-evidence/20260908-everudp-packet-1732800/overhead/loss0-pair3-trace1`
contains 400 data-stream packets, 399 control-stream packets and 798 packets
with no STREAM frames accepted between first public send and last accepted
response. Reproduce with `crates/everudp/tests/net/packet_inventory.py`.
No-STREAM does not prove ACK-only; packet counts are not removable CPU time.

The gateway commits input to its delivery gate and queues its ACK immediately
after the PTY accepts the operation. Keep both actions unchanged. Existing
outbound polling already writes control and ready output in one turn, but
PTY output need not yet exist when the ACK is first ready.

Under `input-ack-hold-spike` only, allow the sole queued, entirely unwritten
`AckInput` record to wait for at most one millisecond from its first outbound
poll. Release immediately when any output is queued/pending, a second control
record is queued, output changes epoch/discards, or the deadline expires.
Never hold partial writes, other control kinds, or reset the deadline on a
repeated poll. After a record finishes, reset its hold state. Resume creates a
new link-local hold; committed input and the queued control records remain
authoritative. No ACK omission, merging, sequence gaps, or wire format changes.

Use one preallocated timer per link, never an allocation per ACK. This is a
deliberate diagnostic exception to the no-delay-timer hot-path objective, not
permission to delay terminal output or change the production default. Control
stream priority remains unchanged; only the eligible ACK waits. A new non-ACK
control record forces the preceding ACK to progress so it cannot be trapped.

Verify deterministic deadline/repeated-poll boundaries, exclusion of partial
writes and non-ACK control, release on output/control pressure/epoch change,
input-commit-before-ACK, reconnection/replay, observer fairness and queue bounds.
Existing production tests must remain green with and without the feature.

Before a latency comparison, use an isolated same-source A/B diagnostic with
identical sealed controls and profile, default `cli` versus
`cli,input-ack-hold-spike`. Retain all results and host bookends. Stop this
experiment if the changed build does not reduce accepted packet count by at
least 15% in the zero-loss echo workload, or any delivery/resource check fails.
This is a pre-qualification engineering cutoff, not a replacement performance
gate. A packet-count pass permits a bounded latency screen, not adoption.

Final acceptance still requires the frozen 1,200-observation-per-cell gates
against both zmosh baselines plus exact-SHA reliability/security/resource and
independent-review gates. No threshold changes, combined speculative features,
release, push or fleet rollout are authorized by this experiment.
