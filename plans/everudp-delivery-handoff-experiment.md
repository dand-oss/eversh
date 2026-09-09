# Bounded application delivery before transmit

Bead: eversh-5fc.66. This is an opt-in experiment, not production acceptance.
Baseline behavior is commit055fa6be (production driver unchanged since1732800).
Evidence: packet archive572456f, exact source1732800 and raw paired I/O traces.

## Hypothesis

The driver processes received packets, then calls drive_transmit and drive_timer,
then forwards application events. Packet-correlated no-loss input receipt to
stream-readable median is58.586us; paired protocol/send calls overlap much of
this interval (independent medians17.648/31.120us, not additive CPU costs).
Notification to GatewayInputPrepared is27.557us median. The existing captures
provide1400 unique input/output readability windows with no missing markers.

Move actual application delivery ahead of one transmit pass. Merely moving the
StreamReadable marker does not count: the connection state lock must be released
so the reader can run. No claim is made that all59us can be recovered or that
this explains the entire zmosh median gap.

## Frozen intervention

Use opt-in noQ feature `stream-delivery-handoff`, exposed through everudp
`stream-delivery-spike`; neither is default. Do not enable inline receive,
immediate send, native driver, datagrams or other prior scheduling experiments.

Only an established, nonterminal connection and an actual blocked stream reader
woken by a Readable event can trigger a handoff. Register/requeue the driver and
release the state lock by returning Pending. Permit at most one deferred poll:
the next driver poll must take its ordinary transmit/timer path even if more
received data arrives. Continue processing endpoint events and timers; preserve
close/drain/error behavior and future wakeups. No sleep, added deadline, spawned
task, payload copy or per-input allocation is permitted. An idle or readerless
connection must not start a self-waking loop.

There is no promise that the executor chooses the app before the requeued driver.
The experiment measures actual application/public boundaries, not just earlier
notification. If executor order defeats the handoff, record a negative result.

## Gates before measurement

Focused tests must exercise a reader wake, forced next-poll TX progress under
repeated input, idle/no-reader behavior, timer/close progress, and stream byte
identity. Run feature-on and default noQ checks plus everudp library/process
regressions proportionate to the change. Keep existing security, backpressure,
replay, observers and bootstrap policy unchanged. Any gate failure remains active
until repaired or recorded as a concrete blocker. No experiment is adopted on
the strength of unit tests alone.

## Bounded measurement and decision

Freeze candidate source/binary hashes after focused gates pass. First use one
bounded packet capture to check actual receipt-to-application movement, compared
with archived timing only descriptively. Then compare ordinary baseline and
candidate in an alternating A/B/B/A order in each0/5% cell,200 trials per candidate
per block, both pinned zmosh controls, same compiled echo fixture,100ms gaps and
CPUs40,42,44,46. Freeze the expanded seeds/order/profile before running; do not
tune on these samples or run analysis/builds concurrently with timing.

Require complete exact transcripts. Retain any failure, never silently replace
a failed block. Assess end-to-end medians and tails alongside packet counts,
resource use and actual app-boundary movement. An earlier notification alone
is not a success. If end-to-end improvement is absent or ACK/throughput/recovery
regresses, do not adopt or iterate arbitrary knobs. Record the result.

Original production acceptance thresholds and exact-SHA reliability/security/
independent-review requirements remain unchanged. Even a useful partial latency
reduction is not a product PASS. Release and fleet rollout remain separate.
