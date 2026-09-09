# Application ownership factorial: causal effect, no adoption

Bead eversh-5fc.66. Exact source bdc641bcaae699cc0122336ebe21504ae9e7571b.
This bounded experiment is NOT production qualification. Neither experimental
feature is enabled by default, and no release or deployment follows this result.

## Frozen identities and schedule

A=ordinary cli; D=delivery handoff; T=application task ownership; X=both.
Each mode was built from the same clean source with portable fat LTO, one codegen
unit, O3 and unwind. The diagnostic build adds packet diagnostics to X only.
All five builds passed. They reuse the exact same five control/fixture binaries
from the sealed ordinary abccb1c baseline build. Before timing, the runner checks
all complete build seals, source/features, original control provenance and byte
identity of every reused binary. Original control provenance SHA256:
90ea3a5510f475281f84267c130d5ccec2c026a932744e28250538524ccfd243.

Expanded runner measurement/frozen-schedule.sh SHA256:
5c6ac21a9a069a1758263903634e42c00f8bc8d1b6c28f3743f364d00a508eac.
Its schedule.sha256 retains the original absolute locator. Per-cell order is
A,D,T,X,X,T,D,A, 200 trials/candidate/block, cells0% and5%, 100ms gaps,
CPUs40,42,44,46. Exact seeds/order and per-build identities are retained.
No builds, agents or analysis ran during timing. All16 ordinary blocks and the
single20-trial diagnostic block passed without retries or replacements:
9,600 ordinary plus60 diagnostic exact responses. All17 block seals reverified.

Build provenance, original full-bundle seals and logs are retained under builds/;
binaries are omitted. Those original build seals describe the original bundles,
not a complete archived binary inventory. The archive root seal covers the files
actually retained, including all original control provenance records.

## Descriptive end-to-end results

Nearest-rank pooled p50/p95 in microseconds,400 samples/mode/cell:

| Loss | A | D | T | X |
|---|---:|---:|---:|---:|
| 0% | 646 / 1059 | 611 / 1041 | 642 / 995 | 589 / 970 |
| 5% | 677 / 4034 | 635 / 4321 | 712 / 4261 | 596 / 4618 |

Matched UDP-control medians by A,D,T,X are436,397,433,420us at0% and
421,437,439,440us at5%. Matched QUIC-control medians are651,607,642,627us
and666,654,661,671us. Identical binaries do not remove temporal/control drift.
There are only two blocks/mode/cell; these are descriptive estimates, not
confidence bounds or significance claims. The final qualification sampling
contract has not been met. X still exceeds the UDP median by about40%/35%,
and its5% p95 is higher than A. Task ownership alone has no clear benefit here.
Do not adopt X from these results or call the higher tail a proven regression.

## Production-path causal observation

The strict packet/dispatch analyzer accepts all20 input/output windows. In X,
all40 directional windows contain ZERO driver-service events between readability
and application handling, versus one in every window of the previous D capture.
Post-notification protocol/transmit call overlap is also zero in every X window.
The intended delivery ordering now occurs on the real application path.

Input receipt-to-application median is24.593us (readability before it at4.6625us;
post-notification19.8145us), versus85.26us in the prior D capture. Output is
6.1045us (1.565us before notification and4.3805us after), versus41.3695us.
Cross-capture figures are unpaired/descriptive, and independent medians do not add.

Remaining X input-stage medians: operation reservation to packet build41.074us,
build to successful send poll6.422us, send poll to userspace receive93.387us,
receive to authentication18.636us, authentication to STREAM receipt8.909us.
The send-call duration47.218us overlaps poll-to-receive; it is not additive.
Output equivalents are9.104,1.996,44.153,6.165,2.338us (send call14.375us).
These are wall-clock spans, not exclusive CPU or pure network time. The remaining
send/receive boundaries require attribution, not an assumption about encryption
or wire overhead. No further implementation is justified solely by these totals.

Other X capture medians: public send to client input queue97.876us, input queue
to first stream write8.672us, gateway input prepared to accepted10.139us,
gateway input accepted to output queued90.1315us, and client output staged to
accepted9.7365us. The input and output handoff terms do not identify exclusive
CPU or kernel delay. They help locate the next missing attribution boundary.

## Independent bounded audit

Luna independently verified all17 seals, five identical reused controls, source
and features, schedule/seeds, and the pooled figures above. There are48 ordinary
result files plus3 diagnostic results (51 total); its initial report's96-file
count was corrected against the actual inventory before acceptance.

At5% loss, the two X block p95 values were4024 and27847us; A was3973 and4034us.
The mixed X tail means neither "no regression" nor a statistically proven
regression is supported. Do not hide the outlying block or replace it with a run
using another seed. No confidence-bound or release-review claim follows this audit.

## Outstanding

Preserve this negative/partial outcome. Independently audit the results, assess
the tail limitation, and trace the remaining intervals before another intervention.
The original exact-SHA performance, reliability, security and release-review
requirements remain unmet. Earlier full performance FAIL remains authoritative.
