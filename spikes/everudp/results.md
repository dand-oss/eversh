# everudp Stage D spike result

Status: terminal NOT-BUILD; requested zmosh p50 parity not proven | Owner:
`eversh-2zq` | Preregistration: frozen in the bead before implementation |
Authoritative campaign: clean source `7d4a43244f0287dddd3d01231994b375f2113c0e`.

## Decision: NOT-BUILD (registered p50 parity failed)

The authoritative replacement campaign does **not** prove that everudp is as
fast as zmosh under the frozen rule. Across six alternating-order blocks and
600 real-PTY observations per candidate at 5% symmetric loss, everudp p50 was
456 us and zmosh p50 was 357 us: a 1.277 ratio, above the registered 1.10
limit. The one-sided bootstrap upper-95 ratio was 1.328, also above 1.10.
everudp did win decisively at p95 (21,315 us versus 60,689 us, ratio 0.351),
but the rule requires both p50 and p95 to pass.

The exact-source build, authenticated substrate, terminal-grid correction,
resource, hostile-input, outage, direct-network, modeled-NAT, ZeroTier,
blocked-UDP, and eversh-fallback gates passed. Tailscale was still unavailable
(missing on badger and bagger, stopped on bugger), but it is no longer the
only reason for NOT-BUILD. The performance failure is independently decisive.

The earlier `9083ef0` campaign and its PASS prose are invalidated. Sol review
found that its everudp timer omitted state/encoding work, its success path did
not hard-require byte-equal authority in release builds, its oracle never
painted predictions into a persistent terminal, and its closure trusted
pre-existing binaries and derived receipts. Those defects were repaired
before this replacement campaign; the old data remains archived only as
review provenance.

Correction retained from the 2026-09-04 review: the pinned zmosh control is
available. The local source checkout at `/home/appsmith/asv/ports/repo/zmosh`
contains version 0.5.9 at commit `dfc8395...`; it was built with Zig 0.15.2
and measured headlessly through its documented C UDP client. zmosh uses its
own XChaCha20-Poly1305 UDP protocol and is not Mosh SSP; the earlier
Mosh-as-family substitution is withdrawn.

## Direct zmosh 0.5.9 head-to-head (updated decision evidence)

Every campaign in this section before "Round-2 exact-source campaign" uses a
metric or closure path later invalidated by review. Its numbers and
contemporaneous pass/fail language are retained as chronology only, not as
accepted decision evidence.

Three independent 30-trial cells at 5% symmetric loss measured everudp-UDP
and pinned zmosh 0.5.9 on the identical netns/veth topology. These first
cells were transport-layer only (everudp reflected datagrams; zmosh ran a
real session PTY) and are retained only to document the harness mistake.

| Run | everudp transport-only median/p95 µs | zmosh median/p95 µs |
| --- | --- | --- |
| 1 | 522 / 21,703 | 581 / 61,090 |
| 2 | 496 / 22,102 | 492 / 810 |
| 3 | 434 / 21,971 | 469 / 61,050 |

### First end-to-end correction (historical; superseded)

After the review identified the path mismatch, the everudp server was
upgraded to drive `echo1.py` through `script` (real PTY, `stty raw
-echo`), matching zmosh's authoritative session path:

| Run | everudp end-to-end median/p95 µs | zmosh median/p95 µs |
| --- | --- | --- |
| 1 | 840 / 22,042 | 583 / 445,110 |
| 2 | 953 / 21,947 | 531 / 929 |
| 3 | 750 / 21,959 | 515 / 121,295 |

At this debug-build checkpoint everudp was roughly 1.58x slower at the
median (aggregate 840 us versus 531 us) and failed the frozen
`p50 <= zmosh p50 * 1.10` rule in every run. The transport-only "parity"
claim was correctly withdrawn. This three-run result is retained as the
measurement error that prompted release-mode measurement and a paired,
hash-bound campaign; it is superseded by the evidence below.

### Exploratory release-mode rerun (not closure evidence)

Removing a redundant per-input server timer and benchmarking optimized
release binaries materially changed the result. Six additional 30-trial
runs produced 180 observations per candidate. With one common empirical
nearest-rank estimator, pooled everudp/zmosh p50 was 521/494 us (ratio
1.055) and p95 was 21,558/61,669 us (ratio 0.350). The frozen point rule
therefore passed on the pooled observations, while only four of six small
run blocks passed separately. A stratified bootstrap put the one-sided 95%
upper bound for the p50 ratio near 1.20, outside the 1.10 parity margin.

These files (`end-to-end/*-rel7.json` through `*-rel12.json`) came from an
in-progress dirty tree and used the older always-zmosh-first harness. They
show that the earlier three-run disproof is no longer decisive, but they do
not prove equivalence and are not exact-SHA closure evidence. The dedicated
paired harness now alternates candidate order, uses equal workloads and
pacing, resets seeded netem before each candidate, retains raw samples and
hashes, and requires a clean source commit before a parity verdict.

### Initial clean paired equivalence campaign (historical pre-hardening result)

Six alternating-order blocks of 100 trials per candidate ran from clean
source commit `1a1029cbe115f909a8bcadc6f36ebd3f760a7d61` and tree
`95b7b7059d04f336d887efa5d9700068d83dc359`. Each block reset independent
seeded 5% random loss on both veth directions before each candidate. Both
candidates received the same rotating one-byte workload through the same
Python echo program on a real PTY, with a 100 ms inter-trial quiet period.

| Pooled result (600 trials each) | everudp | zmosh 0.5.9 | ratio |
| --- | ---: | ---: | ---: |
| p50 | 464 us | 477 us | 0.973 |
| p95 | 21,573 us | 60,802 us | 0.355 |

The preregistered point rule passes both margins. A 20,000-replicate
stratified nonparametric bootstrap produced a p50 ratio 95% interval of
0.922-1.025 (one-sided upper 95% bound 1.015) and a p95 ratio interval of
0.353-0.427 (upper bound 0.427). Both upper bounds are below the frozen
1.10/1.15 limits, so the conservative equivalence verdict also passes.
The probability that a randomly selected everudp observation is faster
than a randomly selected zmosh observation is 0.562.

This first clean campaign established the measurement method, but its source
preceded authenticated session establishment and its qdisc receipts captured
configuration before the run rather than hash-bound before/after counters. It
is therefore retained as historical evidence and superseded by the hardened
campaign below.

### Hardened clean paired equivalence campaign (pre-closure result)

Six fresh alternating-order blocks of 100 trials per candidate ran from clean
source commit `c986ce339faeec8671f6d5c9b549965b3ee776b9` and tree
`de23b70951f2a472ffc8b9b779798a5ee2bed6f6`. This source includes the
authenticated handshake, directional HKDF-derived traffic roots, rotating
AEAD epochs, authentication-before-replay mutation, authenticated address
roaming, bounded amplification, retransmission deduplication, and fail-closed
encrypted MTU limits. Every block hash-binds qdisc counters captured before
and after each candidate; positive packet-drop deltas were observed on both
egress paths in all 12 candidate runs.

| Pooled result (600 trials each) | everudp | zmosh 0.5.9 | ratio |
| --- | ---: | ---: | ---: |
| p50 | 457 us | 467 us | 0.979 |
| p95 | 21,483 us | 60,836 us | 0.353 |

The 20,000-replicate stratified bootstrap produced a p50 ratio 95% interval
of 0.930-1.020 (one-sided upper 95% bound 1.013) and a p95 ratio interval of
0.350-0.427 (upper bound 0.426). Both upper bounds remain below the frozen
1.10/1.15 equivalence limits. Exact-SHA, observed-loss, point-rule, and
conservative equivalence verdicts all pass. The probability that a randomly
selected everudp observation is faster than a randomly selected zmosh
observation is 0.565.

This checkpoint appeared to prove the narrow requested latency claim under
the then-current, later-invalidated boundary. At that point,
independent Tailscale-availability, resource, congestion, provisioning, and
everssh-control gaps kept the production decision at NOT-BUILD. The resource
and everssh-control gaps are superseded by the final closure below.

### Rejected round-1 closure (historical; invalidated)

The round-1 campaign ran from clean source commit
`9083ef07292acbf6ef55ce065968ecaf14d6a74d` and tree
`e7b0678cfc198a1a314341af0c4940547bf578b3`. All parity, control, resource,
outage, oracle, and reachability receipts bind that same source and the same
everudp binary SHA-256
`9f50504c479f43ee2f5edddf04b93e5e2f9fe01000e299024cd654680e2ba5f8`.
The fleet fallback also binds the eversh binary SHA-256
`e4ec813a04e85915784bde85a38dbc8337bcb857d7e3b25372520ec33a3f90f5`.

Six alternating-order blocks contributed 600 real-PTY observations per
candidate under independently reset, seeded 5% symmetric loss:

| Final pooled result | everudp | zmosh 0.5.9 | ratio |
| --- | ---: | ---: | ---: |
| p50 | 457 us | 474 us | 0.964 |
| p95 | 21,347 us | 60,935 us | 0.350 |

Its 20,000-replicate stratified bootstrap gave p50 and p95 ratio intervals
of 0.910-1.009 and 0.347-0.421. Their one-sided 95% upper bounds were 1.002
and 0.420, safely inside the frozen 1.10 and 1.15 limits. The probability
that a randomly selected everudp sample was faster was 0.579.

The separate 30-trial control matrix appeared to pass both frozen point rules at
5% loss: everudp was 0.963x/0.032x zmosh at p50/p95 and 0.155x/0.548x
everssh at p50/p95. Those numerical results are not valid decision evidence:
the timer and authority-validation defects biased the comparison, and the
closure did not prove that the binaries came from the recorded source. The
round-1 `closure.json` is therefore a rejected historical receipt, not an
accepted closure.

### Round-2 exact-source campaign (authoritative terminal result)

The replacement campaign ran from clean source commit
`7d4a43244f0287dddd3d01231994b375f2113c0e` and tree
`47cdeea34120cad4b88b991f4a8098f4d349ee5c`. It built eversh and everudp in
fresh Cargo targets and zmosh from pinned commit
`dfc8395b5edcd237bf82712fbde879c6e8be7dfa` in a fresh detached clone with
isolated Zig caches. Every gate used the resulting hash-bound artifacts.

The replacement metric starts immediately before each candidate's client
input path and stops only after byte-equal authoritative output for that
pending trial is accepted. Wrong bytes, unexpected acknowledgements, send
errors, missing callbacks, zero samples, and timeouts are hard failures.

| Authoritative pooled result (600 each) | everudp | zmosh 0.5.9 | ratio | Frozen maximum | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| p50 | 456 us | 357 us | 1.277 | 1.10 | FAIL |
| p95 | 21,315 us | 60,689 us | 0.351 | 1.15 | PASS |

The stratified 20,000-replicate bootstrap gave a p50 ratio 95% interval of
1.214-1.338 and a one-sided upper-95 ratio of 1.328. The p95 interval was
0.337-0.423 with an upper-95 ratio of 0.423. Thus both the point and
conservative p50 rules fail. The independent 30-trial loss5 control agrees:
everudp/zmosh p50 was 462/363 us (ratio 1.273).

The hardened verifier checked the live clean checkout, freshly built artifact
hashes, complete inventories, controls and parity analyzer re-execution with
byte-identical output, receipt-to-child hash relations, raw oracle derivation,
and reachability derivation. It then failed closed at the registered
performance rule with `control matrix zmosh point rule failed`. The sealed
`terminal-verdict.json` therefore records
`requested_zmosh_parity_proven=false` and `decision=NOT-BUILD`.

## Frozen benchmark execution

The authoritative control cells ran 30 stop-and-wait
keystroke-to-authoritative-echo
trials over one netns/veth pair with symmetric, seeded netem. Every
candidate waited behind the same READY/GO barrier before the measured
workload. everudp and zmosh samples cover real PTY execution; Mosh samples
are pcap-derived authoritative echo arrivals; OpenSSH and everssh samples
are PTY-observed echoes guarded by a remote READY banner. The complete
matrix contains 1,920 positive raw samples across eight conditions and eight
candidates, including UDP/QUIC prediction-off controls.

| Cell | everudp UDP p50/p95 us | everudp QUIC p50/p95 us | zmosh p50/p95 us | everssh p50/p95 us | Mosh p50/p95 us | OpenSSH p50/p95 us |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 0% loss | 389 / 728 | 738 / 1,112 | 376 / 583 | 14,654 / 16,856 | 9,892 / 10,280 | 2,865 / 21,533 |
| 1% loss | 396 / 611 | 563 / 973 | 335 / 737 | 3,070 / 21,034 | 9,840 / 10,405 | 17,983 / 19,968 |
| 5% loss | 462 / 21,311 | 566 / 21,841 | 363 / 348,882 | 4,103 / 22,148 | 9,917 / 110,290 | 2,715 / 189,807 |
| 10% loss | 590 / 21,763 | 617 / 22,059 | 352 / 842,509 | 16,104 / 50,981 | 10,072 / 110,300 | 17,495 / 267,198 |
| 25% loss | 801 / 85,158 | 683 / 85,250 | 513 / 3,091,557 | 35,214 / 187,814 | 10,124 / 171,794 | 207,652 / 863,277 |
| 5% + 25 ms jitter | 50,844 / 58,759 | 51,723 / 71,082 | 51,109 / 154,337 | 69,325 / 135,648 | 58,679 / 67,381 | 65,650 / 134,156 |
| 5% + 50 ms jitter | 100,016 / 123,307 | 100,191 / 121,275 | 100,180 / 328,157 | 157,028 / 357,214 | 60,942 / 205,158 | 162,527 / 275,609 |
| 5% + 2% reorder | 2,542 / 23,888 | 2,565 / 23,811 | 2,428 / 393,066 | 19,014 / 40,442 | 12,055 / 112,317 | 20,383 / 41,784 |

These are authoritative remote echoes, so prediction on/off is expected to
have the same transport target and neither mode consistently wins. Local
speculative paint latency is validated by the correction oracle instead.
Mosh remains a separate control, not a zmosh proxy.

## Correctness oracle

The opaque byte self-comparison has been replaced. The final exact-SHA gate
at `7d4a43244f0287dddd3d01231994b375f2113c0e` ran 30 complete matrices
through real PTYs, including a real tmux 3.7c client. Authoritative PTY output
was independently rendered with the pinned MIT-licensed vt100 0.16.2 terminal
model. Predicted bytes were first painted into a persistent replica; divergent
authority then reconciled the state, redrew that same replica, and captured
the corrected grid. The oracle compares
dimensions, cursor, every cell, foreground/background and text attributes,
wide cells, wrapped rows, alternate-screen state, and cursor visibility.

All 30 echo, mismatch-correction, duplicate/reorder, full-screen, resize,
tmux, no-echo, and epoch-reset/resync matrices matched. Correction convergence
p95 was 293 us against the frozen 300,000 us ceiling; timing includes
reconciliation, full redraw, and corrected-grid capture. Each run applied nine
persistent predictions and exercised five visible corrections. Password
prediction displays were zero. The state model buffers future acknowledgements,
commits authoritative output in sequence, rejects unsent acknowledgements,
suppresses duplicates, and clears the old generation on epoch reset.

## Reachability

The final gate ran from clean source commit
`7d4a43244f0287dddd3d01231994b375f2113c0e` and tree
`47cdeea34120cad4b88b991f4a8098f4d349ee5c`. Each available UDP environment
ran twenty independent one-association client/server processes. The four
Linux namespace NATs have distinct mapping/filter rules plus behavioral
probes: full cone accepted the same endpoint, another port on the same host,
and another host; restricted cone rejected the other host; port-restricted
cone accepted only the opened endpoint; symmetric NAT assigned the two
destinations external ports in disjoint 40001-45000 and 50001-55000 ranges.

| Environment | Result | Frozen threshold |
| --- | --- | --- |
| direct IPv4 | 20/20 PASS | >=19/20 |
| direct IPv6 | 20/20 PASS | >=19/20 |
| full-cone NAT | behavior PASS; 20/20 flows | >=19/20 |
| restricted-cone NAT | behavior PASS; 20/20 flows | >=19/20 |
| port-restricted-cone NAT | behavior PASS; 20/20 flows | >=19/20 |
| symmetric NAT | destination-specific mapping PASS; 20/20 flows | >=18/20 |
| ZeroTier, badger to bugger | 20/20 PASS | >=18/20 |
| UDP black hole | 20/20 exact diagnosed failures in 2,012-2,018 ms | 20/20 below 3,000 ms |
| everssh fallback after blocked UDP | exactly 1 invocation, 1/1 PASS | exactly one successful transition |
| Tailscale fleet inventory | UNAVAILABLE: missing on badger/bagger, stopped on bugger | no comparison claim |

The ZeroTier row used separate hosts and matching spike-binary hashes over
their `zt3middjio` interfaces. The blocked path drops at the server input
boundary, so client sends succeed and the exact
`everudp-spike: UDP association handshake timed out` diagnostic comes from
the bounded authenticated-handshake retry loop. It is followed by one, and
only one, successful invocation of the existing everssh fallback to bugger.
Raw attempt ledgers, namespace addresses/routes, firewall rules, behavioral
probe output, peer identities, binary hashes, fleet inventory, aggregate
receipt, and a verified `SHA256SUMS` manifest are archived under the final
exact-SHA evidence directory named below.

The 6.373 s total-loss gate produced three bounded, diagnosed failures and
recovered a fresh flow on the first attempt, 216 ms after path restoration.
Session-level
5-minute outage continuity remains proven by the production everssh v2
B1 gate, not by this disposable spike.

## Substrate equivalence record

- Repaired authenticated core: a full 32-byte bootstrap secret authenticates
  one random nonzero association ID and fresh client/server randomness. HKDF
  derives separate client-to-server and server-to-client roots; per-epoch
  AES-256-GCM keys and nonce prefixes rotate every 1,048,576 packets.
- Replay and roaming: the 64-packet replay window mutates only after valid
  authentication. Only a packet carrying the association traffic key may move
  the server's peer address. Unit and loopback integration gates cover forged
  hellos/tags/high counters, duplicate packets, rotation-boundary reordering,
  authenticated roaming, and exactly-once PTY execution after retransmission.
- MTU: encoders fail closed above the 1,024-byte payload cap, and maximum
  encrypted request and response frames fit the 1,200-byte ceiling.
- Amplification: the server accounts received and sent bytes with a bounded
  per-association budget; the echo workload cannot send unearned bytes.
- Resource closure: all candidate processes stayed below 128 MiB RSS, 5 CPU
  seconds per 30-trial cell, and 65,536 client-interface bytes per trial. The
  standalone server used 0.00 CPU seconds and sent zero packets while idle;
  10,000 invalid 1,200-byte datagrams elicited zero responses, grew RSS by
  132 KiB, and did not prevent the next legitimate association.
- Remaining production gap: the executable still uses a public benchmark
  fixture instead of a real one-use secret provisioning channel and serves one
  disposable association rather than a managed multi-user service.
- Recovery: 20 ms fixed stop-and-wait retransmission in this spike; noq
  retains its own loss-recovery machinery. This is the dominant documented
  substrate difference and the most likely production-hardening cost.
- Congestion control: none in the spike beyond stop-and-wait; production
  everssh inherits noq's QUIC congestion control.

## Production candidates evaluated for D1

`vte` (Apache-2.0/MIT) provides a parser without a grid; `alacritty_terminal`
(Apache-2.0/MIT) and `wezterm-term` (MIT) provide complete grids. A future
production everudp should reuse one of those licensed models rather than
the spike's minimal line model.

## Retained evidence

The authoritative terminal evidence is tracked under
`docs/release-evidence/20260905-everudp/final-7d4a432/`.
`FINAL_SHA256SUMS` covers all 1,248 component files: fresh build artifacts and
provenance, 1,920 raw control observations, 1,200 raw parity observations,
resource and outage receipts, all 30 raw persistent-grid oracle runs, and all
reachability attempts. `terminal-verdict.json` binds the component inventories
and records the failed frozen p50 rule. `closure.console.stderr` preserves the
hardened verifier's expected fail-closed rejection.

The older `final-9083ef0` directory is retained as rejected round-1 review
provenance. Its recorded PASS must not be cited as evidence of parity.
