# everudp Stage D spike result

Status: latency, authenticated-substrate, terminal-oracle, and
available-environment reachability repairs pass; bead remains open |
Owner: `eversh-2zq` | Preregistration:
frozen in the bead before implementation.

## Decision: NOT-BUILD production everudp now (latency parity passes)

Available evidence does not meet the full preregistered BUILD rule. The
optimized spike now proves end-to-end PTY latency parity with zmosh under
the frozen 5% loss condition, including a conservative bootstrap
equivalence bound. Production remains NOT-BUILD because the substrate is
not production-equivalent to the QUIC control, Tailscale is unavailable on
the test fleet, resource and congestion behavior are not qualified, and the
decisive everssh comparison remains unavailable:

1. The everssh-v2 latency comparison is UNAVAILABLE in this harness: the
   outer-ssh PTY driver initially timed local canonical-mode echo (invalid
   sub-millisecond samples), and after adding a remote READY banner the
   everssh chain no longer established inside the one-shot netns harness
   (empty transcript). Because BUILD requires a >=50% median and >=33% p95
   reduction versus everssh v2, that unmet measurement blocks BUILD.
2. Correction (2026-09-04 review): the pinned zmosh control IS available.
   The local source checkout at `/home/appsmith/asv/ports/repo/zmosh`
   contains version 0.5.9 at commit `dfc8395...`; it was built with Zig
   0.15.2 and measured headlessly through its documented C UDP client. The
   original "source not discoverable" statement was false and is superseded.
   zmosh uses its own XChaCha20-Poly1305 UDP protocol and is NOT Mosh SSP;
   the earlier Mosh-as-family substitution is withdrawn.

## Direct zmosh 0.5.9 head-to-head (updated decision evidence)

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

### Hardened clean paired equivalence campaign (authoritative latency result)

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

This proves the narrow claim requested by the spike: **the authenticated
everudp prototype is at least as fast as zmosh 0.5.9 on the matched direct
5%-loss end-to-end PTY workload**. It does not erase the independent
Tailscale-availability, resource, congestion, provisioning, and
everssh-control blockers that keep the production decision at NOT-BUILD.

## Frozen benchmark execution

All latency cells ran 30 stop-and-wait keystroke-to-authoritative-echo
trials over one netns/veth pair with symmetric netem. everudp samples are
in-process monotonic timestamps; Mosh samples are pcap-derived authoritative
echo arrivals at the client interface; SSH samples are PTY-observed echoes
guarded by a remote READY banner. Prediction is a display property, so
on/off cells intentionally isolate the same transport metric.

| Cell | everudp-UDP median/p95 µs | everudp-QUIC median/p95 µs | Mosh median/p95 µs | SSH median/p95 µs |
| --- | --- | --- | --- | --- |
| 0% loss | 379 / 578 | 1,121 / 2,159 | 9,905 / 10,368 | 14,535 / 16,836 |
| 1% loss | 481 / 831 | 1,178 / 2,013 | 9,650 / 9,763 | 6,752 / 9,930 |
| 5% loss | 484 / 844 | 1,448 / 3,137 | 9,776 / 10,727 | 14,186 / 240,714 |
| 10% loss | 510 / 21,969 | 1,261 / 23,095 | 9,746 / 159,740 | 15,809 / 197,997 |
| 25% loss | 588 / 85,946 | 2,267 / 85,185 | 10,862 / 231,435 | 195,154 / 1,136,516 |
| 5% + 25 ms jitter | 50,812 / 65,096 | 51,483 / 73,525 | 59,507 / 69,097 | 66,748 / 137,742 |
| 5% + 50 ms jitter | 101,843 / 118,138 | 104,082 / 131,601 | 115,964 / 251,635 | 149,335 / 262,162 |
| 5% + 2% reorder | 2,546 / 23,228 | 3,419 / 23,828 | 11,795 / 160,820 | 10,920 / 44,399 |

Mosh remains a separate control, not a zmosh proxy: at 5% loss everudp-UDP
is 20.2x faster at the median (484 µs versus 9,776 µs). The Mosh parser
correlates packet direction without payload semantics, so this is retained
only as an upper-bound transport comparison.

## Correctness oracle

The opaque byte self-comparison has been replaced. The exact-SHA gate at
8a806a15955b838c98add5a7b74a1e813f8b9494 ran 30 complete matrices
through real PTYs, including a real tmux 3.7c client. Authoritative PTY output
and the predicted/reconciled stream were rendered by separate instances of
the pinned MIT-licensed vt100 0.16.2 terminal model. The oracle compares
dimensions, cursor, every cell, foreground/background and text attributes,
wide cells, wrapped rows, alternate-screen state, and cursor visibility.

All 30 echo, mismatch-correction, duplicate/reorder, full-screen, resize,
tmux, no-echo, and epoch-reset/resync matrices matched. Correction convergence
p95 was 5 us against the frozen 300,000 us ceiling, and password prediction
displays were zero. The state model now buffers future acknowledgements,
commits authoritative output in sequence, rejects unsent acknowledgements,
suppresses duplicates, and clears the old generation on epoch reset.

## Reachability

The repaired gate ran from clean source commit
`9a9e56b281a2e52c20aa6f12cfffb5f2d4087e19` and tree
`227261f6e9751cd633d198bbd71efafbe4e1cce4`. Each available UDP environment
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
| UDP black hole | 20/20 exact diagnosed failures in 2,012-2,020 ms | 20/20 below 3,000 ms |
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
receipt, and a verified `SHA256SUMS` manifest are archived under
`docs/release-evidence/20260904-everudp/reachability-repaired/`.

The one 5 s outage observation produced bounded failures throughout loss
and recovered a new flow 138 ms after path restoration. Session-level
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

Sanitized JSON/TSV receipts are tracked under
`docs/release-evidence/20260904-everudp/`. The authoritative parity
aggregate is `parity-hardened/analysis.json`; its six block manifests bind
source, tree, candidate binaries, seeded topology, raw samples, result hashes,
and before/after qdisc counters. `parity/analysis.json` retains the earlier
pre-hardening campaign. `oracle.json` is the exact-SHA 30-run terminal-grid
receipt.
Other raw logs remain under ignored `target/qualification/everudp/`.
