# everudp Stage D spike result

Status: partially repaired after FAIL review; bead remains open |
Owner: `eversh-2zq` | Preregistration:
frozen in the bead before implementation.

## Decision: NOT-BUILD production everudp now

Available evidence does not meet the preregistered BUILD rule. The spike
substrate achieved direct median parity with pinned zmosh 0.5.9, but it is
not security-equivalent to the QUIC control, its terminal oracle is not
independent, and the decisive everssh comparison remains unavailable:

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
and pinned zmosh 0.5.9 on the identical netns/veth topology. Both clients
measure keystroke-to-authoritative-echo at their client edge; everudp uses
its in-process timestamp and zmosh uses its C `output_cb`.

| Run | everudp median/p95 µs | zmosh median/p95 µs |
| --- | --- | --- |
| 1 | 522 / 21,703 | 581 / 61,090 |
| 2 | 496 / 22,102 | 492 / 810 |
| 3 | 434 / 21,971 | 469 / 61,050 |

Median parity holds in every run under the frozen rule (`everudp p50 <=
zmosh p50 * 1.10`): 522<=639, 496<=541, and 434<=516 µs. Aggregate medians
are statistically tied (496 vs 492 µs). p95 is bimodal in both systems
because a single recovered loss dominates the tail; on aggregate medians
everudp is lower (21,971 vs 61,050 µs), but run 2 violates the per-run p95
multiplier because zmosh happened to lose no tail packets. The defensible
claim is median parity, not p95 dominance. This satisfies the user's
"as fast as zmosh" question at the median while leaving production BUILD
unsupported by the everssh comparison below.

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

After the review repair, the state model explicitly distinguishes confirmed
predictions, corrections, and duplicate echoes; focused tests cover all
three plus no-echo safety and epoch reset. The CLI oracle checks opaque
byte equality on echo/resize/full-screen/tmux workloads. This is still NOT
the preregistered independent terminal-grid oracle and supports no
terminal-state correctness claim.

## Reachability

Twenty one-flow UDP attempts per environment. Post-review classification:
the NAT rows are transport smoke tests over one shared MASQUERADE base with
model-specific additions, not proofs of the four RFC NAT semantics; the
ZeroTier row binds and connects on one host and therefore exercises local
routing, not an overlay peer; the blocked row proves bounded exit-code
failure without checking the diagnostic or the everssh fallback transition.

| Environment | Result | Frozen threshold |
| --- | --- | --- |
| direct IPv4 | 20/20 | smoke PASS |
| direct IPv6 | 20/20 | smoke PASS |
| full-cone NAT | 20/20 | smoke only |
| restricted-cone NAT | 20/20 | smoke only |
| port-restricted-cone NAT | 20/20 | smoke only |
| symmetric NAT | 20/20 | smoke only |
| ZeroTier (one host) | 20/20 | local-route only |
| UDP blocked | 20/20 nonzero exits | bounded-failure smoke only |
| Tailscale | UNAVAILABLE: no daemon/interface | no claim |

The one 5 s outage observation produced bounded failures throughout loss
and recovered a new flow 138 ms after path restoration. Session-level
5-minute outage continuity remains proven by the production everssh v2
B1 gate, not by this disposable spike.

## Substrate equivalence record

- NOT equivalent: the bench repeats an eight-byte constant into a 32-byte
  key, uses a constant session prefix with process-reset counters, performs
  no KDF/authenticated key establishment/peer binding/key rotation, and
  updates its replay window before AEAD tag verification. A forged high
  counter could therefore displace legitimate traffic. These are spike
  shortcuts, not a production substrate.
- Positive-but-insufficient pieces: AES-256-GCM per packet; disjoint
  client/server nonce counter half-spaces within one process; 64-packet
  replay window shape; MTU ceiling and 1:1 echo cap.
- MTU: 1,200-byte ceiling and 1,024-byte payload cap.
- Amplification: 1:1 echo only.
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
`docs/release-evidence/20260904-everudp/`; raw logs remain under ignored
`target/qualification/everudp/`.
