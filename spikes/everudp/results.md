# everudp Stage D spike result

Status: complete (2026-09-04) | Owner: `eversh-2zq` | Preregistration:
frozen in the bead before implementation.

## Decision: NOT-BUILD production everudp now

Available evidence does not meet the preregistered BUILD rule. The
encrypted-UDP substrate is viable and dramatically faster than Mosh's SSP
transport under loss, but the two decisive controls could not be evaluated
as registered:

1. The everssh-v2 latency comparison is UNAVAILABLE in this harness: the
   outer-ssh PTY driver initially timed local canonical-mode echo (invalid
   sub-millisecond samples), and after adding a remote READY banner the
   everssh chain no longer established inside the one-shot netns harness
   (empty transcript). Because BUILD requires a >=50% median and >=33% p95
   reduction versus everssh v2, that unmet measurement blocks BUILD.
2. The pinned zmosh control is UNAVAILABLE: zmosh 0.5.9's installed binary
   exposes an interactive attach/serve model; local attach bypasses UDP via
   the ZMX unix socket, `attach -r` requires an interactive SSH bootstrap,
   and no source repository URL is discoverable from the Zig binary or local
   metadata for a pinned-source build. No zmosh-specific comparison is
   claimed.

Mosh 1.4.0 — the same SSP transport family zmosh wraps — was measured
successfully and is reported as the nearest available control.

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

At the preregistered 5%-loss cell, everudp-UDP is 20.2x faster than Mosh at
the median (484 µs versus 9,776 µs) and 12.7x faster at p95 (844 µs versus
10,727 µs). Correction-convergence p95 is 844 µs, far below the frozen
300 ms ceiling; even at 25% loss it remains 85.9 ms.

## Correctness oracle

`everudp-spike oracle` passes exact authoritative-state equality for echo,
resize (`CSI 8` sequences), full-screen replay (`CSI 2J`/home draw), and a
tmux-style alt-screen workload. The no-echo/password policy recorded exactly
zero predicted displays before and after reconciliation.

## Reachability

Twenty one-flow UDP attempts per environment:

| Environment | Result | Frozen threshold |
| --- | --- | --- |
| direct IPv4 | 20/20 | >=95% PASS |
| direct IPv6 | 20/20 | >=95% PASS |
| full-cone NAT | 20/20 | >=95% PASS |
| restricted-cone NAT | 20/20 | >=95% PASS |
| port-restricted-cone NAT | 20/20 | >=95% PASS |
| symmetric NAT | 20/20 | >=90% PASS |
| ZeroTier (zt3middjio) | 20/20 | >=90% PASS |
| UDP blocked | 20/20 bounded diagnosed failures | PASS |
| Tailscale | UNAVAILABLE: no daemon/interface | no claim |

The one 5 s outage observation produced bounded failures throughout loss
and recovered a new flow 138 ms after path restoration. Session-level
5-minute outage continuity remains proven by the production everssh v2
B1 gate, not by this disposable spike.

## Substrate equivalence record

- AEAD/KDF: AES-256-GCM per packet versus noq/rustls TLS 1.3.
- Nonces: 4-byte session prefix + 64-bit counter, disjoint client/server
  half-spaces; 64-packet anti-replay window.
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
