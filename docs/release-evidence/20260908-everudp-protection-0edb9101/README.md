# Packet protection attribution, not qualification

Bead eversh-5fc.67. Clean source0edb91019eb8156c66d6aace80776d9868d80eea,
binary86a846cdd84671807cac4e5f4c84f1cda7d29d55beed4d4536b15e7887d873ba.
Features cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike.
All experimental features remain off by default. Candidate and original shared
control provenance are retained; binaries are not included.

Predeclared capture: 200 trials/candidate, 0% loss, seed212400001,
order everudp,zmosh-udp,zmosh-quic, CPUs40,42,44,46, 100ms gaps, all three
trace flags enabled. Exact build and original capture seals verified. No builds,
agents or analysis overlapped measurement. All600 exact responses passed on the
first run. The strict protection analyzer accepts all200 everudp rows in both
directions, with no exclusions or timestamp-proximity packet matching.

| Wall-clock boundary | Input median us | Output median us |
|---|---:|---:|
| Operation reservation to protection start | 43.2375 | 10.183 |
| Packet and header protection | 5.2385 | 1.3745 |
| Protection end to built marker | 0.464 | 0.176 |

Protection markers enclose `PartialEncode::finish`, including packet and header
encryption, and are tied to connection/cookie/packet-number/number-space.
The start/end pair must be unique, ordered and inside the exact operation's
reservation-to-completion-packet construction interval. Missing, duplicate,
wrong-identity and reversed pairs fail analysis. Context is send-only and the
feature-gated recorder retains no payload, address, key or credential.

These are independent, nonadditive wall-clock medians, not exclusive CPU costs.
The intervals include recorder overhead and may include descheduling. The new
hooks have not been qualified as zero overhead. This is not an uninstrumented
comparison or a claim that crypto can be removed. The result does not support
crypto-backend replacement as the main latency fix: most of the measured input
construction interval precedes encryption. That earlier interval still includes
task dispatch as well as protocol selection and frame assembly.

Reproduce from the repository root:

```sh
python3 -B crates/everudp/tests/net/analyze_packet_protection.py docs/release-evidence/20260908-everudp-protection-0edb9101/capture/everudp
```

Implementation validation: 54 combined-feature everudp library tests, five
isolated noq-proto diagnostic tests, 31 Python tests, strict combined-feature
Clippy, and 31 default-feature everudp library tests passed. Vendor tests used
an isolated source copy because the vendored package is not a workspace member;
the workspace configuration was not modified. The new analyzer's four tests
went RED on missing module, then GREEN. These checks and this capture do not
replace exact-SHA reliability/security/performance qualification. The production
performance receipt remains FAIL.
