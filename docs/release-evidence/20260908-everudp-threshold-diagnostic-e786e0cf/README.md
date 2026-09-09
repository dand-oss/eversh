# Residual latency after ACK-threshold screening: diagnostic only

Bead eversh-5fc.67. Clean source e786e0cf3ff9a1ff41177cd0f5ed56f69e3b490a.
Features: cli,path-packet-diagnostics,application-task-spike,
stream-delivery-spike,quic-ack-threshold-spike. Production defaults unchanged.
Build provenance and inherited frozen-control provenance are retained; no binaries.

Predeclared capture: 200 trials per implementation, zero loss, seed 212800001,
order everudp,zmosh-udp,zmosh-quic, CPUs 40,42,44,46, 100ms intertrial gap,
all three tracing flags enabled. No concurrent builds, agents or analysis during
capture. All 600 exact-response checks passed. All 200 everudp operations join
through path, packet, stdin and protection analyzers; no samples are excluded.

| Independent wall-clock boundary | Median microseconds |
|---|---:|
| Public input send to client stdin ready | 86.2395 |
| Public input send to input queue | 96.4025 |
| Input reservation to protection start | 37.6395 |
| Input protection | 4.165 |
| Input send poll to gateway userspace receive | 92.2775 |
| Input STREAM receipt to application | 28.281 |
| Input prepared to accepted | 9.8075 |
| Input accepted to gateway output queued | 87.7835 |
| Output protection | 1.3705 |
| Output send poll to client userspace receive | 31.509 |
| Output STREAM receipt to application | 5.745 |
| Output staged to stdout accepted | 9.948 |

The 199 complete send-to-next-send windows contain 404 client packets and 599
gateway packets. Each side sends 199 control-STREAM packets; client input uses
199 packets and gateway output uses 199. The remaining 6 client and 201 gateway
packets contain no STREAM frames. That does **not** establish that they are pure
ACK packets: the recorder does not decode every frame type. The last trial is
excluded only from intertrial counts, not the 200-operation delivery analysis.

These are instrumented, independent, nonadditive wall-clock medians, not exclusive
CPU costs. Send-poll-to-userspace-receive includes kernel and scheduling latency;
it is not a wire transit measurement. There is no paired diagnostic trace for
original UDP zmosh here, so these intervals do not attribute the comparative gap
to QUIC alone. Crypto remains too small to explain that gap by itself.

The next concrete audit is the gateway path between accepting input and queuing
PTY output, including control ACK flushing and readiness scheduling. ACKs must
remain after whole-operation acceptance. Do not drop acknowledgements or weaken
replay based on packet counts.

Reproduce from the repository root:

```sh
python3 -B docs/release-evidence/20260908-everudp-threshold-diagnostic-e786e0cf/analyze.py .
```

The analyzer uses the packet sidecar's `packet_transmit_accepted` event (not the
different I/O sidecar's `transmit_accepted`) and requires a nonzero count in every
complete window. The earlier temporary summary's zero transmit counts were an
analysis naming error, corrected before this archive. Raw capture is unchanged.

Status: DIAGNOSTIC, not qualification or adoption. The ordinary screening archive
20260908-everudp-threshold-e786e0cf still misses original UDP median parity.
Exact-SHA production performance, reliability, security and independent review
remain required.
