# ACK inline-storage experiment: NOT ADOPTED

Measured clean candidate `dc019b8ecf41279e1c33c223d9632562962fb223`.
Bead `eversh-5fc.23`. This is a negative floor experiment, not production
qualification. The opt-in feature remains disabled by default.

Eight preregistered blocks completed with 3,200 measured responses and zero
transcript failures. Each candidate has 200 trials per block, 100 ms gaps,
two reversed blocks per variant and loss cell. Seeds 90601–90604 cover 0%
loss, 90701–90704 cover 5%. Block one runs control then inline, floor then
zmosh; block two reverses both. Tracing and the readiness experiment are off.
All blocks use identical frozen zmosh UDP and compiled PTY controls. Original
build provenance and the separately sealed common-control derivation remain.

## Result

| Loss | Variant | Floor p50 us | zmosh p50 us | Ratio | Packet-attempt ratio |
| --- | --- | ---: | ---: | ---: | ---: |
| 0% | Control | 383.5 | 384.5 | 0.997399 | 0.995663 |
| 0% | Inline | 399.5 | 369.5 | 1.081191 | 0.997519 |
| 5% | Control | 387 | 375 | 1.032000 | 1.030861 |
| 5% | Inline | 402 | 406 | 0.990148 | 1.039053 |

Pooled medians use 400 observations per candidate/variant/loss cell.
Both inline cells miss the unchanged 0.90 p50 ceiling. Every block and pooled
cell satisfies the 1.60 packet-attempt ceiling. Packet counts were recomputed
from the raw root-netem sent-plus-dropped counters and matched the manifests.
Luna independently recomputed the pooled results and confirmed the conclusion.

No causal speedup or slowdown is established: control timings also vary by
block/order, and the two implementations are not paired per trial. This change
does not supply the required floor margin and is not adopted. There is no
reason to proceed to production integration or use another diagnostic run to
override this miss. Runtime allocation reduction was not separately measured;
the protocol tests establish representation behavior, not latency savings.

The feature uses inline single-path ACK bookkeeping with the original map
fallback for multiple paths. Protocol library suites passed with feature on
(391 tests) and off (388), alongside integration checks. Measured x86_64
SentPacket layout grows 112 to 120 bytes; net memory improvement is unclaimed.
The experiment changes no default behavior, protocol version, security,
congestion or ACK requirements. Full production gates remain outstanding.

## Reproduce and verify

From this directory, run:

```sh
python3 -B analyze.py measurements --net ../../../crates/everudp/tests/net --provenance-dir build-provenance
sha256sum -c SHA256SUMS
```

The analyzer checks exact block inventory, candidate identity, seeds/order,
features, common controls, public timing boundaries and raw packet accounting.
It emits DIAGNOSTIC, not production PASS. The receipt records the failed
performance criterion explicitly. Outer checksums include nested block seals;
raw counter whitespace is preserved intentionally.
