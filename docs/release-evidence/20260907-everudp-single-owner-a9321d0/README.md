# Single-owner floor: NOT ADOPTED

Candidate `a9321d0060cc726b27fcde89ca7d31e9519c5425`, bead `eversh-5fc.28`.
This is a failed disposable floor experiment, not production qualification.
The single-owner feature remains off by default. No production integration is authorized.

Four preregistered blocks completed, each with 200 trials per implementation,
100 ms gaps, reversed implementation order, and the frozen zmosh UDP control.
There were 1,600 measured responses and zero transcript failures. Separate
20-trial process checks at 0% and 5% loss passed but are not included here or
counted toward the quantitative result.

| Symmetric loss | Floor p50 µs | zmosh p50 µs | Ratio | Packet-attempt ratio |
| --- | ---: | ---: | ---: | ---: |
| 0% | 392 | 412.5 | 0.950303 | 1.002481 |
| 5% | 433.5 | 434 | 0.998848 | 1.081192 |

Both cells miss the unchanged p50 ratio ceiling of 0.90. Every block and
pooled cell passes the 1.60 packet-attempt ceiling. The unchanged analyzer
reports quantitative FAIL and an INVALID overall receipt: native component
attribution is unavailable. Neither result can authorize production adoption.
Luna independently verified all four block seals, source/build/artifact
identities, seeds/order, pooled medians and raw packet counts and confirmed
the failed quantitative conclusion.

Only `cli,reliable-datagram-spike,floor-single-owner` was enabled. Diagnostics,
send-fast-path, and ACK inline-storage experiments were off. The combined
example rejects trace requests for this implementation. This run does not
establish a causal improvement relative to the legacy Tokio floor: it compares
the native candidate with frozen zmosh, not simultaneous native/legacy blocks.

The candidate preserves bootstrap, pinned TLS, admission, the v4 datagram
envelope and 2 ms application retry interval. It owns protocol/socket polling
and terminal I/O synchronously, with bounded turns and retained queue-blocked
datagrams. Native example tests and strict clippy passed before the build.
Real MTU/error injection, hostile traffic, extended resource/fairness checks,
and full production reconnect/security/performance gates remain outstanding.

## Reproduce

From this directory:

```sh
python3 -B analyze.py
sha256sum -c SHA256SUMS --quiet
```

The wrapper validates block identity, build provenance, seeds/order, sample
count, and raw root-netem sent-plus-dropped packet accounting, then executes
the archived unchanged analyzer. Original block seals and artifact hashes
are retained. No credentials or binaries are included.
