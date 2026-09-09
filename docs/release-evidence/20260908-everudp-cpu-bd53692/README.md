# Production CPU samples — derived diagnostic, not qualification

Runtime: `bd53692a23e498408f55ee30b03309017a923a4c`, ordinary `cli` release.
Parser/correlation checkpoint: `69b19f94b739d23e0494931261c1990323c228b9`.
Bead: `eversh-5fc.60`. No runtime change or performance PASS is selected.

One predeclared 0%-loss block, seed 19000001, ran 600 trials per implementation
in everudp/UDP-zmosh/QUIC-zmosh order. All 1,800 responses passed the exact-byte
oracle. During everudp, 45 seconds of process-scoped user/kernel CPU sampling
ran at 4,999 Hz. No other agent, build or analysis ran during measurement.
These profiled timings are not qualification results.

The collector finished the benchmark but incorrectly rejected its profile:
the substring `LOST` matched symbols such as `detect_lost_packets`. The original
INVALID receipt and collector are retained unchanged. This directory is a
separate derived analysis, not a rewritten successful collector receipt.
The strict decoder accepts only complete sample records and rejects every
unrecognized record, including lost-event notifications. All 2,136 records
parsed, with empty decoder stderr. Process generations, executable inode,
thread sets, affinity, time namespace and boot identity were checked; event
attributes confirm monotonic clocks and no inheritance.

Privileged offline decoding resolved symbol names for all 811 kernel samples. Earlier ordinary
user decoding produced unknown kernel symbols; that was a decoding-permission
limitation, not absent samples. No new capture was needed.

The common first/last per-process sample interval covers 445 complete public
keystroke windows; 155 edge/outside windows are excluded explicitly. Zero-sample
trials are retained. There are 1,752 samples within included windows and 384
outside. Counts below are leaf samples, not wall time or predicted savings:

| Role | User samples | Kernel samples | Leading user leaf |
|---|---:|---:|---|
| Client | 564 | 325 | `Connection::poll_transmit`: 53 |
| Gateway | 556 | 307 | `Connection::poll_transmit`: 37 |

Client `populate_packet` has 34 samples; gateway has 13. Kernel samples are
distributed across scheduling, locks, syscall and routing operations. Whole-
capture disassembly annotation spreads 101 `poll_transmit` samples across
many instructions; it does not identify a single removable operation and is
not interchangeable with the public-window histogram. Inlining, sampling skid,
sparse observations and profiling overhead prevent an exclusive attribution.
No optimization or repeated unchanged benchmark is justified by these counts.

`capture/` contains only selected original files, each checked against the
unchanged original inventory. It is deliberately not a complete capture copy.
The raw perf file remains private at `/tmp/everudp-production-cpu-bd53692/`;
its hash remains in `original-SHA256SUMS`. Exported sample rows omit instruction
addresses and binary paths. No stacks, registers, terminal payloads or argv
were requested. The outer inventory seals the derived files.

From this directory, reproduce with `python3 -B analyze.py` and verify with
`sha256sum -c SHA256SUMS --quiet`. The analyzer imports the repository helpers;
run from this commit or a descendant with matching `helper-hashes.json` inputs.
Compare its JSON with `analysis.json`. An independent Luna audit verified the
counts and interpretation; its helper-pinning caveat was repaired before sealing.
Eight parser/correlation tests passed. Reliability, security and performance
qualification remain outstanding; the latest frozen performance receipt is FAIL.
