# Idle CID preparation: no adoption

Bead eversh-5fc.68. Exact source2cab2cc2, resolved full source/tree and binary
hashes in builds/{A,B}/provenance.json. Both clean release builds passed.
A enables cli,application-task-spike,stream-delivery-spike. B adds only
packet-preparation-spike, which avoids local CID sizing when no NEW_CONNECTION_ID
is pending. All these experiments remain disabled by default.

The preregistered uninstrumented schedule was A,B,B,A, 200 trials per candidate
per block, 0% loss, seeds212500001..004, 100ms gaps, CPUs40,42,44,46. Candidate
orders were E/U/Q, Q/E/U, U/Q/E, E/Q/U. The exact runner is retained under
measurement/frozen-schedule.sh, SHA256
2bcee89230c45eda6e674549f2ca80c186360416e2cf007286afb56e458e186b.
It verifies source, features, complete build seals and byte identity of all five
reused control/fixture binaries before timing. No builds, agents or analysis ran
during measurement. All four blocks passed without retries; all2400 responses
passed the exact-transcript oracle. Every original block seal reverified.

Nearest-rank p50/p95, microseconds:

| Block | Mode | everudp | UDP zmosh | QUIC zmosh |
|---|---|---:|---:|---:|
| 0 | A | 587 / 960 | 438 / 849 | 648 / 1254 |
| 1 | B | 577 / 901 | 401 / 834 | 604 / 1034 |
| 2 | B | 610 / 977 | 395 / 702 | 639 / 1208 |
| 3 | A | 584 / 942 | 446 / 872 | 658 / 1130 |
| Pooled | A | 584 / 953 | 443 / 863 | 651 / 1209 |
| Pooled | B | 595 / 939 | 399 / 801 | 617 / 1156 |

The guard did not demonstrate a useful median improvement. The candidate's
pooled median is about1.9% higher, while p95 is about1.5% lower. Control drift is
substantial: the matched UDP median differs443 versus399us. These two blocks per
mode are descriptive, not a proven regression or improvement, and normalized
ratios do not eliminate temporal confounding. No larger qualification run or
production adoption is selected from this result. The frozen release thresholds
are unchanged; production performance remains FAIL.

Implementation validation passed388 protocol tests,35 everudp library tests,
16 build-option tests and strict combined-feature Clippy. Additional candidate
integration tests passed32 with one explicit installed-application qualification
ignore: admission5, handshake3, process13, replay4 and transport7. These are not
the complete exact-SHA release gates. The unchanged nonempty CID loop continues
to issue/retire IDs and suppress discarded-path IDs under those tests.

Run `python3 -B analyze.py` in this directory to reproduce the table from raw
responses and verify manifest/source/control identity. Binaries are omitted;
candidate and original control provenance are retained. The outer seal covers
the retained files; raw network-counter whitespace is intentionally preserved.
