# Initial-offer experiment — INVALID matched-control identity

All eight preregistered blocks completed, reporting 3,200 correct responses.
The matched A/B analyzer rejected the experiment before numerical analysis:
the independently built zmosh controls do not have identical artifact hashes.
No latency gate PASS, causal speedup, or production adoption is claimed.

Baseline runtime: `1bdd3528bc4d257a1f33adc96b1fb48a97a777d9`.
Candidate runtime and execution harness: `f90c878dfda16c86b7bd04ee255889450eedb859`.
Both provenance files identify frozen zmosh source
`dfc8395b5edcd237bf82712fbde879c6e8be7dfa`, with the same release build command.
The PTY fixture executable hashes match; the zmosh executable hashes do not.
See `analysis.json` for both exact hashes and the failure receipt.

The first observed binary difference is an embedded temporary build directory
in a source-file path (`/tmp/everudp-floor-build.t3czMb/` versus
`/tmp/everudp-floor-build.EKx5uL/`). There are 315 differing byte positions in
total. This observation does not establish that every difference is harmless;
the identity check is retained unchanged. The next experiment must reuse one
sealed control executable and preflight artifact equality before any trial.

## Recorded protocol

Each cell (0% and 5% symmetric loss) has four 200-trial blocks in runtime order
baseline, candidate, candidate, baseline. Candidate order within blocks is
everudp-first, zmosh-first, everudp-first, zmosh-first. Seeds are
980701–980704 and 985701–985704; tracing is off throughout. CPU affinity is
40,42,44,46 with performance governors and 100 ms trial gaps.

The exact candidate build completed successfully. Before the build, 25 example
tests, 67 focused library/protocol/transport tests, strict native clippy, legacy
example check and 116 Python tests (two skipped) passed. Independent read-only
review found no remaining concrete send-path blocker. These checks do not
substitute for the failed experiment or production qualification.

## Reproduce the failure

Run `sha256sum -c SHA256SUMS --quiet` in this directory. Then run
`PYTHONDONTWRITEBYTECODE=1 python3 -B analyze.py .`.
Expected: nonzero exit at the cross-build control artifact equality assertion,
before any numerical result is printed. `analysis.json` is the explicit failure
receipt, not generated successful analyzer output.

Original block seals and qdisc whitespace are retained. Baseline and candidate
provenance record their actual binaries separately; no artifact or receipt was
rewritten to hide the mismatch. Original raw artifacts remain in `/tmp`.
