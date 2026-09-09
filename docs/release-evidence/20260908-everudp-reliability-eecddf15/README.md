# Full reliability PASS — not product acceptance

Tested source: `eecddf15f4d8eb72f0f887cc5ec6ac5bae614bc5`.
Tree: `a0a4cde8acdcd0e2ef45d750d1184d89a689d250`.
Ordinary, non-PGO executable SHA256:
`a70b52c3851e7723282ec4c79a85b6809057d475a04266e1c7520d40ea19dd04`.
Bead: `eversh-5fc.9`.

All 17 full network-reliability scenarios passed between
2026-09-08 16:40:44 UTC and 17:17:00 UTC. This was not a smoke run.
Total-loss durations were measured at 300 and 1,800 seconds; both resumed
without an output gap. Forced output overrun produced exactly one GAP and
preserved future output. Loss at 0/1/5/10/25%, jitter, reorder/duplication,
IPv6, MTU reduction, interface migration, process sleep/wake and cancellation
also passed. UDP-only proof recorded zero TCP packets during terminal traffic
and verified the process traces. Sleep/wake here is the harness's process
suspension test, not a claim of physical laptop suspend coverage.

The optional 12-hour soak was NOT_RUN. This is reliability evidence for the
specified source and binary, not for later diagnostic commits. It does not
replace security, application, performance or independent-review qualification.
The frozen original-UDP-zmosh performance gate remains FAIL.

`measurement/` preserves the complete original run, including both original
inventories and receipts. `runner.py` is the exact wrapper whose hash is bound
in the outer receipt; it verifies the clean source and executable before the
run, rechecks the executable afterwards, and validates the gate inventory.
The binary itself is not included. The path name of its build directory contains
`pgo-baseline`; this executable was built without PGO instrumentation or profile use.

Private-key and common credential-marker scans found no matches before archival.
Network captures and transcripts are from the isolated synthetic terminal fixture.
Original artifacts are retained byte-for-byte, including any raw-tool whitespace.

Verify the archive with `sha256sum -c SHA256SUMS --quiet`, then verify the
original inventories from `measurement/` and `measurement/gate/` separately.
