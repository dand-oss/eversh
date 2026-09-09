# Input scheduler attribution

DIAGNOSTIC ONLY. No performance PASS, production integration, or release approval.
Bead: `eversh-5fc.26`. Analyzer version: `b35097b91e1cdb40357e39ea1d6d2896e81b4af0`.

## Identity and scope

All captures reuse the sealed diagnostic binary built from
`04a04ed8c3156d943fc3584cfa92cd4483fa4bc8`, tree
`98418eabf0839088a97c0dba8e86af52efd10b2e`. They are NOT builds of the
later capture harness/analyzer commits. The runtime, dependencies, PTY benchmark,
and network harness source paths were compared against that build and unchanged.
ACK-inline and sender-readiness experiments remain disabled.

Three complete paired benchmark blocks are retained, each with 200 trials per
candidate, 100 ms gaps and 0% netem loss. All 1,200 responses passed the transcript
oracle. Scheduler capture covers a bounded ten-second subset, not every trial.

| Capture | Harness HEAD | Seed | Candidate order |
| --- | --- | --- | --- |
| scheduler-only | 23a3a82 | 91401 | everudp, zmosh |
| forward | 97e1815 | 91402 | everudp, zmosh |
| reverse | 99a168c | 91403 | zmosh, everudp |

Build provenance, raw benchmark inventories, safe scheduler/syscall event text,
capture commands and reproducible analysis are retained. Raw perf files remain
private temporary artifacts: perf also records process metadata through its dummy
event. No raw perf file or buffer address is included here. Read syscall events
contain counts, return lengths and descriptor numbers, never buffer contents.

## Results and exclusions

The scheduler-only capture has 99 included trials and 101 outside coverage.
Its directly computed median send-to-scheduling interval is 86.434 us; the
scheduled-to-read-marker interval is 24.393–24.503 us. The former is computed
per trial, NOT by adding independent stage medians.

Matched syscall capture medians, microseconds:

| Capture / candidate | Included / excluded | Scheduled to read entry | Read syscall | Send to scheduled |
| --- | --- | --- | --- | --- |
| forward / everudp | 98 / 102 | 22.4665 | 5.429 | 74.551 |
| forward / zmosh | 97 / 103 | 12.176 | 4.858 | 80.543 |
| reverse / everudp | 99 / 101 | 22.165 | 5.528 | 72.339 |
| reverse / zmosh | 97 / 103 | 12.762 | 5.330 | 75.995 |

The parser retains all trial rows with explicit exclusions. Inclusion requires
coverage of the complete public interval, one successful one-byte read on the
selected descriptor, and one waking/wakeup/switch-in chain before that read.
The clock-aligned marker analyzer also rejects events inside its uncertainty tail.
Malformed records, timestamp regressions, missing syscall pairs, wrong target PIDs,
and inconsistent public samples fail closed. These checks are unit tested.

The observed dispatch difference is roughly 9–10 us in both orders, not the
entire approximately 100 us input handoff. This is descriptive: scheduler load,
instrumentation and kernel paths remain confounders, and this is not an untraced
A/B of implementations. Do not treat the difference as a guaranteed recoverable
budget or claim a stdin-only runtime rewrite will pass the frozen floor gate.

## Trust limits and corrections

The forward and reverse perf attributes explicitly record CLOCK_MONOTONIC
(use_clockid=1, clockid=1). Captured boot/time-namespace identities match each
benchmark result. PID generation is checked before/after capture. Event filters
limit wakeups, switches and read syscalls to the selected client main thread.
Lost-event display was enabled; no lost records were emitted. The scheduler-only
capture was decoded again with lost-event display and matched its original text;
perf debug checking reported zero misordered timestamps.

Only the reverse capture records before/after descriptor identities, TID sets,
and affinity. It proves fd 13 is an everudp stdin alias and zmosh fd 0 is stdin;
both clients had one thread and unchanged affinity. Forward fd 13 mapping is
temporal/code evidence only, not a retrospectively captured descriptor identity.
Scheduler-only capture did not record namespace identity contemporaneously;
its report retains external verification requirements. Per-event CPU IDs are
not exported; no CPU-migration or exclusive CPU-cost conclusion is made.

The first attempted forward preflight refused a dirty worktree before starting
any benchmark. After committing the analyzer, collection completed normally.
Reverse analysis initially rejected a valid task name containing a space
(`CPU 3/KVM`). Fix b35097b corrects the bounded task-name grammar, with a
regression test. Original capture data was reanalyzed, not rerun or discarded.

## Interpretation and next action

This closes the narrow question of whether the whole local handoff can be
attributed to userspace dispatch: it cannot. A stdin-only rewrite is not selected
on this evidence. Any broader single-owner candidate must preserve the pinned
QUIC engine, authentication, timers, bounded work and I/O error handling, and
demonstrate the unchanged untraced floor gates before production integration.
Protocol API feasibility alone does not supply the missing performance margin.

Run `python3 -B analyze.py` from this directory and compare stdout with
analysis.json. It uses the repository analyzers; reproduce with their recorded
version. SHA256SUMS seals all files including nested original block inventories.
This evidence does not certify production reconnect, delivery, recovery,
observers, security, or performance against either release baseline.
