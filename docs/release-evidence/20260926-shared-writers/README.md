# eversh 0.2.5 shared-writer qualification

Qualified on Badger with rustc 1.95.0. Runtime source: 894adb04;
later commits change tests, harnesses, and evidence only. Wire/ALPN and
everpty protocol versions remain unchanged.

## Artifacts

- Combined eversh SHA-256: `5e6f0a39afa161452be8cb8bf190a83c69e366a3ec96b0d475294c2cc2f65887`.
- Standalone everudp SHA-256: `739490cb16acc5bc579aa737a1e4e0e2f52b6474bb632601df432272c8e95a5d`.
- Fleet ever-tool SHA-256: `1ef1a6be1eef6f28e059fc4dbedbbf278e6ec564e4f117a513a1bc42d8c55a40`.
- Wrapper source: home repository commit d7c6d59d99d1ee5cd2cc9f372b122c35df1eec2b.

## Automated checks

- All-feature workspace: 771 tests passed, zero failed, three marked ignored.
  The terminal application qualification was run separately and passed.
  One ignored helper runs through its subprocess parent; the optional local
  Limits remeasurement was not run.
- Strict all-target, all-feature Clippy; cargo fmt check; shell syntax and diff checks.
- Two writers, observer delivery, independent primary/secondary slow-writer GAP,
  capacity/reclamation, staged takeover failure, disconnected retirement,
  partial-input boundaries and output/control liveness, and resize ownership.
- Compatibility: 0.2.4 clients against the new gateway and new clients against
  an old gateway; old framed broker compatibility.
- Installed shell, tmux, nvim, Claude Code, and Codex application qualification.
- Two 61-second fuzz campaigns: 11,596,897 control executions and
  6,443,282 resume executions, no failures.
- Exact release binary: shared writers under 5% loss plus 25ms jitter.
- Final network gate: loss0/1/5/10/25, jitter25/50, reorder/duplication,
  UDP-only data plane, IPv6 loss, 1200-byte MTU, sleep/wake, cancellation,
  five- and thirty-minute outages, forced overrun, twenty fresh reattachments,
  and interface migration. The optional twelve-hour soak was not run.

The original network runner exited 127 during final summary generation because
its script was edited while the thirty-minute outage was running. All eighteen
scenarios had already passed. [final-network.json](final-network.json) preserves
the failure and independently revalidates the complete expected scenario set,
original results and hashes, outage durations, and reattachment/process checks.
This is a recovered summary, not a claim that the runner exited successfully.
Future long runs should use an immutable harness snapshot.

## Performance

[final-performance.json](final-performance.json) retains all twelve raw-PTY
paired blocks per loss cell, their receipt hashes, both independent six-pair
sets, and the earlier inconclusive shell-echo results. Both raw sets clear the
repeatable >10% p50/p95 regression threshold. Across all twelve pairs,
candidate/baseline paired medians are 1.0124/0.9089 at no loss and
0.9827/0.9681 at 5% loss (p50/p95).

Large scheduling variance remains: this is not an absolute latency or speedup
claim. The historical zmosh comparison's disclosed performance FAIL is
unchanged. The earlier performance.json describes an intermediate candidate,
not the final artifact.

## Rollout

Atomic installation on dandeb, badger, bugger, and bagger; exact binary and
wrapper hashes and eversh 0.2.5 verified on each. Existing broker/child
identities checked before and after; no existing gateway restarted.
Private per-host rollback copies retained under the eversh upgrade staging
directories.

Post-install disposable real-SSH canaries exercise two writers, one local
disconnect, a fresh attach, the same surviving shell, and common child exit.
Bagger self-SSH has a pre-existing host-key mismatch, left untouched;
Badger-to-Bagger and Bagger-to-Badger verify Bagger's server and client roles
without weakening host-key checks.

Already-running old gateways remain single-writer. New shared behavior applies
to new gateways. No remote VT, terminal parser, screen reconstruction, or
scrollback replay was added.
