# LTO integration workspace check — not product qualification

Source: `78da5177dfc3cd9184efb7f745d9776d469acf3b`, clean worktree.

Command: `cargo test --workspace --all-features --locked --quiet`.
Execution session 8577 completed with exit 0. `workspace.log` is the complete
captured output. This verifies the workspace after adoption of the measured
portable fat-LTO/codegen1 release profile in `694798d`, the boundary assertion
repair, failure-only diagnostics, and the separate cancellable test-fixture fix.
Cargo's ordinary test profile is used here; this is not a release benchmark.

This successful run does **not** erase earlier failures. The two retained
workspace failures reproduced a writer-exit timeout after an authenticated Busy
rejection, once in the combined client and once in the standalone client.
They remain unresolved under `eversh-5fc.46`. Isolated repetitions passed, but
no cause or fix for that incident has been established. A later run was stopped
after live stack inspection proved an unrelated fake-sshd writer blocked a test
join; `eversh-5fc.47` fixed that fixture without changing production code or its
drain-status assertions.

The compiler comparison evidence remains in the independent LTO confirmation
archive. Median latency still misses the frozen custom-UDP zmosh gate. No
performance, reliability, security, or independent-review qualification PASS is
claimed here. No release, push, or fleet rollout is authorized by this receipt.
