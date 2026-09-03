# M4 criterion-to-test-to-receipt matrix

Status: frozen 2026-09-03 | Owner: `eversh-chl.5` | Governing plan:
[v1-finish-and-everudp.md](v1-finish-and-everudp.md) Stage B

Rules: every criterion row names its tier, exact test location, pass
assertion, and current receipt. An empty receipt cell blocks M4 closure. Fake
contract tests are required where design §11.4 demands deterministic argv,
Kitty, or partial-failure control; they never substitute for a required
real-composition row. Runtime receipts must name the commit that produced
them.

| # | Criterion | Tier | Test | Pass assertion | Receipt |
| --- | --- | --- | --- | --- | --- |
| 1 | Atomic named connect: concurrent connects create exactly one child; loser sees Busy or attaches per policy | Real | `test-eversh-openssh.sh` scenario 8 `scenario_concurrent_connect` | exactly one session record/broker PID; loser exits 3 (Busy) with zero ticks; winner carries monotonic ticks and exits 41 after kill | PASS (see receipt below) |
| 2 | Implicit attach never revokes writer | Real | `crates/eversh/tests/net/test-eversh-openssh.sh` scenario 4 | second attach exits `Busy`; original tick stream continues | PASS at `b6d2d3e` |
| 3 | Explicit takeover revokes old owner visibly | Real + Fake | Real: `test-eversh-openssh.sh` scenario 9; Fake precision: `crates/everpty/tests/client.rs::takeover_fixes_runtime_ownership_and_both_roles` | Real: takeover attach carries ticks; prior holder stays attached as observer (does not exit Busy/43); exactly one session record; both holders exit 41 after kill. Fake: old writer receives `Revoked` first, stays output-only observer, one writer granted | PASS (see receipt below; fake suite green at `b6d2d3e`) |
| 4 | Missing vs exited vs hard-failed broker distinction | Fake | `crates/eversh/tests/supervisor_linux.rs::busy_and_missing_sessions_are_visible_and_never_retried`, `gone_session_is_not_restarted_after_transport_failure` | distinct visible outcomes; gone broker never restarted | PASS (28-test suite at `b6d2d3e`) |
| 4a | Session torn down mid-reconnect | Real | `test-eversh-openssh.sh` scenario 3 | terminal `SessionGone`; no restart | PASS at `b6d2d3e` |
| 5 | Clean child exit returns real status | Fake | `child_exit_returns_status_without_any_retry` | exact status, no probe | PASS at `b6d2d3e` |
| 5a | Clean child exit through real composition | Real | `test-eversh-openssh.sh` scenario 1 | wrapped exit 43 and marker round-trip | PASS at `b6d2d3e` |
| 6 | Raw SSH: exactly one outer OpenSSH, never restarted | Fake | `raw_ssh_passes_through_and_never_retries`, `raw_ssh_forwards_a_remote_command_after_inner_separator` | one spawn; exact passthrough | PASS at `b6d2d3e` |
| 6a | Raw SSH real process count | Real | `test-eversh-openssh.sh` scenario 10 `scenario_raw_ssh_never_replaced` | after proxy SIGKILL: nonzero exit, exactly one supervisor-spawned outer ssh, exactly three total invocations (outer + proxy `ssh -G` + bootstrap), no probe/reattach text, zero post-kill ticks | PASS (see receipt below) |
| 7 | Forwarding never receives a replacement OpenSSH operation | Real | `test-eversh-openssh.sh` scenario 11 `scenario_forward_never_replaced` | forwarded sshd answers before failure; after proxy SIGKILL: nonzero exit, forwarded listener dead, exactly one supervisor outer ssh and three total invocations (outer + query + bootstrap), no probe/reattach | PASS (see receipt below) |
| 7a | SFTP/SCP compatibility and no second OpenSSH operation | Real (transport compatibility) + policy | Transport: `crates/everssh/tests/net/test-openssh.sh` SFTP batch, modern SCP download, and forwarding sessions; supervisor: raw mode never retries (row 6a) and `eversh ssh` is the only raw surface | SFTP/SCP/forwarding pass byte-exactly through the everssh ProxyCommand transport and its terminal failures are ordinary; the composed supervisor exposes no distinct SFTP/SCP verb and no restart path — raw mode is the single supervisor surface | Transport PASS (existing gate); supervisor policy PASS at `df2d82b` |
| 8 | Kitty launcher contract | Fake | `argv.rs` Kitty argv test; `list_filters_by_origin_and_resume_all_reports_partial_failure` | exact argv, one reconnect per matching window, failed window preserved, partial results reported | PASS at `b6d2d3e` |
| 8a | Real Kitty smoke | Optional diagnostic | WHEN REAL SOCKET EXISTS | not release-blocking; recorded separately if run | N/A |
| 9 | Standalone everpty/everssh execute installed roles | Real | everpty: `crates/everpty/tests/cli.rs` against `CARGO_BIN_EXE_everpty`; everssh: `crates/everssh/tests/net/test-openssh.sh` against standalone `target/debug/everssh` | everpty CLI suite exercises start/attach/list/detach/kill lifecycle on real Linux PTYs; standalone everssh passes all eight real OpenSSH session classes | PASS at current head (13/13 everpty CLI; Slice 5A PASS; `STANDALONE_EXIT=0:0`) |
| 10 | B1 live-session outage continuity | Real | `crates/eversh/tests/net/test-composed-netns.sh b1` | 95s total path loss: local terminal and broker PID unchanged, status `reconnecting`, zero supervisor ssh spawns, queued input delivered exactly once after restore, post-restore marker delivered, local scrollback retained | PASS (see receipt below) |
| 11 | B2 terminal fallback timeline | Real | `crates/eversh/tests/net/test-composed-netns.sh b2` | observed client-budget exhaustion and server-association release (not predicted constants); loss sustained ≥10s after observed release; zero ssh attempts during the configured 30s association drain; first fresh attempt and post-drain backoff ≥29s after terminal; exactly one first-attempt probe and reattach; same broker and local terminal PID; local scrollback retained; old-association input never delivered; only future input arrives; bounded invocation count (≤6 fresh entries = probe+reattach triples) | PASS with observed timestamps (`composed-b2-final.log`) |
| 12 | Released-association drain reattach | Real | `test-eversh-openssh.sh` scenario 2 | killed proxy; same broker PID reattaches after bounded Busy drain; monotonic ticks; wrapped exit 41 | PASS at `b6d2d3e` (420s window) |
| 13 | Status-file argv-only policy | Fake | `status_file_argument_on_structured_ops_only_never_raw_ssh_or_env` | structured-only argument, never environment/raw | PASS at `b6d2d3e` |
| 14 | Link-status classification incl. `reconnecting` | Fake | `crates/eversh/src/supervisor.rs` unit tests | transient records defer bounded phase; only terminal cause classifies | PASS at `b6d2d3e` |

Receipt locations: durable real-gate receipts are tracked under
`docs/release-evidence/20260903-m4/` (observed-timeline composed B1/B2
final runs, the earlier B2 transition at `7c2c563`, standalone artifacts at
`9c762a0`, and the composed final at `9d2c5a8`), with SHA-256 bindings in
`docs/release-evidence/SHA256SUMS`.
Earlier raw run logs remain under `target/qualification/eversh-composed-*`
with the producing short SHA; fake-suite receipts from the workspace test
run are bound by the M5 aggregator's exact-SHA receipt.
