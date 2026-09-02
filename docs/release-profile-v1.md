# eversh v1 release profile

Status: v1 limit record (design section 4) | Environment: see "Measurement environment"

Every configurable limit ships with its selected value, the method that
selected it, and the retained evidence that exercises it. Contract (wire)
values are frozen: changing one requires a recorded design revision. Runtime
values may be tuned without changing the wire contract only while the named
boundary tests stay green.

## Measurement environment

All measured values were selected and verified on the release qualification
host: Linux x86_64 (Debian trixie kernel line), rustc 1.95.0, MSRV 1.88,
single machine, loopback and directly reachable non-loopback UDP, OpenSSH
client/server from the distribution. Privileged network-namespace migration
evidence was captured under sudo on the same host during Milestone 3. No
cross-machine WAN measurement is claimed; the interactive defaults below are
deliberately conservative multiples of observed loopback figures.

## everpty (crates/everpty/src/limits.rs)

Contract values
| Limit | Value | Rule |
| --- | --- | --- |
| frame_max_body | 64 KiB | Rejected before allocation (design 4). |
| name_max | 64 | Conservative session-name charset and length. |
| error_text_max | 256 | Bounded UTF-8 control strings. |
| unix_path_max | 107 | Linux sun_path minus NUL, checked before bind. |

Runtime values (selected in M2 by driving the byte/ownership/resource suites
listed in design 11.1–11.2; evidence: the per-knob selection record
plans/m2-limits.md — which pins the exact ignored-measurement invocation and
the retained measurement artifacts it references — plus the non-ignored
boundary regressions in crates/everpty/tests/resources.rs)
| Limit | Value | Selection rationale |
| --- | --- | --- |
| startup_deadline_ms | 10000 | Broker must see its initial writer well within interactive startup; 100x observed loopback attach time. |
| kill_grace_ms | 5000 | TERM-to-KILL grace; matches everlink drain+finalize sum. |
| writer_queue_bytes | 256 KiB | Backpressure boundary proven by the writer-queue fill tests; keeps one writer lossless while healthy. |
| observer_queue_bytes | 64 KiB | Observers are disposable; small queues bound eviction latency. |
| observer_count | 8 | Bounded fan-out; observer-eviction tests fill every slot. |
| aggregate_queue_bytes | 1 MiB | Total broker delivery memory under max clients. |
| max_connections | 16 | Writers + observers + control connections. |
| writer_input_queue_bytes | 64 KiB | Bounded retained input awaiting a draining PTY. |
| incomplete_frame_deadline_ms | 5000 | Drip-fed frames cannot hold a slot open. |
| accepts_per_iteration | 8 | Poll fairness under accept storms. |
| read_chunk_bytes | 16 KiB | One PTY/socket read; matches everlink copy_buf. |
| stall_deadline_ms | 20000 | Writer revocation bound; matches everlink stall_timeout. |
| pty_exit_drain_ms | 5000 | Post-reap PTY drain-to-EOF bound. |
| control_reply_deadline_ms | 5000 | Control replies cannot wedge the broker. |
| list_probe_deadline_ms | 500 | Discovery pings stay interactive. |
| metadata_max_bytes | 4096 | Discovery-only metadata cap. |
| exec_label_max_bytes | 256 | Executable label without arguments. |
| origin_label_max_bytes / origin_count_max | 64 / 4 | Bounded origin labels (shared with eversh). |

## everlink (crates/everlink/src/limits.rs)

Contract values
| Limit | Value | Rule |
| --- | --- | --- |
| bootstrap_record_max | 4096 | Newline-terminated record, fail-closed parse. |
| auth_frame_len | 35 | u8 version + 32-byte token + u16 port. |
| token_len | 32 | 256-bit one-use token. |
| max_bi_streams | 1 | Exactly one SSH-carrying stream. |

Runtime values (M0 candidates remeasured in M3; evidence: the resource
gate log target/qualification/everlink/runs/20260901T104502Z-c10b885d2cc7/gates/everlink-resource-bounds.log
and the raw campaign/network logs under
target/qualification/everlink/runs/20260901T104502Z-c10b885d2cc7 and
target/qualification/everlink/network/20260901T105153Z-c10b885d2cc7)
| Limit | Value | Selection rationale |
| --- | --- | --- |
| copy_buf | 16 KiB | Per-direction buffer; transport envelope stayed at 3.5 MB during the 12 MiB resource transfer. |
| send_window / receive_window | 384 KiB | Bounds stalled-peer memory: stalled TCP/QUIC ceilings 11.9 MB never exceeded 3.4 MB observed. |
| server_lease_ms | 30000 | One-shot server lifetime without a valid client. |
| handshake_timeout_ms | 10000 | Includes forced Retry round trip. |
| idle_timeout_ms | 30000 | Path-loss teardown bound proven in the netns loss gates. |
| stall_timeout_ms | 20000 | Copy-direction stall bound (stalled-reader gates). |
| drain_timeout_ms / finalize_timeout_ms | 5000 / 5000 | Request->Drain->Finalize bounds; all 32 terminal causes reached Finalized within them. |
| bootstrap_timeout_ms | 20000 | SSH bootstrap round trip incl. remote spawn. |
| max_pending_handshakes | 4 | Unauthenticated concurrency; the resource gate drives 8 concurrent unauthenticated clients against it. |
| incoming_buffer_size | 64 KiB | Per-uncommitted-Incoming cap (x4 pending = 256 KiB). |
| max_retry_attempts | 8 | Initial/Retry budget before fail-closed. |
| max_udp_port_span | 1024 | Operator port-range width bound. |
| route_poll_ms / route_observation_timeout_ms | 250 / 200 | Mandatory fallback poll and per-observation bound; wake/migration gates. |
| max_same_route_replacements | 1 | One same-route rebind, then PathFailed. |

## eversh (crates/eversh/src/limits.rs)

Contract values
| Limit | Value | Rule |
| --- | --- | --- |
| remote_control_max | 64 KiB | Encoded control request cap before decode. |
| arg_count_max | 64 | Child argv element bound. |
| name_max | 64 | Mirrors everpty session names. |
| unix_path_max | 107 | Mirrors everpty. |
| origin_count_max / origin_label_max | 4 / 64 | Mirrors everpty metadata bounds. |

Runtime values (selected in M4/M5 by the reconnect and resource gates;
evidence: the supervisor stability rounds, resource-bounds, and OpenSSH e2e
gate logs under target/qualification/eversh/runs/20260902T055944Z-c78a4f5fe666/gates/,
plus the bounded-attempt assertions in
crates/eversh/tests/supervisor_linux.rs)
| Limit | Value | Selection rationale |
| --- | --- | --- |
| retry_attempts_max | 5 | Finite probe/reattach budget for ordinary in-episode failures; the exhaustion gate counts exactly five probes. A Busy reattach never consumes it — the episode deadline alone governs Busy retries. |
| retry_backoff_base_ms | 250 | First backoff; below human reaction time, above loopback probe cost. |
| retry_backoff_cap_ms | 5000 | Bounded exponential ceiling. |
| retry_deadline_ms | 60000 | Overall reconnect deadline (worst-case backoff sum ~11.6 s x safety margin for slow transports); also the only bound on the Busy-retry path. |
| episode_restarts_max | 3 | Invocation-wide cap on carried-death episode restarts; the `episode_restart_cap_bounds_flapping_reconnects` supervisor gate drives a flapping topology into the cap and the invocation ends as a visible ordinary failure instead of looping. |
| list_output_max | 1 MiB | Captured discovery output cap; overflow kills the transport and fails closed. |
| resume_sessions_max | 64 | Kitty tabs launched per resume-all; excess reported as skipped. |

## Tuning rule

A runtime value may change only when `fuzz/qualify-m4.sh run` (deterministic
gates), the everlink resource gate, and — for transport values — the
`fuzz/qualify-m3.sh run`/`network` gates remain green; a release-qualified
change additionally requires `fuzz/qualify-m5.sh run` to pass in full. An
everpty limit change whose selection evidence is being revised additionally
requires re-running the ignored local limits measurement (the exact
invocation pinned in plans/m2-limits.md) — a green boundary-only gate rerun
is not remeasurement. The new value must be recorded here with its
selection method in the same change.
