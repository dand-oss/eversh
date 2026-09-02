# eversh v1 final handoff (S4)

Accepted release head: `43e80ccbf8db031ead34e702028f8f6559232c91` (tree
`7df2ca620fbecfc9948e03c0c3264721f3d5f375`). This document is
post-acceptance operational material only: it records where the release's
evidence lives and how to re-verify or change it, and it does not alter the
qualified release. Everything under `target/qualification/` is gitignored
retained evidence on the qualification host, not part of the git tree.

## What v1 is

Three Rust executables built from one workspace: the combined multi-role
`eversh` (the user-facing supervisor, which also serves the local everlink
transport role and the remote everpty role), standalone `everpty` (the PTY
session broker), and standalone `everlink` (the QUIC ProxyCommand). v1
targets Linux with directly reachable UDP between client and remote host.
Install and everyday use are documented in `docs/install.md`; the exact
release build (all three `[[bin]]`s are gated behind their own crate's
`cli` feature, so a feature-less build produces none of them):

    cargo build --release --locked --features everpty/cli,everlink/cli,eversh/cli

## Evidence map

Receipts, one per qualification run (JSON, binding head SHA, tree SHA, and
a rechecked clean tree), live under `target/qualification/eversh/runs/`:

- v1 acceptance receipt: `runs/20260902T062953Z-43e80ccbf8db/receipt.json`
  (PASS; binds the head/tree above; gates and campaign logs in its `gates/`
  and `campaigns/` subdirectories, release artifact hashes in `release/`).
- M4-close receipt: `runs/20260902T043349Z-c2f40474a4aa/receipt.json`.
- The directory also retains the full M4-to-v1 arc, including the FAILed
  intermediate receipt `runs/20260902T051552Z-0a087c1ac915/receipt.json`
  (stage `campaign-fuzz_frame`, exit 77) whose crash artifact drove the
  frame-canonicality fix `b2ba7aa`.

Independent GLM review archives (each with `prompt.txt`, `raw.stdout`,
`raw.stderr`, `final.md`) live under `target/qualification/eversh/reviews/`:

- M4 chain: `c2bf1c19e5a3-glm53-max-m4` (round 1, FAIL) —
  `227e84f1edbd-glm53-max-m4r2` (round 2, FAIL) —
  `1f49510e69e7-glm53-max-m4r3` (round 3, FAIL) —
  `b186fe413b53-glm53-max-m4r4` (round 4, FAIL) —
  `c2f40474a4aa-glm53-max-m4r5` (round 5, PASS; M4 closed).
- v1 chain: `c78a4f5fe66-glm53-max-v1` (round 1, FAIL; two documentation
  majors) — `43e80ccbf8d-glm53-max-v1r2` (round 2, PASS, zero findings;
  v1 accepted).

Retained M3 everlink evidence (receipts plus raw gate/campaign logs):

- `target/qualification/everlink/runs/20260901T104502Z-c10b885d2cc7` —
  deterministic gates, the resource-bounds gate, and fuzz campaigns.
- `target/qualification/everlink/network/20260901T105153Z-c10b885d2cc7` —
  production OpenSSH and network-namespace migration/loss gates.

Per-limit selection evidence: `plans/m2-limits.md` (everpty per-knob record
including the ignored-measurement invocation) and
`docs/release-profile-v1.md` (every limit with value, selection rationale,
and evidence pointers).

## Re-verification

- `fuzz/qualify-m3.sh setup` — one-time install of the isolated toolchain
  (pinned stable 1.95.0, MSRV 1.88.0, nightly-2026-08-20, cargo-fuzz,
  cargo-deny) the other scripts share.
- `fuzz/qualify-m3.sh run` / `network` — everlink deterministic gates plus
  fuzz campaigns, and the production OpenSSH + netns migration gates.
- `fuzz/qualify-m4.sh run` — eversh supervisor deterministic gates: fmt,
  check, clippy, and tests across the workspace and the fuzz crate, three
  supervisor_linux stability rounds, the MSRV and aarch64 cross-checks,
  and cargo-deny — no campaigns.
- `fuzz/qualify-m5.sh run` — the full release qualification: the m4 gate
  set plus the eversh resource-bounds gate, the seven-scenario production
  OpenSSH end-to-end gate
  (`crates/eversh/tests/net/test-eversh-openssh.sh`), eight cargo-fuzz
  campaigns, and reproducible release packaging with per-binary hashes.

Every script requires a clean committed tree (uncommitted or untracked
changes abort with a `dirty-tree` FAIL receipt before any gate runs),
binds its receipt to the exact head and tree SHAs, rechecks the tree
identity after the last gate, and fails closed: a nonzero gate or a missing
expected line writes a FAIL receipt naming the stage and the raw log under
the run directory. Measured wall times on the qualification host: m4 about
4 minutes; m3 `run` about 6-7 minutes and `network` about 4 minutes; m5
about 13 minutes (the eight 61-second fuzz campaigns dominate).

## Changing a limit safely

The full rule is the Tuning rule section of `docs/release-profile-v1.md`.
In short: contract (wire) values are frozen and need a recorded design
revision; a runtime value may change only with the named qualification
gates green (m5 in full for a release-qualified change); an everpty limit
whose selection evidence is being revised additionally requires re-running
the ignored local limits measurement (exact invocation pinned in
`plans/m2-limits.md`) — a green boundary-only gate rerun is not
remeasurement; and the new value with its selection method must be
recorded in the release profile in the same change.

## Known minors on record (accepted at v1)

- `eversh kill` has a floor of about `kill_grace_ms` (~5 s): the everpty
  broker reaps a killed session only after its TERM-to-KILL phase elapses,
  even when the session child is already gone.
- An externally initiated detach or kill ends the still-attached writer's
  own connection with exit 1 (NotLive-on-EOF), not 0 — everpty's existing
  behavior for a writer whose session ends around it, accepted as-is.
- The e2e harness's scenario-7 optional link-status content snapshot never
  fires (the terminal record lands inside a sub-10-ms window). The
  scenario's binding assertions all pass; the skipped snapshot is disclosed
  on stderr and was accepted by the v1 reviews.
- `parent_requires_readiness_eof_and_reaps_every_pretransfer_failure` in
  `crates/everlink/src/roles.rs` has flaked once in a full-suite run
  (pre-existing timing sensitivity, never reproduced across reruns) —
  rerun before judging a gate red on it.

## The link-status channel

For every structured interactive operation (`connect`, `attach`, `observe`)
and every reconnect probe, eversh allocates a private per-spawn
link-status file (a `0700` directory, `0600` exclusive file) under its
state root and passes the path to the local everlink ProxyCommand edge as
a `--status-file` argument — never an environment variable, so no
`SendEnv`/`AcceptEnv` policy or ambient value can instrument a spawn.
everlink appends versioned `everlink-status-v1` records: `carrying` once
the QUIC stream first delivers remote-originated bytes, and a terminal
`cause <clean-close|transport-failure> carried=<0|1>` on every exit path.
On an ssh exit of 255, eversh reads and removes the file: `clean-close` is
an ordinary SSH failure, reported with no probe and no retry (this
deterministically covers both authentication failures and a remote command
that itself exits 255); `transport-failure`, or a missing or unparseable
file, enters the bounded probe-gated reconnect episode. The channel is
fail-closed: if no state root resolves, the root is unusable, or the path
cannot travel as the quoted argument (non-UTF-8, quotes, control bytes, or
a percent token OpenSSH would expand — `%` is rejected outright, never
escaped), the operation fails with a clear local error before any ssh
child exists, because an uninstrumented spawn's missing record would
misclassify an ordinary 255 as a transport failure and wrongly reconnect.
