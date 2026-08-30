# EverLink M3 Slice 0 evidence

Recorded on 2026-08-30. This is dependency preflight and donor-disposition
evidence only. It implements no identity, transport, admission, bridge,
bootstrap, migration, supervisor, or other production behavior.

## Boundary and identities

| Item | Exact identity / result |
| --- | --- |
| Repository | `/home/appsmith/asv/ports/repo/eversh` |
| Frozen base and unchanged HEAD | `1d14a7eba1517a1c1c80ba86585b718d021fa723` on `master` |
| Starting state | Empty `git status --porcelain=v1`; binary-diff SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Frozen task | SHA-256 `bd17951393ed0a44c7338fd49334352a8260edfcd0e029d361b7c963f400adbe` |
| Accepted plan | SHA-256 `6c14d687cc220166fc03da403b4ae6dca6bba764835d2e5d6b3616de14e2b9b6` |
| Git | `/home/appsmith/bin/git`, SHA-256 `2c692adad6a0785d1c0c7d2b50413816b077296852f90563a2d071a7faaa9b35` |
| Cargo | `/usr/bin/cargo`; `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`; SHA-256 `eab5512c7d143d409a09388a47edfe8c330b2fb5d1a8baee10996cb0c17a0d4e` |
| Rust | `/usr/bin/rustc`; `rustc 1.95.0 (59807616e 2026-04-14)`, host `x86_64-unknown-linux-gnu`, LLVM 21.1.8; SHA-256 `d8cb5537ada4fcee501c986afbc40910df7d8598892e3fcaabbefb500393a053` |
| cargo-deny | Offline-installed in `/tmp`; `cargo-deny 0.20.2`; executable SHA-256 `a272479de722d2eefe46f7c031c2286948c1f806c17cb74e8d2235ba73a5098e` |
| OpenSSH | `/usr/bin/ssh`, OpenSSH_10.4p1 Debian-5, SHA-256 `b3c6352abfa1e5349d73ca4de113f662d714c5f9cd1be2a8a4afa166d4afd199`; `/usr/sbin/sshd`, same version, SHA-256 `4d1151f5a242f793ea636d9ca2b47fa38f5d5462fe65e3747d8d7bb76a11cc3a` |
| Privilege tool | `/usr/bin/sudo`, SHA-256 `8a4a1fbc6d9dcdd2fc873ecc5be8bd29ce8d42290e4f9a8f2c8a30c5f2165dca`; unavailable inside the model sandbox, but `sudo -n true` and the migration gate passed from the controller host as recorded below |

No commit, push, merge, branch change, deployment, tracker, Dolt, zmosh, or
credential mutation was performed. Temporary tool/cache files live only under
`/tmp`. The final repository scope is checked below against the eight allowed
paths.

### Frozen donors

| Donor | Verified identity | Disposition |
| --- | --- | --- |
| Rust/noq M0 | Commit `1b3324bb53d0b5e3fabb1ae546e694f473381f11`; commit tree `fb6965d192c2d26c34faa83b444aec4abdf4d552`; `spikes/noq-m0` tree `a1da5b8e9ce6747559fa0a0d0e6afe2e5e02871f`; `git diff --quiet <commit> -- spikes/noq-m0/src` returned 0 | Symbol dispositions are frozen below. |
| zmosh behavioral reference | Read-only verification in `/i/ports/repo/zmosh`: commit `205e8394c8841798d96c21d66bdba5155ee04868`, tree `449e93d1b412c211e98a73a73ea045199d017a0a` | Behavioral/test ideas only; no Zig source copied and no zmosh file changed. |
| zmx replant reference | Commit `cd88d1b9dd04805b628d609058559cef2e920d38`, tree `8d6fda7cc2905ca45c8956c747343ff1d7b10373` | Reference identity only in Slice 0. |

## Frozen baseline gate receipts

All receipts bind HEAD `1d14a7eba1517a1c1c80ba86585b718d021fa723`
and empty diff `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Their directory is the PairEngine run's `gates/` directory.

| Receipt | SHA-256 | Frozen command | Receipt result |
| --- | --- | --- | --- |
| `baseline-fast-00-00-diff-check.receipt.json` | `03d33761872b2857b8396f3b53253bba483697ba8b2a9382017202c7ce1e3b08` | `git diff --check` | PASS, exit 0 |
| `baseline-fast-00-01-cargo-check.receipt.json` | `2e2217c02ebd76de68967ebb4d0cb45db9487f759d2eea6dcd6b513993cb3cd4` | `cargo check --workspace --all-targets --all-features --locked` | PASS, exit 0 |
| `baseline-full-01-00-cargo-fmt.receipt.json` | `9cd8ea4cd71dae109302d0f7979c6fa3dd18246d182816748e9efc826aa631c9` | `cargo fmt --all -- --check` | PASS, exit 0 |
| `baseline-full-01-01-cargo-clippy.receipt.json` | `73a499fc1662bd1e072920b0a50618279440a9832872f00a6b6570bde51bb6f1` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | PASS, exit 0 |
| `baseline-full-01-02-cargo-test.receipt.json` | `0178d71ef99385f08cd25dea3cd7bcb0772805ac025e50a901b932bb5b06aabd` | `cargo test --workspace --all-features --locked` | PASS, exit 0 |
| `baseline-full-01-03-cargo-check-no-default-features.receipt.json` | `55a3ff6b8c8e07ca3bb35ab7bc2842396847fa951efd339197d52b60ba69bfe2` | `cargo check --workspace --no-default-features --lib --locked` | PASS, exit 0 |

These are controller receipts, not reconstructed prose. Candidate commands
below are builder runs; the controller owns the authoritative candidate/full
receipts for the exact final diff.

## Dependency graphs and independent decisions

The reproducible graph commands were `cargo metadata --locked`, targeted
`cargo tree --locked -e normal -i PACKAGE`, structural `[[package]]` scans of
all three locks, and cargo-deny. Where a separate workspace could not
materialize an archive, the lock scan is reported as a lock result, not as a
metadata or build PASS.

### Exact before and final named graph

All three locks had the same named versions at the base. Only chacha20 changes
in the final named graph.

| Workspace | Path into graph | Base | Final |
| --- | --- | --- | --- |
| Root | `everlink -> noq -> noq-proto -> rand -> chacha20`; `noq -> noq-udp`; noq/proto -> rustls/ring; everlink -> rcgen/ring | chacha20 0.10.1; noq/noq-proto/noq-udp 1.1.1; rustls 0.23.43; ring 0.17.14; rcgen 0.13.2; rand 0.10.2 | chacha20 0.10.2; every other named version unchanged |
| M0 spike | `noq-m0 -> noq -> noq-proto -> rand -> chacha20`; `noq -> noq-udp`; direct rcgen/ring | same base versions as root | chacha20 0.10.2; every other named version unchanged |
| Fuzz | `eversh-fuzz -> everlink -> noq -> noq-proto -> rand -> chacha20`; `noq -> noq-udp` | same base versions as root | chacha20 0.10.2; every other named version unchanged |

| Package | Base/final checksum |
| --- | --- |
| chacha20 0.10.1 (base only) | `d524456ba66e72eb8b115ff89e01e497f8e6d11d78b70b1aa13c0fbd97540a81` |
| chacha20 0.10.2 (final) | `65c35e4b699c7e15ccbe7ee35c005e4fc0a278d22238a2857e6ce2dadeda1b06` |
| noq 1.1.1 | `09e4bb6601fa543c110d8957813267d5a8d775a0f8fbaccf1f615d06ba9b10da` |
| noq-proto 1.1.1 | `baa7b5ccd819a9c68a0d955e67a881032d09b1a17219b1f90b0997a0888e1a15` |
| noq-udp 1.1.1 | `02bba20e097a5a16cd0ad14ec882fae1e80a092a124e9422fc4dddd92e96a647` |
| rustls 0.23.43 | `0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06` |
| ring 0.17.14 | `a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7` |
| rcgen 0.13.2 | `75e669e5202259b5314d1ea5397316ad400819437857b90861765f24c4cf80a2` |
| rand 0.10.2 | `c7f5fa3a058cd35567ef9bfa5e75732bee0f9e4c55fa90477bef2dfcdbc4be80` |

| Lock | Base SHA-256 | Final SHA-256 |
| --- | --- | --- |
| `Cargo.lock` | `e2d4d059ddb6ba6e572c66228b71e09785a167be658a11757ec3f0254789fb7a` | `7daf3d9cb5001514cdbf457ebffa7398b0e6ae87bf156333cdf54cc8e126e1c7` |
| `spikes/noq-m0/Cargo.lock` | `cc591e7d0ffc1acf15594f1b15a0ee6bdad1a7a5055293459eb44cfbed227ea4` | `c9447b8c8458c9d25ffa30db0abf22a83138a6e0e5a4a0e6b999d33a47dc3fbc` |
| `fuzz/Cargo.lock` | `09ee7cb5bc838b2d78f76f56edde3b77f993e46cac5ce1fea28275fc3d380216` | `f8b34ec6c26ff5e6f2d193dba9d8798db2fbdbf7047ca8add44b1e1d89bb333b` |

### Decision A: remove chacha20 0.10.1 independently

1. `cargo update --manifest-path <root|M0|fuzz Cargo.toml> -p
   chacha20@0.10.1 --precise 0.10.2 --offline` reported exactly one update in
   each graph.
2. Before either policy file was edited, a package-aware scan of all three
   locks returned `PASS: no chacha20 0.10.1 package in any applicable lock`.
   The immediate lock hashes were the final hashes in the table above.
3. Root and fuzz inverse trees both resolve `noq-proto 1.1.1 -> rand 0.10.2
   -> chacha20 0.10.2`. Only after that proof were the two
   `chacha20@0.10.1` advisory ignores removed.
4. On the final graph, cargo-deny 0.20.2 with a writable isolated advisory DB
   reports `advisories ok, bans ok, licenses ok, sources ok` for root and fuzz.
   M0's policy command is explicitly incomplete below because its pre-existing
   `pem`/`base64` archives are unavailable; its final lock is nevertheless
   structurally exact and contains chacha20 0.10.2 only.

This decision does not depend on the noq trial.

### Decision B: retain exact noq 1.1.1

The temporary trial used exact `noq = "=1.2.0"`, defaults disabled, and only
`runtime-tokio`, `rustls`, `ring`, `bloom` in production and M0. All three
trial locks resolved noq/noq-proto/noq-udp 1.2.0, while the other named graph
versions above stayed fixed. Trial checksums were:

| Trial package | Checksum |
| --- | --- |
| noq 1.2.0 | `f1e6c57353d26be91a242f0ec96073066c4481a03f6be874daafb18902394515` |
| noq-proto 1.2.0 | `9a46813e306c29c4f86357b6ffa39a8e1c97bb274b9a296a19a56d62e4111225` |
| noq-udp 1.2.0 | `b56d621ed2c1773b5356ab39cc68c819f8d0103f7493d8661c4a5f5f8ea55f40` |

The official cached noq 1.2.0 archive hashes to its lock checksum and declares
`rust-version = "1.88"`. Read-only source inspection found the required public
surfaces still present: `Incoming::retry` and validation queries,
`Endpoint::rebind`, `Connection::{open_bi,accept_bi,close}`, endpoint close and
idle wait, the rustls/ring features, and public path APIs. That inspection is
not a qualification PASS: the exact graph could not be compiled, and no
private API or source adaptation was attempted.

#### Required noq 1.2.0 matrix

| Required cell | Exact command/evidence | Honest result on the trial graph |
| --- | --- | --- |
| PairEngine diff | `git diff --check` | PASS, exit 0 |
| PairEngine fmt | `cargo fmt --all -- --check` | PASS, exit 0 |
| PairEngine check | `cargo check --workspace --all-targets --all-features --locked` | INCOMPLETE, exit 101: `noq-proto 1.2.0` archive could not be fetched because registry DNS/network is unavailable |
| Remaining PairEngine semantic cells | clippy, workspace test, no-default-features check | NOT RUN on 1.2.0 after its exact locked graph could not materialize; NOT PASS |
| M0 fmt | `cargo fmt --manifest-path spikes/noq-m0/Cargo.toml -- --check` | PASS, exit 0 |
| M0 clippy | `cargo clippy --manifest-path spikes/noq-m0/Cargo.toml --all-targets --locked -- -D warnings` | INCOMPLETE, exit 101: required cached archives were unavailable (`base64 0.22.1` was the first reported) |
| M0 tests and graph execution | `cargo test --manifest-path spikes/noq-m0/Cargo.toml --locked`; locked tree/metadata | NOT RUN / INCOMPLETE after the same materialization failure; lock resolution itself succeeded, which is not a test PASS |
| Real OpenSSH bootstrap/e2e | `spikes/noq-m0/net/test-bootstrap.sh`, `test-e2e.sh` | NOT RUN: no exact 1.2.0 M0 binary could be built; NOT PASS |
| Privileged migration | `sudo spikes/noq-m0/net/test-migration.sh` | UNAVAILABLE: `sudo -n true` exits 1 (`no new privileges`); `ip netns list` also exits 1 (`Operation not permitted`). The destructive script was not started and no namespace/resource was created. |
| Rust 1.88 MSRV | exact 1.88 cargo/rustc | UNAVAILABLE: no rustup, `cargo-1.88`, or `rustc-1.88` exists; only `/usr/bin/{cargo,rustc}` 1.95.0 was found. No `cargo +toolchain` result is fabricated. |
| Rust 1.95 aarch64 | `cargo check ... --target aarch64-unknown-linux-gnu --locked` | UNAVAILABLE: `/usr` contains only the `x86_64-unknown-linux-gnu` Rust stdlib; NOT PASS |
| cargo-deny 0.20.2 root/fuzz/M0 | exact pinned binary, all features, locked | INCOMPLETE, exit 1 in all three trial graphs because cargo metadata could not fetch the missing 1.2.0 archives (M0 also lacked historical pem/base64 archives); policy evaluation did not complete |

Because multiple mandatory cells are unavailable or incomplete, noq 1.2.0 is
rejected. Both declarations and all related lock entries were restored with
`cargo update ... -p noq@1.2.0 --precise 1.1.1 --offline`. Final production,
M0, and fuzz graphs contain exact noq/noq-proto/noq-udp 1.1.1 and chacha20
0.10.2. No Rust source was adapted.

## Final candidate checks available to the builder

| Check | Result |
| --- | --- |
| `cargo check --workspace --all-targets --all-features --locked` | PASS, exit 0 on final 1.1.1/0.10.2 graph |
| `cargo fmt --all -- --check` | PASS, exit 0 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | PASS, exit 0 |
| `cargo check --workspace --no-default-features --lib --locked` | PASS, exit 0 |
| `cargo test -p everlink --all-features --locked` | PASS: 11 integration tests, no failures |
| cargo-deny 0.20.2 root | PASS: advisories, bans, licenses, sources all OK |
| cargo-deny 0.20.2 fuzz | PASS: advisories, bans, licenses, sources all OK |
| cargo-deny 0.20.2 M0 | INCOMPLETE inside the offline model sandbox because `pem 3.0.6` and `base64 0.22.1` were absent; PASS on the controller host after the exact locked graph materialized, as recorded below |
| Local `cargo test --workspace --all-features --locked` | INCOMPLETE in the model sandbox: 35 pre-existing everpty process/socket tests received `EPERM` and poisoned related locks (89 pass, 35 fail, 1 ignored). PairEngine's controller-owned final gate subsequently passed the whole workspace on the exact reviewed diff. |

## Controller-host qualification of the reviewed candidate

The model sandbox limitations above remain part of the trial record; they are
not recast as passes. After PairEngine froze and independently approved the
candidate, the controller host ran the following additional gates on the same
base and six-path content. PairEngine recovery run
`20260830T132953Z-Recover-and-independently-qualify-th-14762ec40b9c4efc8132c4c4dc`
finished `DONE` with fresh `ZAI/glm-5.3:max` review, no findings, and all six
configured final-only gates passing. Its reviewed/final diff identity before
this host-evidence section was appended was
`1630eefc13e08ecfe7052cc657a5b312f0d1e75044f92712bc27bf473967652e`.

| Gate | Controller-host result |
| --- | --- |
| Root cargo-deny 0.20.2 | PASS: `cargo-deny --all-features --locked check`; advisories, bans, licences, and sources all OK. Duplicate-version policy warnings remained warnings. |
| Fuzz cargo-deny 0.20.2 | PASS: `cargo-deny --manifest-path fuzz/Cargo.toml --all-features --locked check`; all four policy groups OK. |
| M0 cargo-deny 0.20.2 | PASS from `spikes/noq-m0`: the previously absent `pem 3.0.6` and `base64 0.22.1` archives materialized and all four policy groups were OK. |
| M0 deterministic suite | PASS: fmt; clippy with warnings denied; locked build; and 25 tests across unit, process, bridge, migration, resource, and shutdown suites, with no failures. |
| Real OpenSSH bootstrap | PASS: exactly one record, token absent from child argv/environment, child alive after bootstrap, bounded lease exit, and no surviving owned server. |
| Real OpenSSH behavior | PASS: remote command, exit 42 propagation, 65,536-byte random stream, SFTP, SCP, local forwarding, remote forwarding, stdout purity, and bounded process cleanup. |
| Privileged migration | PASS under fresh `ns-m0srv`/`ns-m0cli` namespaces: stable identity `93905927841840` survived rebind from `0.0.0.0:35561` to `10.231.1.2:33993`; 400 numbered frames / 409,600 bytes arrived exactly once; total path loss closed the server within 60 seconds. |
| Rust 1.88 MSRV | PASS: isolated official `rustc 1.88.0 (6b00bc388 2025-06-23)`, rustc SHA-256 `ac3e92e45fe15c789939deedf7614f4f9578cc9609cb9ead39c9b1808a316c5b`; `cargo +1.88.0 check --workspace --all-targets --all-features --locked`. |
| Rust 1.95 aarch64 | PASS: isolated official `rustc 1.95.0 (59807616e 2026-04-14)`, rustc SHA-256 `bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6`; installed `aarch64-unknown-linux-gnu` stdlib SHA-256 `59fa077f9a51350d5029760d8906128697daa15c8f32a15f99bc10be9aa92017`; `cargo +1.95.0 check --workspace --target aarch64-unknown-linux-gnu --locked`. |
| Resource cleanup | PASS after explicit verification: no `ns-m0srv`/`ns-m0cli`, M0 veth, or M0 process survived. The disposable E2E trap had retained mode-0700 debug material containing ephemeral private keys, and migration had left mode-0644 root-owned evidence including the one-use record. Those exact temporary artifacts were securely removed. Production harnesses must clean on success, failure, signal, and timeout and must never leave bootstrap records world-readable. |

The isolated toolchains live only under
`/tmp/eversh-m3-rustup.zqpctZ`; `RUSTUP_HOME` and `CARGO_HOME` were scoped to
that directory, so the system Rust installation and shell configuration were
not changed.

## Symbol-level M0 promotion ledger

The classifications below use exactly the four Slice 0 dispositions. A
"promote" disposition promotes the proved algorithm/ownership seam, not its
spike diagnostics or panic paths. Named targets are the production modules
frozen in `plans/m3-plan.md`; creating them is later-slice work.

### Modules, types, fields, and functions

| M0 source symbol | Target symbol or test seam | Classification | Reason / required rewrite boundary |
| --- | --- | --- | --- |
| `lib.rs::config` | existing `everlink::limits` | rewrite against an existing/named production type | Production already owns contract/provisional limits. |
| `lib.rs::pinning` | existing `everlink::pinning` | rewrite against an existing/named production type | Production verifier and DER walker already supersede the spike module. |
| `lib.rs::protocol` | existing `everlink::bootstrap`, later `admission` | rewrite against an existing/named production type | Spike text magic/types are disposable; production codecs are already typed. |
| `lib.rs::shutdown` | `everlink::shutdown` | promote into a named production module | First-cause Request/Drain/Finalize is a donor, expanded to owned cleanup/deadlines. |
| `lib.rs::spike` | `identity`, `transport`, `admission`, `bridge` | rewrite against an existing/named production type | Split by ownership; never copy the aggregate module. |
| `lib.rs::ALPN` | existing `bootstrap::ALPN` | delete | Duplicate constant. |
| `lib.rs::PROTOCOL_VERSION` | existing `bootstrap::{BOOTSTRAP_VERSION,AUTH_VERSION}` | delete | Production has separate typed versions. |
| `config.rs::Limits` | existing `limits::Limits` | rewrite against an existing/named production type | Keep production representation and validation; do not introduce a second limits type. |
| `Limits::bootstrap_record_max` | `limits::Limits::bootstrap_record_max` | rewrite against an existing/named production type | Existing capped bootstrap value. |
| `Limits::auth_frame_len` | `limits::Limits::auth_frame_len` | rewrite against an existing/named production type | Existing 35-byte contract value. |
| `Limits::token_len` | `limits::Limits::token_len` | rewrite against an existing/named production type | Existing 32-byte contract value. |
| `Limits::copy_buf` | `limits::Limits::copy_buf` | rewrite against an existing/named production type | Provisional; remeasure before bridge completion. |
| `Limits::send_window` | `limits::Limits::send_window` | rewrite against an existing/named production type | Provisional bounded transport value. |
| `Limits::receive_window` | `limits::Limits::receive_window` | rewrite against an existing/named production type | Provisional bounded transport value. |
| `Limits::max_bi_streams` | `limits::Limits::max_bi_streams` | rewrite against an existing/named production type | Contract remains one; admission must also reject extras. |
| `Limits::server_lease` | `limits::Limits::server_lease_ms` | rewrite against an existing/named production type | Use production representation and absolute bootstrap-derived deadline. |
| `Limits::handshake_timeout` | `limits::Limits::handshake_timeout_ms` | rewrite against an existing/named production type | Use production representation and one non-extending deadline. |
| `Limits::idle_timeout` | `limits::Limits::idle_timeout_ms` | rewrite against an existing/named production type | Transport-owned path/idle deadline. |
| `Limits::stall_timeout` | `limits::Limits::stall_timeout_ms` | rewrite against an existing/named production type | Bridge-owned bounded-stall deadline. |
| `Limits::drain_timeout` | `limits::Limits::drain_timeout_ms` | rewrite against an existing/named production type | Shutdown drain deadline. |
| `Limits::finalize_timeout` | `limits::Limits::finalize_timeout_ms` | rewrite against an existing/named production type | Owner cleanup/join deadline. |
| `Limits::bootstrap_timeout` | `limits::Limits::bootstrap_timeout_ms` | rewrite against an existing/named production type | SSH bootstrap capped-read deadline. |
| `Limits::max_pending_handshakes` | `limits::Limits::max_pending_handshakes` | rewrite against an existing/named production type | Admission/transport hard cap, not merely a documented value. |
| `Limits::default` | existing `limits::Limits::default` plus resource gate | rewrite against an existing/named production type | Contract values stay fixed; every provisional runtime value must be remeasured. |
| `protocol.rs::BootstrapRecord` and `version` | existing `bootstrap::BootstrapRecord::version` | rewrite against an existing/named production type | Use production magic/version and total parser. |
| `BootstrapRecord::udp_port` | existing `BootstrapRecord::{udp_endpoint,udp_port}` | rewrite against an existing/named production type | Spike omitted the authenticated published endpoint. |
| `BootstrapRecord::spki_sha256` | existing `BootstrapRecord::spki_sha256` | rewrite against an existing/named production type | Preserve SPKI, not whole-certificate, identity. |
| `BootstrapRecord::token` | existing record plus `identity` guarded token owner | rewrite against an existing/named production type | Secret must be one-use, bounded in lifetime, and never diagnosed. |
| `BootstrapRecord::pid` | existing `BootstrapRecord::pid` | rewrite against an existing/named production type | Diagnostics-safe identity only; never ownership by PID alone. |
| `protocol.rs::ProtocolError` | existing `error::Error` | delete | Stringly spike error is superseded by typed production errors. |
| `protocol.rs::decode_hex32` | existing private `bootstrap::decode_hex32` | rewrite against an existing/named production type | Reuse total production parser. |
| `BootstrapRecord::{encode,parse}` | existing `bootstrap::BootstrapRecord::{encode,parse}` | rewrite against an existing/named production type | Existing production record includes literal endpoint and cap-first parsing. |
| `protocol.rs::{encode_auth_frame,decode_auth_frame}` | existing `bootstrap::{encode_auth_frame,decode_auth_frame}`, later `admission` | rewrite against an existing/named production type | Keep exact 35-byte schema; production validates version and typed errors. |
| `protocol.rs::hex` | existing `bootstrap::hex32` | delete | Generic formatter enables accidental secret formatting; use fixed production helper only where allowed. |
| `protocol.rs::ct_eq` | existing `bootstrap::ct_eq`, later admission comparison | rewrite against an existing/named production type | Existing constant-shape helper; token consumption remains admission-owned. |
| `protocol.rs::tests` | existing `crates/everlink/tests/wire.rs`, later admission negatives | retain only as a test/harness donor | Retain malformed/truncation/round-trip ideas, not spike text wire format. |
| `pinning.rs::PinMismatch` | existing `Error::PinMismatch` | delete | Existing typed error supersedes the unit struct/string. |
| `pinning.rs::SpkiPinVerifier::{pin,provider,new}` | existing `pinning::SpkiPinVerifier` | rewrite against an existing/named production type | Production type already owns the same guarded verifier state. |
| `SpkiPinVerifier::ServerCertVerifier` methods | existing verifier trait implementation | rewrite against an existing/named production type | Preserve fail-closed SPKI and provider signature checks; no second TLS stack. |
| `pinning.rs::extract_spki` | existing `pinning::extract_spki` | rewrite against an existing/named production type | Production already contains the read-only DER walk. |
| `pinning.rs::tlv_probe` | DER boundary tests | retain only as a test/harness donor | Public probe existed only for tests; production `tlv` remains private. |
| `pinning.rs::tlv` | existing private `pinning::tlv` | rewrite against an existing/named production type | Reuse total bounds checks; no public DER utility. |
| `pinning.rs::sha256` | existing `bootstrap::sha256` | delete | Production already hashes through ring. |
| `pinning.rs::tests` | existing wire/SPKI tests | retain only as a test/harness donor | Keep known-key SPKI assertions only. |
| `shutdown.rs::Phase` | `shutdown::Phase` | promote into a named production module | Preserve monotonic Running/Requested/Draining/Finalized model. |
| `shutdown.rs::TerminalCause` | `shutdown::TerminalCause` | rewrite against an existing/named production type | Expand into the production first-cause union with precise owner/failure causes. |
| `shutdown.rs::{ShutdownState,Inner}` | `shutdown::Coordinator` | rewrite against an existing/named production type | Replace poison-panicking mutex access; own absolute deadlines and cleanup evidence. |
| `ShutdownState::{new,default}` | `shutdown::Coordinator::new` | rewrite against an existing/named production type | Construction receives frozen deadlines/resource owners. |
| `ShutdownState::request` | `shutdown::Coordinator::request` | promote into a named production module | First-cause-wins/no-resurrection semantics are retained without unwrap. |
| `ShutdownState::drain` | `shutdown::Coordinator::drain` | rewrite against an existing/named production type | Production drain coordinates both copy directions and an absolute deadline. |
| `ShutdownState::finalize` | `shutdown::Coordinator::finalize` | rewrite against an existing/named production type | Must close, join/reap, scrub, and prove owned resources returned. |
| `ShutdownState::{phase,cause}` | typed shutdown observations | rewrite against an existing/named production type | Expose consistent snapshots/evidence, not independently locked reads. |
| `shutdown.rs::tests` | future shutdown/failure-precedence tests | retain only as a test/harness donor | Keep monotonic, idempotent, and concurrent first-winner cases. |
| `spike.rs::SPIKE_ALPN` | existing `bootstrap::ALPN` | delete | Duplicate constant. |
| `spike.rs::SpikeError` and conversion impls | existing/extended `error::Error` | rewrite against an existing/named production type | Replace string categories and discarded rustls detail with bounded typed causes. |
| `spike.rs::transport_config` | `transport::configured_transport` | rewrite against an existing/named production type | Preserve finite windows/one bidi/zero uni; also disable every excluded mode and validate limits. |
| `spike.rs::ServerIdentity` and fields | `identity::EphemeralIdentity` | rewrite against an existing/named production type | Guard key/token ownership and explicit scrub/drop; do not expose all fields publicly. |
| `spike.rs::generate_identity` | `identity::generate` | rewrite against an existing/named production type | Preserve ring-backed cert/SPKI/token generation but return typed errors and scrub secrets. |
| `spike.rs::server_endpoint` | `transport::server_endpoint` | rewrite against an existing/named production type | Preserve rustls/ring setup; replace arbitrary bind with authorized route policy. |
| `spike.rs::client_endpoint` | `transport::client_endpoint` | rewrite against an existing/named production type | Preserve pinning/no resumption; remove `0.0.0.0` assumption and use validated route-selected bind. |
| `spike.rs::client_connect_auth` | `transport::connect` then `admission::authenticate_client` | rewrite against an existing/named production type | Split transport from the existing 35-byte admission schema and absolute deadline. |
| `spike.rs::AuthOutcome` and fields | `admission::AdmittedStream` plus typed transport evidence | rewrite against an existing/named production type | Return only admitted capability; peer/Retry evidence remains transport-owned. |
| `spike.rs::server_accept_auth` | `transport::accept_with_retry` plus `admission::admit` | rewrite against an existing/named production type | Force Retry, cap pending work, atomically consume token, reject extra streams, and open no target early. |
| `spike.rs::copy_quic_to_tcp` | `bridge::copy_quic_to_tcp` | promote into a named production module | Promote fixed-buffer direct backpressure/half-close; replace unwrap and debug output with typed outcomes. |
| `spike.rs::copy_tcp_to_quic` | `bridge::copy_tcp_to_quic` | promote into a named production module | Promote fixed-buffer direct backpressure/FIN-reset behavior with typed errors. |
| `spike.rs::bridge` | `bridge::run` coordinated by `shutdown` | promote into a named production module | Preserve concurrent directions and second-direction drain bound; production owns task abort/join. |
| `main.rs` role module and `main` | thin production CLI plus `roles` and existing `runtime::build` | rewrite against an existing/named production type | Typed clap dispatch, one runtime owner, bounded stderr, and CLI-only exit mapping. |
| `main.rs::read_record` | `ssh_bootstrap::read_record` using existing bootstrap types | rewrite against an existing/named production type | Keep one capped newline record; remove `String` errors and cap arithmetic ambiguity. |
| `main.rs::{authorized_target_port,read_port_pipe}` | `ssh_bootstrap::parse_ssh_connection` -> `admission::AuthorizedTarget` | delete | A text port pipe and unconditional loopback target are not authoritative production admission. |
| `main.rs::run_bootstrap_parent` | `roles::bootstrap_parent` plus `ssh_bootstrap` owner | rewrite against an existing/named production type | Preserve protected channel/one record; production must retain and reap child ownership and bound stderr. |
| `main.rs::run_server` | `roles::one_shot_server` composed from identity/transport/admission/bridge/shutdown | rewrite against an existing/named production type | Remove env-selected wildcard/loopback policy, text record, PID assumptions, and diagnostics. |
| `main.rs::run_record` | no production role | delete | Redundant record-printing helper; typed unit/harness fixtures replace it. |
| `main.rs::run_migrate_client` | migration netns/process harness | retain only as a test/harness donor | Direct rebind proves noq feasibility only; production trigger belongs to transport's bounded route supervisor. |
| `main.rs::run_proxy_peer` | binary stdin/stdout bridge harness | retain only as a test/harness donor | Test-only role; no public production process role. |
| `main.rs::run_proxy` | `roles::client_proxy`, `ssh_bootstrap`, `bridge` | rewrite against an existing/named production type | Preserve stdout byte purity; audit ssh argv/effective config, do not force BatchMode, and remove duplicated bridge loops. |
| `NOQ_M0_DEBUG`, `eprintln!`, `println!` diagnostics | typed library evidence and bounded CLI stderr presenter | delete | Library layers never print; no token/private key or unbounded child stderr enters diagnostics. |

### Explicit architectural seams

| Concern | Frozen disposition for later slices |
| --- | --- |
| Identity/SPKI | Rewrite M0 generation into `identity`; retain the existing production SPKI verifier; ring is the only provider; pin is over SPKI, never whole certificate. |
| Retry/path validation | Rewrite `server_accept_auth` into transport-owned forced Retry before committed state. Public noq APIs only; no private fork. |
| Admission/cardinality | Existing 35-byte codec feeds a new typed `admission`; atomically consume one token, accept exactly one bidi stream, reject extras, and connect only the complete bootstrap-derived loopback target after success. |
| Wildcard/loopback assumptions | Delete `0.0.0.0:0`, `NOQ_M0_BIND_ADDR`, and unconditional `127.0.0.1` selection as policy. `transport` performs literal-family route/bind validation; `AuthorizedTarget` derives the matching loopback from authenticated `SSH_CONNECTION`. |
| Bridge | Promote only fixed-buffer concurrent copy, direct backpressure, flush/half-close, and bounded drain. No queue, persistence, replay, or terminal parsing. |
| Rebind | Keep direct `Endpoint::rebind` and stable-id frame checks as harness donors. Production uses a bounded transport-owned route supervisor and validated replacement socket. |
| Shutdown | Promote first-cause semantics, but rewrite state/ownership to absolute Request/Drain/Finalize deadlines, idempotent cleanup, joins/reaps, and secret scrub evidence. |
| Bootstrap/process roles | Rewrite into typed private versioned roles. The bootstrap owner alone reaps its child; system sshd is never owned. |
| Forced `BatchMode=yes` | Delete. Production preserves effective OpenSSH behavior and establishes mandatory bootstrap options by audited first-value policy or rejects conflicts. |
| Test-only proxy/migrate roles | Retain only as process/network harness patterns; neither becomes a user-facing production role. |
| Diagnostics | Delete spike debug printing. Library returns typed errors/evidence; CLI bounds and redacts stderr; stdout remains opaque SSH bytes only. |

### Every M0 unwrap/expect/panic path

There is no explicit `panic!`, `todo!`, or `unimplemented!` in
`spikes/noq-m0/src/**`. Every `unwrap`/`expect` occurrence is dispositioned
here; none may enter production behavior by copying.

| Source lines / enclosing symbol | Disposition |
| --- | --- |
| `protocol.rs:145,165` tests | Retain only as test assertions in typed wire tests; no production panic path. |
| `pinning.rs:170,172,177` tests | Retain only as known-good fixture assertions; no production panic path. |
| `main.rs:35 main` runtime build | Rewrite through `runtime::build` and typed CLI failure/exit mapping. |
| `main.rs:107 run_bootstrap_parent`, `485 run_proxy` current executable | Rewrite `current_exe` failure as typed bootstrap/CLI error. |
| `main.rs:125,132 run_bootstrap_parent` child pipes | Rewrite absent pipe handles as construction rollback that kills/reaps the owned child. |
| `main.rs:178 run_server` endpoint address | Rewrite bind/local-address failure as typed transport error before readiness. |
| `main.rs:305,322 run_migrate_client` local addresses | Retain only in harness and turn failures into explicit harness failures. |
| `main.rs:521,525 run_proxy` bootstrap pipes | Rewrite as typed partial-construction rollback with exclusive child reaping. |
| `shutdown.rs:66,79,92,100,104` mutex access | Rewrite poison handling/state ownership; production shutdown cannot panic while cleaning up. |
| `shutdown.rs:153` test join | Retain only as a concurrency-test assertion. |
| `spike.rs:92,93,98 generate_identity` | Rewrite rcgen, DER, and CSPRNG failures into typed identity errors with secret cleanup. |
| `spike.rs:131,137 client_endpoint` crypto config | Rewrite provider/protocol/config conversion failures into typed transport/TLS errors. |
| `spike.rs:140 client_endpoint` wildcard parse | Delete string parse and wildcard policy; bind a typed, validated route-selected socket. |
| `spike.rs:282 copy_quic_to_tcp`, `322 copy_tcp_to_quic` | Promote the loop only after replacing timeout `unwrap` with exhaustive nested `Result` matching. |

## Slice 0 scope receipt

Expected final tracked paths are only `Cargo.lock`, `deny.toml`,
`fuzz/Cargo.lock`, `fuzz/deny.toml`, `spikes/noq-m0/Cargo.lock`, and this
evidence file. `crates/everlink/Cargo.toml` and
`spikes/noq-m0/Cargo.toml` were used for the temporary exact trial and restored
byte-for-byte, so they are not final diff paths. No production Rust source is
changed. The final `git diff --check`, path allow-list comparison, lock scan,
and configured gates are rerun/owned by the builder and PairEngine controller
on the exact final diff.
