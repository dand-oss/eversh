# M5 mechanical section-14 release matrix

Status: frozen 2026-09-03 | Owner: `eversh-chl.6` | Governing plan:
[v1-finish-and-everudp.md](v1-finish-and-everudp.md) Stage C3

Every row names the exact qualification entry point, environment, pass rule,
and retained evidence. The release SHA is not duplicated here: the M5
aggregator requires a clean tree, records `head_sha`/`tree_sha`, and
hash-binds every subreceipt log to that one identity. Raw logs live under
the ignored `target/qualification/eversh/` run root named by the receipt;
sanitized closure evidence is copied under `docs/release-evidence/`.

Supported release targets: x86_64-unknown-linux-gnu on Ubuntu 22.04/24.04
and Debian 12, plus aarch64-unknown-linux-gnu on Debian 12 (QEMU TCG or
native; the aarch64 cross-check is compile-only and runtime qualification
on that target is not claimed until a native/QEMU execution receipt is
recorded). Sanitizer, audit, licence, reproducibility, and packaging
failures are release-blocking.

| §14 criterion | Exact command | Environment and SHA | Pass rule | Retained evidence |
| --- | --- | --- | --- | --- |
| Exactly three physical executables (everpty, everssh, eversh) | `fuzz/qualify-m5.sh run` stage `release-build` | release qualification host; SHA bound by M5 receipt | all three binaries exist, execute `--version`, and are reproduced byte-identically by a second isolated target-dir build | `release-binaries.json`, `release-build*.log` in the M5 run root |
| Real OpenSSH PTY, command, SFTP, SCP, local+remote forwarding through everssh | `fuzz/qualify-m5.sh run` stage `everssh-openssh-slice5a` | Linux, distribution OpenSSH client + sshd; clean release SHA | gate exits 0 with terminal line `EverSSH Slice 5A production OpenSSH path: PASS` (eight session classes byte-exact) | `gates/everssh-openssh-slice5a.log` |
| OpenSSH remains authoritative (config/keys/agent/exit) | same Slice 5A gate plus `documentation-compat` | same | authentication, host keys, effective-config policy, and exit semantics verified by scenario assertions; no stale one-shot claims in live docs | Slice 5A log; `gates/documentation-compat.log` |
| everpty byte transparency, attachment loss, drain/discard, no terminal parsing | root workspace tests (`root-test`) + three supervisor rounds | clean release SHA | full workspace suite and three consecutive `supervisor_linux` rounds pass | `gates/root-test.log`, `gates/eversh-supervisor-round-{1,2,3}.log` |
| Busy/takeover/observer/resize/cleanup/stale-socket races | same root tests + `eversh-e2e-openssh` | clean release SHA | all race/fault scenarios pass with finite cleanup | root-test and e2e logs |
| Standard QUIC migration; bounded resume inside lease; terminal past lease | `fuzz/qualify-m5.sh run` stage `everssh-migration-netns` | root netns/veth, IPv4+IPv6, direct and total-loss paths | terminal line `everssh Slice 4 production netns/veth gate: PASS`; includes 302 s IPv4 / 22 s IPv6 recovery, terminal expiry, replay/duplicate, and sequential-outage reset assertions | `gates/everssh-migration-netns.log`; durable M3 copies under `docs/release-evidence/20260903-m3/` |
| Composed outage continuity (B1) and terminal fallback (B2) | `fuzz/qualify-m5.sh run` stages `everssh-composed-netns-b1/-b2` | root netns, real eversh+everssh+everpty+sshd | B1: same local/broker PIDs, reconnecting status, zero supervisor spawns, queued input exactly once; B2: 405 s loss waits drain, then exactly one probe/fresh reattach, same broker, only future input | both `gates/everssh-composed-netns-*.log` |
| Request->Drain->Finalize leaves no owned task/socket/child/secret | workspace tests + resource-bounds + B1/B2 cleanup assertions | clean release SHA | all terminal-cause tests finalize; process/fd/task ceilings hold | root-test, `gates/eversh-resource-bounds.log`, composed logs |
| All limits finite, tested, documented with measured evidence | this matrix + `docs/release-profile-v1.md` | clean release SHA | every configured value appears in the profile with selection evidence; M3/M5 receipts bound the transport measurements | `docs/release-profile-v1.md`; M3 durable receipts |
| Fuzz, hostile-network, sanitization, licence, vulnerability, reproducibility, real-OpenSSH | `fuzz/qualify-m5.sh run` full matrix | isolated pinned toolchains (1.95/1.88/nightly, cargo-fuzz 0.13.2, cargo-deny 0.20.2) | all nine fuzz campaigns 60+ s with zero crash artifacts; deny checks, MSRV, aarch64 check, and byte-identical release rebuilds pass | `campaigns.json`, deny/msrv/aarch64 logs, `release-binaries.json` |
| Version-skew fail-closed coordinated upgrades | `fuzz/qualify-m5.sh run` stage `everssh-version-skew` | pinned old peer `43e80cc`; both whole-product directions plus protocol-edge fixtures | recognizable old records yield `unsupported protocol version; coordinated everssh upgrade required`; old client rejects v2; role markers fail before negotiation; no fallback | `gates/everssh-version-skew.log`; `crates/everssh/tests/version_skew.rs` |
| No terminal emulation, semantic replay, scrollback, second SSH, restricted/GPL production code | dependency-boundary tests + `cargo-deny` root/fuzz + release artifact inspection | clean release SHA | boundary gates pass; deny bans prohibited licences; release contains exactly the three contracted binaries | root-test, deny logs, release build logs |

Closure rule: `eversh-chl.6` closes only on one M5 `PASS` receipt whose
`head_sha`/`tree_sha` match a clean commit, every subreceipt hash verifies,
and the sanitized receipt plus this matrix are tracked outside `target/`.
