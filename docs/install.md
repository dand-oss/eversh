# Installing and upgrading eversh v1

eversh is three Rust executables built from one workspace: the combined
multi-role `eversh` (the user-facing supervisor), standalone `everpty` (the
PTY session broker), and standalone `everssh` (the QUIC ProxyCommand).
V1 targets Linux with directly reachable UDP between the client and the
remote host (including ZeroTier or Tailscale overlay addresses).

## Build

Requirements: Rust 1.88 or newer (the release is qualified with 1.95.0) and
a Linux host.

    cargo build --release --locked --features everpty/cli,everssh/cli,eversh/cli

The three binaries land in `target/release/{eversh,everpty,everssh}`.
Every `[[bin]]` is gated behind its own crate's `cli` feature and no single
crate's feature implies the other two (`eversh/cli` enables `everssh/cli`
but not `everpty/cli`), so the feature-less build produces none of them;
the command above is the exact release-build invocation the qualification
receipt uses.
Release artifact hashes for a qualified build are recorded in the release
qualification receipt under `target/qualification/eversh/`.

## Install

Local (client) host: place `eversh` on `PATH` (for example
`~/.local/bin/eversh`). The supervisor re-invokes its own executable with a
private `__everssh` role marker for the everssh transport role, so a
single installed binary is sufficient locally.

Remote host: v1 does not upload, install, or update remote binaries
(design section 8); the remote host must already have a compatible `eversh`
on the login `PATH`, or you must point at it explicitly:

    eversh connect myhost --remote-eversh /opt/eversh/bin/eversh --session work

`--remote-eversh WORD_OR_PATH` is a global flag (valid on every subcommand)
naming the remote combined binary as a bare `PATH` word or an absolute path;
it defaults to `eversh`. The standalone `everpty` and `everssh` binaries
are optional operator tools; the combined binary serves both roles
remotely.

## Use

    eversh [--remote-eversh WORD_OR_PATH] connect HOST [--session NAME] [--take-over] [--ssh-option OPTION]... [-- COMMAND...]
    eversh [--remote-eversh WORD_OR_PATH] attach  HOST NAME [--take-over] [--ssh-option OPTION]...
    eversh [--remote-eversh WORD_OR_PATH] observe HOST NAME [--ssh-option OPTION]...
    eversh [--remote-eversh WORD_OR_PATH] list    HOST [--local-host NAME] [--json] [--ssh-option OPTION]...
    eversh [--remote-eversh WORD_OR_PATH] resume-all HOST [--local-host NAME] [--ssh-option OPTION]...
    eversh [--remote-eversh WORD_OR_PATH] detach  HOST NAME [--ssh-option OPTION]...
    eversh [--remote-eversh WORD_OR_PATH] kill    HOST NAME [--ssh-option OPTION]...
    eversh ssh     HOST [-- SSH_OPTIONS... [-- COMMAND...]]

OpenSSH remains authoritative for authentication, host keys, ssh_config,
aliases, ports, agents, and certificates. eversh injects only its own
ProxyCommand (first on the command line, so it wins under OpenSSH
first-obtained-value semantics); configure ports and identities in
`~/.ssh/config` or pass audited options with `--ssh-option` (for example
`--ssh-option -F/path/to/config`, `--ssh-option -oConnectTimeout=7`).
`--ssh-option` is accepted on `connect`, `attach`, `observe`, `list`,
`resume-all`, `detach`, and `kill`; each value is audited by
`everssh::ssh_policy::audit_ssh_option` (the same `ALLOWED_O` allowlist
documented in `crates/everssh/src/ssh_policy.rs`) before it is threaded
through to both the outer `ssh` invocation and the everssh bootstrap —
anything else, including `-oProxyCommand=...` or `-J`, is rejected before
any process is spawned — ProxyJump configurations are rejected with a clear
diagnostic (design section 8); the UDP endpoint must be directly reachable.
`eversh ssh` (raw passthrough over everssh) takes its trailing tokens
verbatim and unaudited; see the note below.

`resume-all` opens one Kitty tab per matching live session, targeting
`KITTY_LISTEN_ON` when set; failed attaches stay visible in their tab and
every partial failure is reported.

**Raw mode's inner separator:** the tokens after `eversh ssh HOST --` may
contain one further literal `--`: tokens before it are passed to the outer
`ssh` client verbatim as SSH options (unaudited; the subset that passes the
`--ssh-option` audit is also mirrored into the everssh bootstrap), and
tokens after it become the remote command, placed after the destination.
With no inner `--`, every token is an SSH option — `eversh ssh HOST -- -4`
behaves exactly as before. Raw `eversh ssh` is never retried and never
passes a link-status file, so its exit is always reported as the ssh client
itself left it.

**State root and the link-status channel:** interactive operations
(`connect`, `attach`, `observe`) and every reconnect probe allocate a
private per-spawn link-status file under eversh's state root —
`$EVERSH_STATE_DIR`, else `$XDG_RUNTIME_DIR/eversh`, else
`$XDG_STATE_HOME/eversh`, else `~/.local/state/eversh` (directory `0700`,
files `0600`). The file's path travels to the local everssh ProxyCommand
edge as a `--status-file` argument — never an environment variable — so no
ambient or remotely forwardable value can instrument a spawn. If no state
root resolves at all, or the root's path cannot travel as that argument
(for example it contains `%`, which OpenSSH would expand), the operation
fails with a clear local error before any `ssh` process is spawned.

## Upgrade

Upgrades are operator actions: replace the installed binaries. Compatibility
is decided by wire protocol versions, not file names (design section 8):

- A running everpty broker survives an on-disk binary replacement; later
  clients must speak the broker's live protocol version and fail closed with
  a clear diagnostic otherwise, without disturbing the broker.
- everssh's bootstrap record and QUIC application protocol
  (`eversh-link/1`) are versioned; mismatches fail closed on stderr.
- The private eversh remote-role grammar is versioned (`v1`); a version
  mismatch names the component and version and exits without side effects.

Upgrade the remote host with the same operator mechanism you use for any
remote binary; there is no self-update or upgrade agent in v1.
