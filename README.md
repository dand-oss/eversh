# eversh

Persistent remote shells without a terminal multiplexer or a remote screen buffer. Sessions survive lost connections and roam across address changes, while your local terminal keeps owning rendering, scrollback, copy/paste, and keyboard handling.

eversh is a released product. The names follow one pattern: `ever` + the thing made persistent. One Cargo workspace installs four executables:

- `eversh` — the ever-shell: the user-facing supervisor. It drives your system OpenSSH client, creates and reattaches named remote sessions, and never touches terminal bytes itself.
- `everpty` — the ever-pty: the PTY session broker. One daemon per named session keeps the remote child alive while clients come and go.
- `everssh` — the ever-ssh: the roaming QUIC transport. It carries an ordinary OpenSSH connection over TLS 1.3 QUIC with standard migration and a bounded reconnect window.
- `everudp` — the ever-udp: the direct terminal transport. After an SSH-authenticated bootstrap, terminal bytes travel directly between your terminal and a persistent per-session gateway on the remote host.

## Quick start

Build (Linux, Rust 1.88 or newer; releases are qualified with 1.95.0):

~~~bash
cargo build --release --locked --features everpty/cli,everssh/cli,everudp/cli,eversh/cli
~~~

Put `eversh` on `PATH` on the local host and on the remote host's login `PATH`, then:

~~~bash
eversh connect badger.a --session work
eversh connect badger.a --session editor -- nvim
eversh attach badger.a work --take-over
eversh observe badger.a work
eversh list badger.a
eversh resume-all badger.a
eversh detach badger.a work
eversh kill badger.a work
~~~

`connect`, `attach`, `observe`, and `resume-all` accept `--transport everssh|everudp|auto` (default `everssh`); with `everudp`, SSH is used only to bootstrap and recover, and terminal bytes ride a direct QUIC stream. Every session command accepts audited `--ssh-option` values, and `--remote-eversh WORD_OR_PATH` selects the remote binary when it is not on the login `PATH`. Full usage, install, and upgrade instructions are in [docs/install.md](docs/install.md).

## How it fits together

~~~text
Kitty or another local terminal emulator
  owns rendering, screen state, scrollback, copy, paste, and keyboard handling
                  |
                  v
          system OpenSSH client
                  |
                  | ProxyCommand stdin/stdout
                  v
        everssh client ===== QUIC/UDP ===== everssh server
                                                |
                                                | TCP loopback
                                                v
                                         remote OpenSSH sshd
                                                |
                                                | remote command
                                                v
               everpty attach -- Unix socket -- PTY broker -- child process
~~~

The boundaries are deliberate: the local terminal owns rendering and scrollback; OpenSSH owns authentication, host keys, ssh_config, forwarding, SFTP, and SCP; everssh owns the roaming encrypted byte transport (everudp the direct terminal path); everpty owns PTY and child lifetime; eversh owns composition and reconnect policy.

## Behavior

- Closing your connection detaches it; the child keeps running. There is no detach key because eversh does not intercept terminal input.
- A reattachment receives only output produced after it: everpty keeps no scrollback, log, snapshot, or session history, so output produced while detached is discarded rather than stored.
- A second writer gets `Busy` unless `--take-over` is explicit. A healthy writer is lossless; a writer that exceeds its stall deadline is detached instead of being allowed to consume unbounded memory. Observers are read-only, see future output only, and are disconnected when they lag.
- A lost QUIC connection opens one bounded reconnect epoch (360 s association lease by default): the association retransmits unacknowledged opaque frames and suppresses duplicates, so a live SSH stream survives short outages byte-exactly. Past the lease the transport ends, and eversh opens a fresh SSH connection to reattach the same session. Raw `eversh ssh`, forwarding, SFTP, and SCP are never restarted automatically.
- No local echo or prediction: interactive latency remains network round-trip time.

## Requirements and compatibility

Linux with directly reachable UDP between client and host (ZeroTier or Tailscale overlay addresses work). The remote host needs a compatible eversh binary; compatibility is decided by wire protocol version, and a mismatch fails closed with a diagnostic naming the component and version. There is no relay, rendezvous service, account, custom NAT traversal, or Windows support.

## Documentation

- [docs/install.md](docs/install.md) — build, install, usage, and upgrades
- [docs/design.md](docs/design.md) — architecture and component contracts
- [plans/everudp-v1.md](plans/everudp-v1.md) — frozen everudp contract and release decision
- [plans/reference.md](plans/reference.md) — reviewed reference projects and licence decisions
- [docs/release-evidence/](docs/release-evidence) — qualification receipts and measurements

## Licence

eversh is dual-licensed under the [MIT licence](LICENSE-MIT) or the [Apache License 2.0](LICENSE), at the user's option. Dependencies and incorporated code must be compatible with both distribution choices.

Markdown prose is not hard-wrapped: keep each paragraph and each list item on one physical line.
