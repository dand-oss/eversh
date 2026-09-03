# eversh

Persistent remote shells without a terminal multiplexer or a remote screen buffer.

> [!IMPORTANT]
> eversh is in the design phase. There is no usable release yet. The commands below describe the intended v1 interface and may change only through the design-review gates in [plans/design.md](plans/design.md).

eversh keeps two independent failures independent: `everpty` keeps the remote PTY and process alive when its client disappears, while `everssh` carries an ordinary OpenSSH connection over a roaming QUIC path. `eversh` composes both pieces into the normal user experience, and each component remains useful separately.

## Product boundary

Modern terminal emulators such as Kitty already provide tabs, splits, scrollback, copy and paste, graphics protocols, and rich keyboard handling. eversh therefore leaves terminal interpretation and scrollback entirely to the local terminal, keeps the remote process alive independently of the connection, lets OpenSSH continue to own authentication and SSH semantics, and replaces the fragile TCP path beneath OpenSSH with a QUIC path that can survive address changes.

eversh does not provide terminal prediction or local echo. QUIC is a reliable ordered byte transport, not latency magic, and the SSH stream remains subject to network round-trip time.

## The three components

### `everpty`

`everpty` is a reusable Rust PTY/session library and standalone executable. It creates one PTY, starts one child process, and exposes the live byte stream through a private Unix socket. It provides named daemon-per-session PTYs, `start`, `attach`, `observe`, `list`, `current`, `detach`, and `kill`, one lossless healthy writer, live best-effort read-only observers, `Busy` by default, explicit `--take-over`, writer-controlled resize, child exit reporting, bounded writer-stall handling, and continuous drain-and-discard only when no attached client can accept output.

`everpty` has no Tokio or noq dependency in its core. Its implementation uses a small poll-based event loop or a bounded fixed worker design; it never creates an unbounded task or thread per output frame.

`everpty` deliberately has no terminal parser, virtual screen, screen model, history file, output ring, replay, log, scrollback, alternate-screen handling, attach-time redraw, newline conversion, or detach-key interception. It forwards arbitrary bytes unchanged.

### `everssh`

`everssh` is a reusable Rust QUIC byte-link library and standalone executable. In its primary mode it is an OpenSSH `ProxyCommand`: the client side reads and writes standard I/O, the server side connects to the authorized loopback `sshd`, and one ordered QUIC stream carries the opaque OpenSSH byte stream in both directions.

V1 uses exactly one Tokio runtime for `everssh`, `noq` with its reviewed rustls path, TLS 1.3, one authenticated reliable bidirectional stream, standard QUIC migration, and bounded flow control. `everssh` does not parse SSH or terminal data, implement SSH authentication, own PTYs, or predict input. If a QUIC connection dies, its v2 association opens one bounded reconnect epoch and retransmits opaque frames retained until cumulatively acknowledged; already-delivered duplicates are suppressed. The configured association lease is 360 seconds, the client reconnect budget is one per-outage epoch of lease minus one handshake timeout, and each direction retains at most 4 MiB / 1,024 frames. Observed production recovery is 302 seconds on IPv4 and 22 seconds on IPv6; production-scale terminal expiry is proven in the root netns gate.

The QUIC server is launched through an already authenticated OpenSSH bootstrap. The bootstrap delivers an ephemeral certificate pin, one-use token, and association identity. A failed QUIC connection enters the bounded association epoch above; terminal association failure, lease/budget expiry, or queue exhaustion ends the inner SSH connection and requires a fresh SSH connection. Protocol-version mismatches fail closed with a coordinated-upgrade diagnostic. Quinn is retained only as a documented Rust fallback if the bounded noq feasibility gate cannot pass the required standard migration tests.

### `eversh`

`eversh` is a reusable Rust supervisor library and standalone user-facing executable. It invokes the installed system OpenSSH client, uses the existing SSH configuration, keys, agent, host-key policy, forwarding, SFTP, and SCP behavior, starts `everssh`, and requests remote `everpty` operations.

`eversh` is a thin supervisor. It does not relay terminal data, parse terminal bytes, own a PTY, or become a second SSH implementation. For a named persistent `everpty` session, it decides when to retry after an unexpected transport failure, starts a fresh SSH connection, verifies that the same session is still alive, and reattaches it. It never automatically restarts raw SSH commands, forwarding, SFTP, or SCP.

## Topology

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

The ownership boundaries are intentional: the local terminal owns rendering and scrollback, OpenSSH owns user and host authentication and SSH features, `everssh` owns the roaming encrypted byte transport, `everpty` owns PTY and child lifetime, and `eversh` owns composition and reconnect policy.

V1 installs exactly three physical executables from the same reusable crates: standalone `everpty`, standalone `everssh`, and the user-facing combined/multi-role `eversh` executable. The combined `eversh` binary contains all three libraries and private role dispatch, but persistent PTY brokers and one-shot QUIC servers remain separate operating-system processes.

## No retained or replay output buffer

While attached, PTY bytes are forwarded unchanged. The current writer is lossless while it remains responsive: finite live queues may apply PTY backpressure, but bytes are not silently dropped. A writer that exceeds the configured stall deadline is detached, its live queue is discarded, and PTY draining resumes. Observers are best-effort, continue receiving future output when no writer is attached, and are disconnected if their finite live queues fill. Output is drained and discarded only when no attached client can accept it. A new attachment receives only bytes produced after its accepted attachment; no old output, screen, log, snapshot, or replay is sent. Kernel queues and bounded live delivery or QUIC retransmission state are delivery buffers, not retained session history.

Standard QUIC migration may preserve the same live SSH stream. If the QUIC connection expires during a named persistent session, the old SSH stream ends and eversh may open a fresh SSH connection, confirm that the PTY broker is still alive, and reattach it. eversh never resumes an expired SSH stream, reruns a command or transfer, or claims exactly-once delivery across connections.

## Intended v1 commands

~~~bash
eversh connect badger.a --session work
eversh connect badger.a --session editor -- nvim
eversh attach badger.a work --take-over
eversh list badger.a
eversh resume-all badger.a
eversh kill badger.a work

everpty start work -- bash --login
everpty attach work
everpty observe work
everpty attach work --take-over
everpty list
everpty current
everpty kill work

everssh ssh-proxy HOST PORT
ssh -o 'ProxyCommand everssh ssh-proxy %n %p' server.ever
~~~

When the remote user's non-interactive `PATH` does not include the install
directory, select the compatible remote executable explicitly:

~~~sh
ssh -o 'ProxyCommand everssh ssh-proxy --remote-bin /home/alice/bin/everssh %n %p' server.ever
~~~

`--remote-bin` accepts a canonical absolute path only; it does not invoke a
local shell or accept remote command fragments.

Closing a connection detaches it; the child continues running. There is no special detach key because eversh does not intercept terminal input. A second writer receives `Busy` unless `--take-over` is explicit. A healthy writer is lossless; a writer that exceeds its finite stall deadline is detached rather than allowed to consume unbounded memory. Observers receive future output only, cannot resize or write, are disconnected if they lag, and remain eligible to receive output while the session has no writer.

## V1 scope

V1 targets Linux and directly reachable UDP, including ZeroTier or Tailscale overlay addresses. It supports standard QUIC migration, bounded association resume, real OpenSSH compatibility, exactly three physical executables, named PTY sessions, terminal-failure reconnect into the same session, and no retained or replay output history.

V1 does not include public relays, rendezvous services, accounts, custom NAT traversal, QAD, negotiated multipath, QNT, 0-RTT, Windows support, browser clients, or arbitrary public proxy targets. The bounded candidates and permanent non-goals for later work are in [plans/v2.md](plans/v2.md).

## Rust workspace

All original implementation code is Rust in one Cargo workspace with one `Cargo.lock`. The workspace contains reusable `everpty`, `everssh`, and `eversh` crates plus thin binary targets. The production dependency graph contains no terminal-emulation crate, no second SSH implementation, no Asupersync dependency, and no GPL/AGPL or custom-restricted dependency.

`everpty` has no Tokio/noq core dependency. `everssh` uses one Tokio runtime and noq's reviewed rustls integration. `eversh` remains a supervisor and uses no data-relay loop. The remote side must already have a compatible combined `eversh` binary or the required standalone roles on `PATH`; v1 does not upload binaries, self-update, or run an upgrade agent. Protocol versions fail closed with clear stderr diagnostics, and compatibility is by protocol version rather than assumed binary version. A broker may keep running across an on-disk binary upgrade; a later client may attach only if it supports the broker's live protocol version. Recursive ProxyCommand use is disabled for bootstrap, ProxyJump is not guessed, and direct or overlay UDP endpoint rules are explicit. The exact Rust toolchain, MSRV, noq release, rustls features, limits, endpoint policy, and acceptance gates are normative in [plans/design.md](plans/design.md).

## References and licence

Keepty is the primary permissively licensed structural reference for PTY ownership and Unix-socket framing; its replay, parser, screen, redraw, logging, and input-interception behavior is excluded. GPL or AGPL projects are behavioral references only. Asupersync and ATP are design/test references only because their licence and runtime boundaries are incompatible with this project; eversh adopts their Request -> Drain -> Finalize shutdown pattern without depending on Asupersync. The complete evidence inventory is in [plans/reference.md](plans/reference.md).

eversh is dual-licensed under the [MIT licence](LICENSE-MIT) or the [Apache License 2.0](LICENSE), at the user's option. Dependencies and incorporated code must be compatible with both distribution choices.

Markdown prose is not hard-wrapped: keep each paragraph and each list item on one physical line.
