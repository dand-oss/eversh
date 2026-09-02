# eversh engineering references

Status: evidence inventory supporting the locked Rust design | Last updated: 2026-08-30

This document records reviewed projects, source snapshots, protocol evidence, and licence decisions for `everpty`, `everlink`, and `eversh`. A reference is not automatically a dependency or source of code. The normative contract is [design.md](design.md); this file records why its boundaries were selected.

## Governing contract

- The local terminal emulator owns rendering, screen state, scrollback, copy, paste, keyboard encoding, and terminal features.
- `everpty` owns a PTY and child process, forwards live bytes unchanged, keeps attached observers receiving future output even without a writer, drains and discards only when no attached client can accept bytes, and never reconstructs a previous screen.
- `everlink` carries opaque OpenSSH bytes over one ordered QUIC stream and never parses terminal or SSH data.
- System OpenSSH remains responsible for user authentication, host authentication, configuration, PTY negotiation, forwarding, command execution, SFTP, and SCP.
- A live QUIC connection may hold bounded unacknowledged transport data, but a replacement connection never receives application bytes from an expired connection.
- A failed migration ends the SSH stream; `eversh` opens a fresh SSH connection and reattaches the surviving `everpty` session.
- No component provides local echo, prediction, terminal-state synchronization, or application replay.

## Locked implementation decision

All original implementation code is Rust in one Cargo workspace. The workspace has three reusable crates and exactly three physical binaries: standalone everpty, standalone everlink, and combined/multi-role eversh. everpty has no Tokio or noq dependency in its core and uses a small poll-based loop or bounded fixed workers. everlink uses exactly one Tokio runtime, noq, and its reviewed rustls path.

Milestone 0 is a bounded Rust/noq feasibility and exact dependency-pin gate, not a language comparison. The gate proves one-stream ProxyCommand behavior, SSH bootstrap trust, standard migration, loss and reordering, half-close, bounded backpressure, path failure, process exit, and Request -> Drain -> Finalize shutdown. Quinn remains a documented Rust fallback only if noq fails a required migration test or cannot provide a supportable exact pin.

## Reviewed source snapshots

These exact snapshots were reviewed by 2026-08-30, with the transport-resume
additions below reviewed by 2026-09-02. They are evidence snapshots, not approved
dependencies unless the design and licence checks explicitly add them.

| Project | Reviewed snapshot | Licence | Use or boundary |
| --- | --- | --- | --- |
| [Keepty](https://github.com/BorjaGM1/keepty) | `5db15668a6843b3f2640619c4837fe4f34e7ae26` | MIT OR Apache-2.0 | Primary PTY ownership, Unix-socket framing, roles, and deferred-spawn reference; compatible code may be adapted with attribution. |
| [atch](https://github.com/dand-oss/atch) | `90c3d2f09834a3394a144296ec65efea18f34859` | GPL | Session names and management behavior reference only; no source, tests, comments, logs, or distinctive structure. |
| [dtach](https://github.com/crigler/dtach) | `b027c27b2439081064d07a86883c8e0b20a183c9` | GPL-2.0 | Minimal PTY loop and drain behavior reference only. |
| [zmx](https://github.com/neurosnap/zmx) | `ea45749278bac648ab13a4280a6035012854d717`; zmosh base `cd88d1b` | MIT | Daemon-per-session and discovery UX reference; screen snapshots and scrollback excluded. |
| [tty7](https://github.com/l0ng-ai/tty7) | `a2b5ae56d920fa8fadb05b7e9141cb9fe8e23a48` | Apache-2.0 | Raw replay and authoritative client-terminal comparison; a full terminal workbench, not an `everpty` component. |
| [OpenAI Codex CLI](https://github.com/openai/codex) | `rust-v0.151.0` | Apache-2.0 | Application-owned structured transcript, resize reflow, transcript overlay, and session-resume evidence. |
| [zmosh](https://github.com/dand-oss/zmosh) | `205e8394c8841798d96c21d66bdba5155ee04868` on `replant-zmx0.7` | MIT | QUIC adapter failure cases, timers, bounded egress, FIN, loss, reorder, and SSH-bootstrap test reference. |
| [quicz](https://github.com/dand-oss/quicz) | `067e7bab687536c1327fb436484dee85d5368318` | MIT | Zig transport test evidence only; eversh does not inherit zmosh's language or Ghostty constraints. |
| [quicssh-rs](https://github.com/oowl/quicssh-rs) | `d748a0f0f5fafea95ff4072d58c397a0afa809ac` | MIT | Rust ProxyCommand topology reference; reviewed certificate and gateway shortcuts are rejected. |
| [noq](https://github.com/n0-computer/noq) | `c334d2da218226777d61fdfd32cb0a45b2cdb7e3`; selected release `=1.1.1`, crate SHA-256 `09e4bb6601fa543c110d8957813267d5a8d775a0f8fbaccf1f615d06ba9b10da`, tag noq-v1.1.1 at `12a4bf0b42070b570fb8cf90fe315c630b03f56e` | MIT OR Apache-2.0 | Selected transport by Milestone 0 (2026-08-21): default features off, exactly `runtime-tokio`, `rustls`, `ring`, `bloom`; rustls 0.23.43 via `noq::rustls` with ring; build toolchain Rust 1.95.0, MSRV 1.88. |
| [Quinn](https://github.com/quinn-rs/quinn) | API/behavior reference reviewed alongside noq | MIT OR Apache-2.0 | Rust fallback only if noq fails required standard migration tests. |
| [moul/quicssh](https://github.com/moul/quicssh) | `1c771b69d1a702804637d1aa47ffadb9fc724109` | Apache-2.0 | One-stream OpenSSH ProxyCommand topology reference; old security and lifecycle choices are rejected. |
| [udp-link](https://github.com/pgul/udp-link) | `5493f7de5939829acc770deda8793e6d6fb5e8df` | MIT | SSH-assisted one-shot launch and stdout bootstrap boundary reference; custom reliable-UDP protocol is rejected. |
| [tsshd](https://github.com/trzsz/tsshd) | `7fe3f454a8446de849b56e6b93fcaa0fd2604fd1` | MIT | Ownership, reconnect, PTY, and hostile-network test ideas; its SSH replacement and output cache are rejected. |
| [trzsz-ssh](https://github.com/trzsz/trzsz-ssh) | `dca1425cd9c63f342e03706e53f3e3885cee9597` | MIT | Bootstrap and reconnect comparison; terminal filtering, redraw, and input policy are rejected. |
| [StableSSH](https://github.com/hrntknr/stablessh) | `22318e4fd7736cc89128fb89378ac5ea8574e495` | MIT | Proof of the application acknowledgements, replay queues, and persistent gateway required for hard stream resumption; rejected by design. |
| [quic-send](https://github.com/maxomatic458/quic-send) | `687bd48f9006a3e7e5235dab1de18e4e27adb014` | MIT | Resumable QUIC transfer and hole-punching evidence; file-transfer state cannot be reused for an opaque SSH byte stream. |
| [fsend](https://github.com/maxomatic458/fsend) | `7ea94ca910d8ac08f3250c7a34d6b5bce2af1ca0` | MIT | WebRTC/Iroh resumable-transfer comparison; browser storage and transfer-chunk semantics are outside everssh. |
| [QCP](https://docs.rs/qcp/latest/qcp/) | source `599a0fb07feb93eb3a1f1bb469ccde96435bc7bd`, docs 0.9.0 | AGPL-3.0 | SSH-assisted QUIC bulk-transfer architecture and transport tuning evidence only; licence and one-shot transfer semantics exclude code reuse. |
| [bitbang](https://github.com/richlegrand/bitbang) | `8db7931e13918713aa100c2aa3f767335eb66d23` | MIT | Trustless-signaling/WebRTC P2P reachability comparison; its URL bearer model and browser-facing framework are not an everssh transport. |
| [neqo](https://github.com/mozilla/neqo) | `e7ce4aa4bc8b02b6f5457c065c65abc24e43d14d` | MIT OR Apache-2.0 | Alternate Rust QUIC implementation and test-suite evidence; no change to the pinned noq selection. |
| [p2psh](https://github.com/tovsaa/p2psh) | `6dc884cd427dadfe1e7efb154f8a41510bf7aada` | Apache-2.0 | WebRTC DataChannel SSH-like shell, hybrid post-quantum handshake, signaling privacy, and bounded resume-chain comparison. |
| [sshx](https://github.com/suutaku/sshx) | `819701ff9fe618cd53cd1980bbef3139330fc7ba` | MIT | Go/pion WebRTC P2P SSH tunnel comparison; signaling and daemon architecture reviewed, not adopted. |
| [Terminal7](https://github.com/tuzig/terminal7) | `e45109b904449bfe328fb7e99cd097a7760fe8d3` | GPL-3.0-only | Smart-client terminal multiplexer and WebRTC behavior reference only. |
| [ws-terminal](https://github.com/uditrajput03/ws-terminal) | `b8e1e85439c9d859de6d582aad51db3069cb44b2` | MIT | Outbound WebSocket/PTY reachability comparison; no encryption-by-default or stream-resume contract. |
| [ws-relay](https://github.com/uditrajput03/ws-relay) | `fe5aa0622bc4f2511d1b0dbb285210c07b018698` | ISC | Simple relay/channel architecture and its trust exposure; not a candidate data plane. |
| [quic-go](https://github.com/quic-go/quic-go) | `cf0c4ffd0ce6af5172fa59cde9b82ec19b2bf029` | MIT | Historical one-stream and migration API evidence only; it is not an eversh implementation candidate. |
| [Asupersync](https://github.com/Dicklesworthstone/asupersync) | `289402bcf6746533d98153ca1fcae21333fe6a71` | custom MIT-like licence with OpenAI/Anthropic restriction | Request -> Drain -> Finalize and structured-cancellation reference only; no dependency or copied source. |
| [ATP](https://github.com/Dicklesworthstone/atp) | distribution `1df65ca1f483418ccdf9c6c977184a83df4df531`; pinned Asupersync `cb87a3546bc7cf5d87ccbcca3a95c74ec3fcdcbd` | custom MIT-like licence with OpenAI/Anthropic restriction | Fountain-coded bulk-transfer and bounded-memory test comparison only; no dependency or protocol reuse. |
| [Mosh](https://github.com/mobile-shell/mosh) | current product/protocol reference | GPL-3.0-or-later | Roaming and sleep/wake test conditions; terminal state, prediction, and replay are permanent non-goals. |
| [MoshCatty](https://github.com/binaricat/MoshCatty) | `554b9d305e7ac4b11de740d764bbc3e05f816d7b` | GPL-3.0-or-later | Rust loss/reorder and Mosh interoperability test reference only. |
| [RoSE](https://github.com/nikhiljha/rose) | `f145dfc383d925d9703d500d24f8f95bf8edcdfd` | GPL-3.0-or-later | Quinn/rustls and hostile-network test comparison only; remote terminal state is excluded. |

## Reviewed transport articles

These articles were reviewed by 2026-09-02 as behavior evidence, not dependency
approval:

| Article | Use or boundary |
| --- | --- |
| [Rust WebRTC without the WebRTC glue](https://archive.casouri.cc/note/2024/rust-webrtc/index.html) | Maps the ICE/DTLS/SCTP layering and cert-fingerprint exchange needed if a future native WebRTC transport is evaluated. |
| [BitBang: one binary, one URL, zero config](https://hackaday.com/2026/08/03/get-a-remote-terminal-with-one-binary-one-url-and-zero-config/) | Documents browser-facing P2P terminal reachability and trustless-signaling tradeoffs. |
| [Trickling ICE over SSH](https://terminal7.dev/posts/trickling_ice_over_ssh/) | Shows SSH as an authentication/signaling channel before upgrading a Terminal7 session to WebRTC. |
| [Replacing WebRTC](https://moq.dev/blog/replacing-webrtc/) | Contrasts WebRTC's P2P/ICE strengths with QUIC/WebTransport and why neither magically provides terminal prediction. |

## PTY references

Keepty is the strongest permissively licensed structural reference. It separates a broker-owned PTY from clients over typed length-prefixed Unix-socket frames, supports roles and terminal size, delays spawn until a client is ready, and has byte-oriented tests. eversh may adapt compatible Rust code only with the required notices and only after removing incompatible behavior.

Keepty's output ring, replay on attach, vt100 monitor, screen state, alternate-screen handling, resize/redraw nudge, newline transformation, and intercepted input are not disabled options; they are absent from the eversh protocol and data structures.

dtach confirms the minimal process model: one process owns the PTY, Unix sockets attach clients, output is forwarded as bytes, and the PTY is drained without an attached client. It is GPL-2.0, permits behavior eversh rejects, and is a behavioral reference only.

atch and zmx confirm useful names, session directories, list/current/kill, stale cleanup, daemon-per-session separation, and attach-versus-create UX. Their logs, scrollback, replay, multiple writers, terminal parsing, and screen restoration are excluded.

## Terminal ownership evidence

Kitty's [FAQ](https://sw.kovidgoyal.net/kitty/faq/) and [multiplexer explanation](https://github.com/kovidgoyal/kitty/issues/391#issuecomment-638320745) support keeping a real local terminal directly attached so it retains native scrollback, graphics, OSC-52, keyboard protocols, and rendering. The narrower eversh claim is testable: eversh itself never parses terminal output.

Ghostty and ghostty-vt are useful compatibility-test targets for transparent bytes, but no terminal-emulation crate, virtual grid, snapshot, scrollback model, or restore behavior belongs in the production graph. tmux or screen may run inside an everpty session if the user chooses; eversh does not reproduce them.

### Application-owned redisplay and competing restoration models

The attachment layer cannot safely guess when to restore scrollback. Raw PTY output does not distinguish durable semantic history from alternate-screen state, animations, secrets, or terminal queries with side effects. The stable boundary is therefore ownership, not a better heuristic: `everpty` preserves the child and PTY, applies the attaching writer's real dimensions, and forwards future bytes; the application restores meaning from application state when it supports doing so.

| Layer or product | Retained authority | Attachment or recovery behavior | Relevance to eversh |
| --- | --- | --- | --- |
| `everpty` | Child process, PTY, ownership, and bounded live delivery only | Starts future-byte delivery at the accepted boundary | The v1 core contract. |
| tty7 | Bounded raw-output replay ring segmented by terminal dimensions; its client owns an Alacritty terminal model | Sends the current size and raw snapshot segments for the client terminal to parse and render | Valid full-workbench design, but not safe to copy unless eversh also owns the terminal client and renderer. |
| zmx and zmosh | A daemon-side Ghostty VT shadow model | Sends a semantic terminal snapshot on attachment | Valid generic-TUI restoration layer, intentionally excluded from `everpty`. |
| Superlogical | Announced server-side libghostty state plus capable clients running the same terminal state machine | Described design sends synchronized terminal state at attachment, then follows raw PTY output while scrollback arrives separately | Promising terminal-owning product above the PTY layer; pre-beta and not public enough to audit or benchmark, so it does not alter the v1 core. |
| Codex CLI | Structured conversation cells and persisted thread state | Reflows from application cells on resize, opens its transcript with `Ctrl+T`, and resumes a dead process with `codex resume` | Preferred application-native recovery for Codex sessions; no PTY replay is needed. |

tty7 does not use zmx's shadow-VT architecture. Its daemon [stores a bounded raw replay ring segmented by dimensions](https://github.com/l0ng-ai/tty7/blob/a2b5ae56d920fa8fadb05b7e9141cb9fe8e23a48/crates/tty7-core/src/daemon/scrollback.rs#L1-L63) and [sends size-tagged raw snapshot segments](https://github.com/l0ng-ai/tty7/blob/a2b5ae56d920fa8fadb05b7e9141cb9fe8e23a48/crates/tty7-core/src/daemon/pane.rs#L2435-L2439). The client then feeds those bytes into its [authoritative Alacritty terminal parser](https://github.com/l0ng-ai/tty7/blob/a2b5ae56d920fa8fadb05b7e9141cb9fe8e23a48/src/terminal/remote.rs#L1019-L1027). tty7 can make that replay coherent because it owns the terminal workbench and explicitly handles concerns such as [Kitty graphics commands](https://github.com/l0ng-ai/tty7/blob/a2b5ae56d920fa8fadb05b7e9141cb9fe8e23a48/crates/tty7-core/src/core/kitty_graphics.rs#L1-L16), geometry, resets, and query side effects. A transparent PTY broker does not have that authority.

zmx instead feeds output to both the live client and a daemon-side Ghostty VT, then serializes the terminal model on reattachment; its [implementation description](https://zmx.sh/#impl) explicitly makes the shadow terminal the restoration authority. This is the approach already explored by zmosh and remains available if a higher-level generic terminal-restoration product is required, but it is not needed for applications that can redraw themselves.

Superlogical is the closest announced product to a deliberate hybrid of the tty7 and zmx ideas. Its [official product description](https://www.superlogical.com/) promises long-lived terminal blocks, native scrollback and selection, web and native clients, sharing, and cross-device reconnection; Mitchell Hashimoto's [announcement](https://mitchellh.com/writing/superlogical) says the multiplexer is built on libghostty. The [detailed architecture thread](https://x.com/mitchellh/status/2082936029426892960) describes an authoritative libghostty terminal model on the server while capable clients parse the same raw PTY stream in parallel. On attachment the server supplies synchronized screen state, then live raw output continues; historical scrollback can follow separately. Native splits and view state belong to the clients rather than being redrawn into one server-owned terminal.

That architecture can avoid the normal tmux-style parse-and-re-encode step on the live display path, but it still makes terminal emulation and synchronization part of the product. It must solve exact snapshot/live-stream boundaries, terminal-size authority, version-compatible state machines, client desynchronization, terminal queries, graphics, and access control. The [August 2026 demo](https://x.com/mitchellh/status/2093451043661316217) and [no-learning multiplexer claim](https://x.com/mitchellh/status/2093456226810200230) are useful product-direction evidence, not independent performance or correctness results. As of 2026-08-30 the official site still describes an upcoming beta and possible future open-source releases; there is no public implementation, stable protocol, licence for the complete product, or reproducible benchmark to audit.

Superlogical therefore strengthens rather than weakens the EverPTY boundary. Generic exact restoration is possible when a product deliberately owns matching terminal state on the server and clients. EverPTY does not own those clients and must remain process continuity plus future bytes. Superlogical may become a strong higher-level replacement for zmosh or tty7-style UX when it ships, but it is not a reason to put speculative replay or a VT into the transparent broker.

Codex CLI provides concrete application-owned behavior in the locally reviewed `0.151.0` release. [`Ctrl+T` opens the transcript overlay](https://github.com/openai/codex/blob/rust-v0.151.0/codex-rs/tui/src/app/input.rs#L350-L356), while its [resize handling rebuilds the inline transcript from structured history cells](https://github.com/openai/codex/blob/rust-v0.151.0/codex-rs/tui/src/transcript_reflow.rs#L1-L13). If the application process no longer exists, [`codex resume --last` or `codex resume <thread-id>`](https://learn.chatgpt.com/docs/codex/cli) restores the semantic session. [`Ctrl+L` clears the UI transcript](https://github.com/openai/codex/blob/rust-v0.151.0/codex-rs/tui/src/app/history_ui.rs#L270-L322); it is not a restoration command. This separation is the expected agent workload: EverPTY preserves a still-running process, while Codex owns conversation history and redisplay.

The decision is not to remove `everpty`; it is to keep its abstraction honest. For an opaque full-screen application with no native redraw or semantic history, attachment intentionally yields only future bytes. Users who require exact historical visuals should select a terminal-owning layer such as tty7, zmx/zmosh, tmux, or screen rather than adding replay guesses to the process-continuity core.

## QUIC and SSH evidence

The one-stream ProxyCommand topology in moul/quicssh and quicssh-rs proves that unmodified OpenSSH can run over a QUIC byte stream. Their old certificate verification, always-on gateway, and incomplete EOF behavior are not acceptable security or lifecycle defaults.

udp-link demonstrates an SSH-assisted one-shot process and a bootstrap record over stdout. Its custom reliable-UDP protocol, weak or process-visible key handling, and missing transport guarantees are rejected; QUIC supplies the standardized TLS 1.3, congestion control, connection IDs, path validation, and migration required here.

StableSSH demonstrates the cost of hard resumption: application packet IDs, acknowledgements, resend queues, persistent gateway state, and memory limits. Because its queue contains encrypted SSH bytes, including terminal output, it is direct evidence for keeping hard reconnect above everlink and re-opening OpenSSH.

The [Teleport QUIC discussion](https://github.com/gravitational/teleport/issues/1595) correctly separates transport mobility from perceived latency: QUIC by itself does not provide Mosh-style prediction or remove head-of-line blocking from a single ordered SSH byte stream. eversh intentionally chooses transparent OpenSSH compatibility and migration without claiming terminal prediction or magical latency reduction.

The tsshd/tssh source audit found reconnect output caching, input policy, status injection, escape filtering, and redraw behavior. In particular, the reviewed tsshd output path caches at least a line-count or PTY-height-derived reconnect window, flushes retained output after reconnection, removes cursor-position queries, and may resize the PTY or inject discard warnings. Those choices may be valid for that product, but violate eversh's byte-transparent, no-replay contract.

Mosh reports [#1041](https://github.com/mobile-shell/mosh/issues/1041), [#1281](https://github.com/mobile-shell/mosh/issues/1281), and [#1295](https://github.com/mobile-shell/mosh/issues/1295) document screen corruption or redraw problems reported with Neovim, Vim, tmux, and wrapped lines. Individual issue reports do not prove one root cause, but they are concrete compatibility cases for the rule that everpty and everlink never interpret terminal state and for the byte fixtures that must cover wrapped lines, redraws, and multiplexers running as ordinary child applications.

Standard QUIC migration is distinct from hard reconnect. Migration keeps one connection and its bounded in-flight state over a validated path. Hard reconnect creates new QUIC and SSH connections and cannot preserve the old stream without application replay and exactly-once semantics, which eversh permanently rejects.

## noq, Quinn, rustls, and runtime evidence

noq is the locked feasibility target because it is Rust, MIT OR Apache-2.0, derived from Quinn, and exposes the required QUIC family. The v1 requirement is the standard reliable ordered stream and RFC migration behavior, not noq's draft QAD, multipath, or QNT features. Those features remain disabled until separately justified and tested.

Quinn was retained as a documented fallback within Rust until Milestone 0 selected noq (2026-08-21). It is not a second production implementation: noq is pinned, Quinn was not selected, and the alternative is removed from the production graph.

Asupersync's documented Request -> Drain -> Finalize cancellation pattern is useful for everlink's full-duplex shutdown. The supervisor requests cancellation after the first terminal condition, drains owned copy directions and protocol close work within deadlines, then finalizes sockets, tasks, process state, and secret memory. This pattern is implemented directly in Rust/Tokio and is not an Asupersync dependency.

The [Asupersync integration guide](https://github.com/Dicklesworthstone/asupersync/blob/main/docs/integration.md) explicitly provides selected I/O, Hyper, and Tower bridges but does not construct or enter a Tokio runtime. It does not provide a noq, Quinn, QUIC, UDP, or `noq::Runtime` adapter. A separate runtime island or new adapter would violate the one-Tokio/noq runtime boundary, and its custom licence is outside the project's MIT OR Apache-2.0 dependency policy.

ATP's fountain-coded bulk transfer separates control and data planes, verifies complete objects, and supplies useful pacing, fault, and bounded-memory test ideas. An interactive SSH byte stream is ordered and non-fungible: applying fountain coding would add reconstruction windows, manifests, repair rounds, and application buffering without removing the need for strict ordering. ATP's code and Asupersync source are also outside the dependency licence policy.

## Overlay deployment evidence

ZeroTier is the v1 deployment baseline because it supplies authenticated membership, stable overlay addresses, routing, and NAT traversal. Tailscale is a compatible alternative. eversh therefore does not need a public relay, rendezvous service, account system, or custom NAT traversal in v1.

Ordinary OpenSSH over the same overlay must be measured across Wi-Fi loss, interface changes, sleep/wake, NAT rebinding, packet loss, reordering, and high RTT. That baseline determines whether everlink's standard migration materially improves recovery; it does not weaken the no-replay or OpenSSH ownership contract.

## Additional transport references

### kcp-go

[kcp-go](https://github.com/xtaci/kcp-go) at reviewed commit `f3f1bbd9b9f2c18fde5882c19335ae31c131b077` is MIT-licensed and provides an ordered reliable `net.Conn`-like stream over UDP with retransmission, optional FEC, and packet encryption. It is useful as a recovery-time benchmark under loss and high RTT and as a comparison already exercised by tsshd. It is not selected for everlink: KCP would still require separate authentication, congestion, keepalive, close, MTU, and roaming policy that QUIC standardizes.

### qtelnet

[qtelnet](https://github.com/1995parham/qtelnet) at reviewed commit `012cd6dafbcb02450ba2c0477b6a67ff3d5de2eb` is GPL-3.0 and demonstrates minimal bidirectional terminal-like data over QUIC. It is a smoke-test and API-shape reference only; it has no OpenSSH compatibility, SSH-assisted bootstrap, PTY persistence, hard-reconnect boundary, or eversh licence compatibility.

### USSH and draft-x1co-ussh

[USSH](https://github.com/x1colegal/ussh) at reviewed commit `100447a9cdb291745307b006949d1503a00585f9` and its [draft-x1co-ussh](https://datatracker.ietf.org/doc/draft-x1co-ussh/) describe an experimental SSH-like Python shell over USTPS, not a tunnel for the OpenSSH wire protocol. They are useful for separating transport sequence numbers from application stream positions, retry-token anti-amplification, duplicate/stale handling, and selective-retransmission tests. They are rejected as the everlink protocol because they introduce a separate password/host identity, TOFU store, PTY server, and session protocol and therefore replace OpenSSH authentication, sshd, forwarding, SCP, and SFTP.

The project's [Reddit announcement thread](https://www.reddit.com/r/ssh/comments/1tyo3t0/built_an_sshlike_remote_shell_over_udp_instead_of/) is retained as provenance for the product claims and discussion, not as protocol or security evidence; the repository and Internet-Drafts are the technical sources.

### USTP-Secure and draft-x1co-ustps

[USTP-Secure](https://github.com/x1colegal/USTP-Secure) at reviewed commit `493f268313ca5dc23c435594f8c759d07bfceaa9` and its [draft-x1co-ustps](https://datatracker.ietf.org/doc/draft-x1co-ustps/) define a custom reliable-unordered UDP protocol with transport sequence, application stream position, selective ACK/NACK, X25519 setup, retry tokens, AEAD, congestion options, and a fixed payload. They supply useful reorder, duplicate, gap, bound, and negative custom-roaming tests. They are not everlink: an ordered OpenSSH stream still needs application reassembly, while custom cryptography, congestion, MTU, migration, and endpoint validation duplicate QUIC.

## QUIC-native SSH and HTTP/3 references

### draft-bider-ssh-quic

[draft-bider-ssh-quic-09](https://datatracker.ietf.org/doc/draft-bider-ssh-quic/) is an expired 2020 individual Internet-Draft proposing a new SSH-over-QUIC exchange and channel mapping. It supplies background on duplicate flow control, host-key trust, connection IDs, path mobility, packet sizing, and amplification defense. It is not v1: it is not an OpenSSH standard, changes both endpoints, and would abandon the transparent byte-proxy boundary.

### SSH3

[SSH3](https://github.com/francoismichel/ssh3) at reviewed commit `5b4b242db02a5cfbb9ebf9dfc5aad2c32e10f245` is Apache-2.0 and implements a distinct remote shell over HTTP/3 Extended CONNECT, QUIC/TLS 1.3, HTTP Authorization, X.509 server identity, and its own server. It is useful for HTTP/3, forwarding, PTY, agent, and integration-test comparisons. It is not the everlink transport because it owns a new protocol, server, identity/configuration surface, and session semantics.

### SSHOQ

[SSHOQ](https://github.com/h4sh5/sshoq) at reviewed commit `a46ca8953da9e4e4e6bc4859eb3267de7d913db7` is Apache-2.0 and the maintained SSH3 continuation with HTTP/3, QUIC, rustls-adjacent certificate/authorization handling, OpenSSH-format keys and agent support, OIDC, forwarding, SFTP, and ProxyJump-over-UDP ideas. It is a current comparison for integration and error handling, not a transparent OpenSSH stream and not an eversh dependency.

## Product and UI references

### Oryxis

[Oryxis](https://github.com/wilsonglasser/oryxis) at reviewed commit `a7d66c0b9f96fdac825d412b83f1415c2d02f879` is AGPL-3.0-or-later and is a native Rust SSH desktop client with host import, an encrypted vault, SFTP, and a UI. Its `russh` path and Quinn-based synchronization are useful UX and integration comparisons only; no AGPL code or desktop terminal manager enters eversh.

### Netcatty

[Netcatty](https://github.com/binaricat/Netcatty) is an Electron/React/xterm.js SSH workspace and host for MoshCatty. It supplies examples of session, SFTP, split-terminal, and Mosh integration UX. It is not a production dependency and its xterm.js rendering, workspace, and terminal manager remain outside the eversh core.

### latch

[latch](https://github.com/unixshells/latch) at reviewed commit `44417b56aa122bddc679384cc02a9a7404118c9a` is MIT and combines native SSH, Mosh, browser access, a persistent QUIC relay, a VT emulator, windows, and scrollback. It is useful for relay/NAT architecture, transport adapters, and multi-client test ideas. Its server-side rendering, relay account, browser terminal, and persistent screen are explicitly rejected.

### HerdR and ratatui

The [HerdR guide](https://betterstack.com/community/guides/ai/herdr-ai-agent/) and [ratatui](https://github.com/ratatui/ratatui) demonstrate an application TUI that intentionally renders by interpreting input and emitting terminal control sequences. They are not transparent PTY or transport layers. A ratatui program may run inside everpty like any child, but no ratatui or TUI parser belongs in the eversh data path.

## Historical implementation evidence

### quic-go

[quic-go](https://github.com/quic-go/quic-go) at reviewed commit `cf0c4ffd0ce6af5172fa59cde9b82ec19b2bf029` is MIT and documents standard migration, connection IDs, path probing/switching, TLS, flow control, keepalive, and qlog. Its API and tests are historical transport evidence only; the Rust/noq decision is locked and quic-go is not an eversh implementation candidate.

### tssh and tsshd

[trzsz-ssh](https://github.com/trzsz/trzsz-ssh) at `dca1425cd9c63f342e03706e53f3e3885cee9597` and [tsshd](https://github.com/trzsz/tsshd) at `7fe3f454a8446de849b56e6b93fcaa0fd2604fd1` provide maintained bootstrap, UDP, path-authentication, PTY, forwarding, reconnect, and multi-platform test examples. The source audit also records why they are not a runtime component: reconnect caches output, filters cursor requests, injects status/redraw sequences, controls input during timeout, and implements a replacement SSH/session layer rather than carrying the unmodified OpenSSH stream.

## Decision summary

| Concern | Adopt | Reject |
| --- | --- | --- |
| PTY core | Keepty-informed Unix socket, deferred spawn, one writer, observers, drain/discard | Replay ring, parser, screen state, redraw, newline conversion, logs, input interception |
| Session UX | Names, list/current/kill, stale cleanup, atomic attach-or-create, explicit takeover | Multiple writers, screen restoration, remote scrollback |
| Byte transport | One noq reliable stream, TLS 1.3, Retry, standard migration, SSH bootstrap trust | Custom reliable UDP, QUIC datagrams for SSH, application replay |
| Rust fallback | Quinn only after noq gate failure, with an exact reviewed pin | Parallel production implementations or a second runtime |
| Shutdown | Direct Request -> Drain -> Finalize states with owned tasks and deadlines | Asupersync dependency, unowned cancellation |
| Trust | Existing OpenSSH keys, agent, host keys, ssh_config, authenticated ephemeral pin/token | Long-lived eversh identity, custom account service, unauthenticated gateway |
| Rendering | Local Kitty/Ghostty/terminal emulator | Remote VT, snapshots, scrollback, prediction, viewport emulation |
| Deployment | Linux direct UDP, ZeroTier, Tailscale | v1 relay, rendezvous, custom NAT traversal |

## Required pre-implementation evidence

- Measure ordinary OpenSSH over ZeroTier and Tailscale under interface change, sleep/wake, loss, reorder, NAT rebinding, and high RTT.
- Build the bounded Rust/noq one-stream proxy with authenticated bootstrap and exact rustls feature path.
- Prove real migration by changing the UDP path while preserving the same QUIC connection and SSH stream; replacement QUIC plus hidden replay does not count.
- Prove hard failure by destroying all paths, closing old SSH, opening a new SSH connection, and reattaching everpty with no old output.
- Saturate stdin, stdout, target TCP, writer queue, and observer queue independently and record finite resource behavior.
- Exercise EOF, half-close, SSH commands, SFTP, SCP, forwarding, bootstrap failures, and process kill at every handshake boundary.
- Capture arbitrary binary and terminal escape fixtures and verify byte-for-byte forwarding through every layer.

## Licence rules

- Original eversh code is MIT OR Apache-2.0.
- MIT, Apache-2.0, and dual MIT/Apache-2.0 source may be adapted only with required notices retained at the point of reuse.
- GPL and AGPL projects in this file are behavioral references only; do not copy their source, tests, comments, creative fixtures, or distinctive structure.
- Custom-restricted and source-available projects are reference-only unless a separate licence review approves their use; a licence is not compatible merely because it begins with MIT wording.
- Internet-Drafts are protocol background and are not source-reuse permission.
- Every dependency is audited at an exact release or commit before addition; this inventory is not dependency approval.

## Maintenance rule

When a reference changes a design decision, record the exact reviewed release or commit, the evidence used, and the adopted or rejected behavior here, then update [design.md](design.md) so the normative contract does not contradict this inventory.
