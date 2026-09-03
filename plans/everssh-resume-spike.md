# everssh StableSSH-style resume spike

Status: implemented-result record (revision 2026-09-03) | Original spike:
2026-09-02

This document began as the proposal for the v2 association revision. Its
original 24-hour lease, older-remote fallback, and raw-operation opt-out ideas
were superseded by implementation evidence. The implemented and qualified
contract is:

- protocol: bootstrap `everssh v2`, ALPN `everssh-link/2`;
- association lease: configured 360 s on the server clock from entry into
  resume acceptance (observed production recovery: 302 s IPv4, 22 s IPv6;
  production-scale terminal expiry proven in the netns gate);
- client budget: one per-outage epoch of lease minus one handshake timeout,
  created before its first route/bind attempt and cleared after successful
  resume;
- replay: per-direction 4 MiB / 1,024 frame bounds; frames retained until
  cumulatively acknowledged and retransmitted on resume; delivered duplicates
  suppressed;
- compatibility: mismatched protocol versions fail closed with a coordinated
  upgrade diagnostic — no automatic old-protocol fallback;
- supervisor: `reconnecting` defers probes; only terminal association failure
  enters the existing bounded fresh-SSH path.

Normative details now live in `plans/design.md` revision 2. The sections below
are retained as the spike's reasoning record, not as release promises.

## Decision

Rename the SSH-over-QUIC component from `everlink` to `everssh`, and add
StableSSH-style **association resume** as an explicit v2 everssh mode.

The goal is not Mosh/zmosh terminal semantics. `everudp` remains a separate
future direct-UDP terminal transport. Everssh resume preserves the outer
OpenSSH byte stream across fresh QUIC connections using bounded per-direction
replay queues. It does not parse terminal output, predict input, reconstruct a
screen, or make an expired QUIC connection itself continue.

That design revision was adopted, implemented, and qualified; production
resume behavior is now claimed only through the gates named in the result
record above.

## Current v1 boundary

Current everssh performs this one-shot sequence:

1. The ProxyCommand runs a normal OpenSSH bootstrap.
2. The bootstrap starts a detached one-shot everssh server.
3. The server binds UDP, exposes one certificate pin and one one-use token.
4. The client opens one QUIC connection and one bidirectional stream.
5. The server authenticates the stream, connects to the authorized loopback
   `sshd`, and bridges the two byte streams.
6. A stalled or expired QUIC path closes both transport directions.
7. The SSH stream ends; only eversh's everpty supervisor can create fresh SSH
   and reattach the surviving PTY.

That is a hardened `quicssh`-style ProxyCommand, not StableSSH-style stream
continuity. In particular:

- `ServerEndpoint` accepts one authenticated connection and removes its server
  config after that connection.
- the bootstrap token is deliberately one-use;
- `TargetBridge` owns the target TCP stream and one QUIC stream together;
- neither side retains unacknowledged application bytes;
- EOF/FIN and byte delivery are coupled to the lifetime of that one QUIC
  stream.

## Reference result

StableSSH proves the missing mechanism. It keeps the ProxyCommand client and
remote gateway alive, associates them with a client key, retains packet queues,
exchanges acknowledgements, and re-sends unacknowledged packets after a fresh
QUIC connection. The outer SSH process therefore remains alive across network
sleep/wake and does not authenticate again.

Its unacceptable defaults are equally instructive:

- packet-count queues can become enormous;
- the default server hold window is one week;
- client and server certificate verification shortcuts are too broad;
- an always-on gateway exposes a larger service surface;
- queue exhaustion, EOF, and shutdown behavior need stronger gates.

Everssh can adopt the association/replay idea without adopting those defaults.

## Target architecture

```text
OpenSSH client stdio
  -> everssh client association actor
     -> bounded client-to-server replay queue
     -> fresh QUIC connection(s), sequentially
     -> everssh server association actor
     -> bounded server-to-client replay queue
     -> persistent authorized loopback TCP target: sshd
```
There is still at most one live application stream. A reconnect creates a new
QUIC connection only after the previous connection is dead. The association
actor, target TCP connection, client stdio ownership, and replay queues survive
between those connections.

### Association identity

The first connection remains anchored by the existing authenticated OpenSSH
bootstrap:

1. The ProxyCommand generates an ephemeral client certificate/key pair before
   the bootstrap.
2. The server still uses its ephemeral pinned certificate and one-use
   bootstrap token.
3. During first authentication, everssh binds:
   - the one-use bootstrap token;
   - the authenticated loopback target;
   - the client certificate SPKI;
   - a random association ID;
   - a bounded association lease.
4. Subsequent QUIC handshakes must present the same client private key. The
   association record is keyed by client SPKI and association ID.

The client certificate need not chain to a public CA: possession of its private
key plus the prior bootstrap-authorized binding is the security boundary. This
is materially narrower than StableSSH's unrestricted self-signed identity pool.
The server certificate pin continues to prevent a proxy-side interception.

Rejected alternatives:

- Reuse the original bootstrap token forever: turns a one-use secret into a
  long-lived bearer secret.
- Keep only a client IP/port: breaks roaming and is spoofable at the network
  layer.
- Trust any self-signed client after the first connection: permits a new,
  attacker-generated identity to create a fresh association.

### Frame protocol

The committed `everssh::resume` prototype defines the core wire shape:

```text
version: u8 = 1
kind:    u8 = data | fin | ack
sequence: u64 big-endian, nonzero for data/fin
length:  u32 big-endian
payload: exactly length bytes
```
Data frames carry opaque SSH bytes and are zeroized when dropped. `fin` encodes
half-close at its sequence. `ack` carries the highest sequence the peer has
delivered to its local sink; sequence zero means nothing has been delivered.
All fields are exact and trailing bytes are rejected.

The queue is bounded by both wire bytes and frame count. Cumulative ACKs remove
only complete frames. A receiver accepts only the next sequence and suppresses
duplicates on replay. Each direction has independent sequence and FIN state.

### Connection startup and replay

Every fresh QUIC connection performs:

1. TLS 1.3 handshake with pinned server identity and association client key.
2. Association hello:
   - association ID;
   - protocol version;
   - last delivered ACK for the sender's opposite direction;
   - optional proof nonce if rotation is added.
3. Both sides trim their peer-to-local replay queues through the received ACK.
4. Each side writes all still-unacknowledged data/FIN frames in sequence order.
5. Newly read local bytes append only after the replay prefix.

No connection interprets or reorders the SSH byte stream. A duplicate frame is
discarded only after its sequence has already been delivered to the local sink.

### Backpressure and queue exhaustion

Each direction allocates one fixed replay budget. A proposed initial ceiling is
4 MiB per direction and no more than 1,024 frames, subject to qualification;
the frame payload remains bounded by the existing 16 KiB copy buffer. A full
queue stops reads from its local source. It never silently drops SSH bytes.

If the queue remains full beyond the association lease or an explicit
configuration deadline, the association fails terminally and reports queue
exhaustion. The original 24-hour lease proposal was rejected by the measured
bounds described in the result record; 360 seconds is the configured value
pending the M5 idle/resource soak.

### FIN and terminal completion

Local EOF becomes a sequenced `fin`. It is replayed and acknowledged like data.
An association terminates only after:

- both directions' FINs have been delivered and acknowledged; or
- target/stdio I/O reports a terminal local failure; or
- replay capacity or the association lease expires; or
- the operator cancels the association.

Request -> Drain -> Finalize still applies to every owned task, socket, secret,
and child. Association ownership does not permit detached tasks.

### Eversh supervisor interaction

With association resume, a temporary QUIC loss does not close the ProxyCommand
stdio and therefore does not end the outer SSH process. Eversh's current probe
and fresh-SSH reconnect path runs only after terminal association failure or
queue exhaustion. An older remote fails closed at its protocol boundary and
requires coordinated upgrade; raw operations never receive a second OpenSSH
operation, although their live association retains the same bounded
retransmission behavior.

The link-status file must distinguish:

- temporary association reconnect in progress;
- terminal association failure;
- clean outer SSH completion.

This prevents eversh from launching a second writer while the original SSH
stream is still being resumed.

## Why not only increase QUIC idle timeout?

A larger timeout can hide a short outage, but does not solve total path loss,
address changes that fail migration, sleep/wake, process lifetime, queue
bounds, or SSH stream continuity. It also keeps stale connection and
retransmission state alive without an explicit association contract. Resume
requires an application association layer above QUIC.

## Relationship to everudp

Everssh resume still has reliable ordered SSH-stream semantics:

- packet loss can head-of-line block later SSH bytes;
- no local prediction exists;
- an outage freezes the local terminal until queued bytes resume;
- OpenSSH, forwarding, SFTP, SCP, and VS Code Remote remain compatible.

Everudp remains the proposed Mosh/zmosh-like path for low-latency terminal
behavior: direct encrypted UDP terminal state/diffs, no inner SSH data path,
and loss-tolerant display updates. These are complementary modes, not competing
implementations of one transport.

## Evidence inventory roles

Every supplied reference is pinned in `plans/reference.md`. Its role here is:

- StableSSH: primary association/replay model to harden.
- quic-send and fsend: resumable transfer chunking and reconnect UX evidence.
- QCP: SSH-assisted QUIC bootstrap and transport tuning evidence.
- bitbang, p2psh, sshx, Terminal7, and the Rust WebRTC article: WebRTC/ICE
  reachability and SSH-assisted signaling alternatives.
- ws-terminal and ws-relay: outbound WebSocket reachability and relay trust
  tradeoffs.
- neqo: alternate Rust QUIC implementation if noq's API blocks association
  ownership; no dependency change is proposed now.
- MoQ article: why QUIC/WebTransport does not itself provide terminal
  prediction or WebRTC peer traversal semantics.

## Required implementation stages

1. **Association server prototype**
   - keep one server endpoint config alive;
   - authenticate the first token-backed association;
   - bind client SPKI, target, ID, and lease;
   - reject duplicate association IDs and foreign client keys.

2. **Association actor**
   - split target/stdio ownership from one QUIC stream;
   - integrate one replay queue per direction;
   - enforce byte/frame limits and source backpressure;
   - preserve independent half-close and terminal cleanup.

3. **Client reconnect loop**
   - retain stdio and client key across QUIC death;
   - bind a fresh route-selected UDP socket when needed;
   - send association hello and ACK;
   - replay, then continue streaming;
   - classify temporary versus terminal failure for link-status.

4. **Production qualification**
   - real OpenSSH PTY, command, SFTP, SCP, forwarding, and half-close tests;
   - total loss longer than the QUIC idle timeout;
   - sleep/wake and IPv4/IPv6 address changes;
   - duplicate/reordered replay on reconnect;
   - queue exhaustion and 24-hour association lease;
   - hostile handshakes, stolen old tokens, wrong client keys, duplicate IDs;
   - RSS/fd/thread ceilings and zero retained state after Finalize;
   - eversh probe suppression while the original association remains live.

## Spike result

The committed state prototype already proves the central local invariant:
after a simulated lost connection, only frames after the peer's cumulative ACK
replay; duplicates are suppressed; FIN is durable; and queue capacity is
byte-based rather than StableSSH's packet-count-only bound.

Production resume is not claimed until the server/client actors and all
qualification stages above pass. No v1 release behavior is retroactively
changed.
