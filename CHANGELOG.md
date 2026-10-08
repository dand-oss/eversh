# Changelog

## 0.2.8

### Added

- README notes that `nohup` is not needed for eversh sessions.

### Fixed

- everudp names an exhausted `--udp-port-range` as "no free UDP port in
  everudp range START:END" instead of reporting a malformed bootstrap record
  when every port is held by live session gateways.

### Compatibility

- No wire or ALPN change. An exhausted-range gateway exits with dedicated
  status 75; only the parent diagnostic changes.

## 0.2.7

### Added

- Reproducible static musl release build: `tools/build-musl.sh` selects
  musl-gcc for ring's C code and builds with the cli features.

### Fixed

- everpty builds SCM_RIGHTS control messages on musl and keeps its pthread
  ThreadId Send, so the workspace suite passes on musl.

### Compatibility

- First release that builds as a static musl binary for hosts whose glibc is
  older than the build host.

## 0.2.6

### Added

- eversh reuses verified remote SSH agents for launched commands through a
  bounded identities probe, private keychain fallback, and one-shot command
  routing without replay.

### Fixed

- everssh session creation carries the validated client COLORTERM hint and
  applies it only when a new remote child starts.

### Compatibility

- Coordinated client and remote upgrade. The recorded four-host rollout
  preserves the atomic installer, installed hashes, session checks, and real
  environment and agent canary results.

## 0.2.5

### Changed

- EverUDP attaches share one PTY by default without a remote VT. Network
  reconnect resumes the same attachment; explicit takeover retires all old
  writers, including disconnected ones, while preserving observers.
- Independent bounded output queues isolate slow writers. Input operations
  cannot interleave mid-frame, and a blocked PTY no longer blocks admission,
  output, or local detach.
- The most recently typing writer controls the shared PTY size. Inactive
  resize and ordinary attach/resume do not steal size ownership.
- Fleet wrappers no longer imply takeover on resume or resume-all; explicit
  takeover is forwarded to every requested tab.

### Compatibility

- No wire or ALPN change. Already-running gateways are preserved; old
  gateways remain single-writer and may return Busy. Local everpty and
  EverSSH remain single-writer. Bare eversh still defaults to EverSSH.
- New clients stop automatic recovery when their attachment is retired.
- No screen reconstruction, scrollback replay, terminal parsing, or forced
  repaint. Applications remain responsible for redraw after a GAP.
- The historical zmosh comparison's disclosed performance FAIL is unchanged.
