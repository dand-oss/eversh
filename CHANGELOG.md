# Changelog

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
