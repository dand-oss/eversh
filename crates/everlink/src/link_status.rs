//! Local, out-of-band status file for the `ssh-proxy` client edge (design 3,
//! 7). eversh points this process at a private per-spawn file for structured
//! interactive operations and probes only (never raw `eversh ssh`, which is
//! never retried and stays fully uninstrumented) by passing the path as a
//! `--status-file` ProxyCommand ARGUMENT. OpenSSH executes the ProxyCommand
//! line through the user's local shell, so the path arrives in this
//! process's own argv — a purely local handoff that no environment-
//! forwarding policy (`SendEnv`/`AcceptEnv`) can transmit remotely and no
//! ambient environment value can imitate.

use crate::bridge::{BridgeCompletion, DrainStatus, FinalizeStatus};
use crate::shutdown::TerminalCause;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const STATUS_PREFIX: &str = "everlink-status-v1";

/// The two-class mapping every M3 [`TerminalCause`] collapses to (design
/// 6.3, 9): a transport that plainly died underneath a live peer, or an
/// ordinary completed/closed exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCause {
    TransportFailure,
    CleanClose,
}

impl StatusCause {
    fn word(self) -> &'static str {
        match self {
            Self::TransportFailure => "transport-failure",
            Self::CleanClose => "clean-close",
        }
    }
}

/// One versioned status record, decoded from a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusRecord {
    /// The QUIC stream has delivered at least one byte originating from the
    /// remote peer: a genuine round trip.
    Carrying,
    /// The terminal exit record, written on every exit path.
    Cause { cause: StatusCause, carried: bool },
}

/// Classify one terminal cause into exactly two words. Matches every
/// [`TerminalCause`] variant by name — no wildcard arm — so a future
/// variant fails this build instead of silently falling through a default;
/// any genuinely ambiguous cause maps to `TransportFailure`, which fails
/// toward a bounded probe rather than silently skipping a retry a live
/// session still needed.
///
/// A graceful `SourceEof` — either the local ssh client closing its own
/// output after a completed exchange, or the remote gracefully finishing
/// and closing its QUIC send side — is the only potentially clean case;
/// whether it proves a completed exchange is decided by
/// [`classify_completion`] against the drain/finalize evidence. Every other
/// variant (a failed or stalled copy operation, cancellation, a failed
/// bridge task, a QUIC path failure, a route-supervisor failure, a
/// construction failure, a deadline that could not even be represented, or
/// a finalize that itself timed out) means the transport died underneath a
/// peer that was not finished.
pub fn classify_cause(cause: TerminalCause) -> StatusCause {
    match cause {
        TerminalCause::SourceEof(_) => StatusCause::CleanClose,
        TerminalCause::OperationFailed { .. }
        | TerminalCause::OperationStalled { .. }
        | TerminalCause::Cancelled
        | TerminalCause::TaskFailed(_)
        | TerminalCause::PathFailed
        | TerminalCause::RouteSupervisorFailed
        | TerminalCause::ConstructionFailed
        | TerminalCause::DeadlineOverflow(_)
        | TerminalCause::FinalizeTimeout => StatusCause::TransportFailure,
    }
}

/// Classify one COMPLETED bridge run for the terminal status record.
///
/// A `clean-close` requires more than a graceful `SourceEof` terminal cause
/// (design 6.3): the exchange is only proven completed when Drain AND
/// Finalize both finished cleanly. A remote FIN followed by path loss, a
/// shutdown failure, or an incomplete/expired drain would otherwise claim a
/// clean completed exchange and suppress a probe a live session still
/// needed — so any `SourceEof` without fully clean shutdown evidence, like
/// every other terminal cause regardless of its evidence, is a
/// `transport-failure`.
pub fn classify_completion(completion: &BridgeCompletion) -> StatusCause {
    let graceful_cause = classify_cause(completion.cause) == StatusCause::CleanClose;
    let clean_shutdown = completion.drain == DrainStatus::Completed
        && completion.finalize == FinalizeStatus::Completed;
    if graceful_cause && clean_shutdown {
        StatusCause::CleanClose
    } else {
        StatusCause::TransportFailure
    }
}

/// Parse one line (without its trailing newline) against the versioned
/// status protocol. `None` means the line is not a status-channel line at
/// all (unrecognized prefix, or a malformed record) — the caller's default
/// fallback for a missing/unparseable file applies.
pub fn parse_line(line: &str) -> Option<StatusRecord> {
    let rest = line.strip_prefix(STATUS_PREFIX)?.strip_prefix(' ')?;
    if rest == "carrying" {
        return Some(StatusRecord::Carrying);
    }
    let rest = rest.strip_prefix("cause ")?;
    let (word, carried_part) = rest.split_once(' ')?;
    let cause = match word {
        "transport-failure" => StatusCause::TransportFailure,
        "clean-close" => StatusCause::CleanClose,
        _ => return None,
    };
    let carried = match carried_part.strip_prefix("carried=")? {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    Some(StatusRecord::Cause { cause, carried })
}

/// Append one line, best-effort: a failed status write must never affect
/// the bridge itself. `O_APPEND` keeps each write atomic with respect to
/// any other writer sharing the file descriptor's underlying open file
/// (POSIX guarantees this for one `write(2)` no larger than `PIPE_BUF`, and
/// every line here is far smaller). The file is expected to already exist,
/// created by eversh with the correct `0600` mode under its `0700` state
/// root — a missing file simply means nothing is recorded here.
fn append_line(path: &Path, line: &str) {
    if let Ok(mut file) = OpenOptions::new().append(true).open(path) {
        let _ = file.write_all(line.as_bytes());
    }
}

/// Record that the QUIC stream has delivered at least one byte originating
/// from the remote peer — the ssh server banner arriving here proves a
/// genuine round trip, i.e. the transport is actually carrying the session
/// rather than merely authenticated. Written at most once per file, by
/// [`TrackedWriter`].
fn write_carrying(path: &Path) {
    append_line(path, &format!("{STATUS_PREFIX} carrying\n"));
}

/// Record the final cause. Callers write this on every exit path, including
/// setup failures that never reach a live bridge (those pass
/// `StatusCause::CleanClose` and `carried: false`: an ordinary failure, per
/// design 7's bootstrap/authentication rule).
pub fn write_cause(path: &Path, cause: StatusCause, carried: bool) {
    append_line(
        path,
        &format!(
            "{STATUS_PREFIX} cause {} carried={}\n",
            cause.word(),
            u8::from(carried)
        ),
    );
}

/// Wraps the peer-facing reader — bytes read here flow from the local peer
/// toward QUIC (`CopyDirection::PeerToQuic`'s source) — to record whether it
/// ever delivered a byte, for the final `carried` flag (bytes must have
/// flowed in both directions).
pub struct TrackedReader<R> {
    inner: R,
    delivered: Arc<AtomicBool>,
}

impl<R> TrackedReader<R> {
    pub fn new(inner: R, delivered: Arc<AtomicBool>) -> Self {
        Self { inner, delivered }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for TrackedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if result.is_ready() && buffer.filled().len() > before {
            self.delivered.store(true, Ordering::Release);
        }
        result
    }
}

/// Wraps the peer-facing writer — bytes written here flow from QUIC toward
/// the local peer (`CopyDirection::QuicToPeer`'s destination). The first
/// successful non-empty write proves the QUIC round trip is genuinely
/// carrying the session and appends `carrying` to the status file exactly
/// once, right then; the shared `delivered` flag is also used for the final
/// `carried` computation.
pub struct TrackedWriter<W> {
    inner: W,
    delivered: Arc<AtomicBool>,
    status_path: Option<PathBuf>,
}

impl<W> TrackedWriter<W> {
    pub fn new(inner: W, delivered: Arc<AtomicBool>, status_path: Option<PathBuf>) -> Self {
        Self {
            inner,
            delivered,
            status_path,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for TrackedWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, bytes);
        if let Poll::Ready(Ok(count)) = &result {
            if *count > 0 && !self.delivered.swap(true, Ordering::AcqRel) {
                if let Some(path) = &self.status_path {
                    write_carrying(path);
                }
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::shutdown::{CopyDirection, CopyOperation, DeadlineKind};

    #[test]
    fn classify_cause_is_exhaustive_and_maps_to_exactly_two_classes() {
        let clean = [
            TerminalCause::SourceEof(CopyDirection::PeerToQuic),
            TerminalCause::SourceEof(CopyDirection::QuicToPeer),
        ];
        for cause in clean {
            assert_eq!(classify_cause(cause), StatusCause::CleanClose, "{cause:?}");
        }
        let failures = [
            TerminalCause::OperationFailed {
                direction: CopyDirection::PeerToQuic,
                operation: CopyOperation::Read,
            },
            TerminalCause::OperationFailed {
                direction: CopyDirection::QuicToPeer,
                operation: CopyOperation::Write,
            },
            TerminalCause::OperationStalled {
                direction: CopyDirection::PeerToQuic,
                operation: CopyOperation::Delivery,
            },
            TerminalCause::Cancelled,
            TerminalCause::TaskFailed(CopyDirection::QuicToPeer),
            TerminalCause::PathFailed,
            TerminalCause::RouteSupervisorFailed,
            TerminalCause::ConstructionFailed,
            TerminalCause::DeadlineOverflow(DeadlineKind::Drain),
            TerminalCause::DeadlineOverflow(DeadlineKind::Finalize),
            TerminalCause::DeadlineOverflow(DeadlineKind::Operation),
            TerminalCause::FinalizeTimeout,
        ];
        for cause in failures {
            assert_eq!(
                classify_cause(cause),
                StatusCause::TransportFailure,
                "{cause:?}"
            );
        }
    }

    #[test]
    fn classify_completion_requires_a_clean_cause_and_a_clean_drain_and_finalize() {
        let source_eof = TerminalCause::SourceEof(CopyDirection::PeerToQuic);
        let clean = BridgeCompletion {
            cause: source_eof,
            drain: DrainStatus::Completed,
            finalize: FinalizeStatus::Completed,
        };
        assert_eq!(classify_completion(&clean), StatusCause::CleanClose);

        // A graceful SourceEof WITHOUT fully clean shutdown evidence is a
        // transport failure, never a clean completed exchange (a remote FIN
        // followed by path loss, an incomplete drain, or a failed finalize
        // must not suppress a required probe).
        for completion in [
            BridgeCompletion {
                cause: source_eof,
                drain: DrainStatus::Incomplete,
                finalize: FinalizeStatus::Completed,
            },
            BridgeCompletion {
                cause: source_eof,
                drain: DrainStatus::DeadlineExpired,
                finalize: FinalizeStatus::Completed,
            },
            BridgeCompletion {
                cause: source_eof,
                drain: DrainStatus::Completed,
                finalize: FinalizeStatus::DeadlineExpired,
            },
            BridgeCompletion {
                cause: source_eof,
                drain: DrainStatus::Incomplete,
                finalize: FinalizeStatus::DeadlineExpired,
            },
        ] {
            assert_eq!(
                classify_completion(&completion),
                StatusCause::TransportFailure,
                "{completion:?}"
            );
        }

        // Every other terminal cause stays a transport failure even when the
        // drain/finalize evidence happens to be clean.
        for cause in [
            TerminalCause::Cancelled,
            TerminalCause::PathFailed,
            TerminalCause::OperationFailed {
                direction: CopyDirection::QuicToPeer,
                operation: CopyOperation::Write,
            },
        ] {
            let completion = BridgeCompletion {
                cause,
                drain: DrainStatus::Completed,
                finalize: FinalizeStatus::Completed,
            };
            assert_eq!(
                classify_completion(&completion),
                StatusCause::TransportFailure,
                "{completion:?}"
            );
        }
    }

    #[test]
    fn parse_line_round_trips_every_record_shape() {
        assert_eq!(
            parse_line("everlink-status-v1 carrying"),
            Some(StatusRecord::Carrying)
        );
        assert_eq!(
            parse_line("everlink-status-v1 cause clean-close carried=1"),
            Some(StatusRecord::Cause {
                cause: StatusCause::CleanClose,
                carried: true
            })
        );
        assert_eq!(
            parse_line("everlink-status-v1 cause transport-failure carried=0"),
            Some(StatusRecord::Cause {
                cause: StatusCause::TransportFailure,
                carried: false
            })
        );
        for bad in [
            "",
            "everlink-status-v1",
            "everlink-status-v1carrying",
            "everlink-status-v1 established",
            "everlink-status-v1 cause bogus carried=0",
            "everlink-status-v1 cause clean-close carried=2",
            "everlink-status-v1 cause clean-close",
            "eversh-status-v1 carrying",
        ] {
            assert!(parse_line(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn write_cause_and_carrying_append_exact_lines() {
        let dir =
            std::env::temp_dir().join(format!("everlink-status-write-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("status");
        std::fs::write(&path, b"").unwrap();
        write_carrying(&path);
        write_cause(&path, StatusCause::TransportFailure, false);
        write_cause(&path, StatusCause::CleanClose, true);
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            content,
            "everlink-status-v1 carrying\n\
             everlink-status-v1 cause transport-failure carried=0\n\
             everlink-status-v1 cause clean-close carried=1\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_to_missing_file_is_a_silent_no_op() {
        let path = std::env::temp_dir().join(format!(
            "everlink-status-missing-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        write_cause(&path, StatusCause::CleanClose, true);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn tracked_writer_records_carrying_exactly_once_on_first_nonempty_write() {
        let dir = std::env::temp_dir().join(format!("everlink-status-tw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("status");
        std::fs::write(&path, b"").unwrap();
        let delivered = Arc::new(AtomicBool::new(false));
        let mut writer = TrackedWriter::new(
            tokio::io::sink(),
            Arc::clone(&delivered),
            Some(path.clone()),
        );
        use tokio::io::AsyncWriteExt;
        writer.write_all(b"hello").await.unwrap();
        assert!(delivered.load(Ordering::Acquire));
        writer.write_all(b"world").await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "everlink-status-v1 carrying\n",
            "carrying must be written exactly once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tracked_writer_without_a_status_path_never_writes() {
        let delivered = Arc::new(AtomicBool::new(false));
        let mut writer = TrackedWriter::new(tokio::io::sink(), Arc::clone(&delivered), None);
        use tokio::io::AsyncWriteExt;
        writer.write_all(b"hello").await.unwrap();
        assert!(delivered.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn tracked_reader_records_delivery_only_on_nonempty_reads() {
        let delivered = Arc::new(AtomicBool::new(false));
        let mut reader = TrackedReader::new(&b"hi"[..], Arc::clone(&delivered));
        use tokio::io::AsyncReadExt;
        let mut buffer = [0u8; 8];
        let count = reader.read(&mut buffer).await.unwrap();
        assert_eq!(count, 2);
        assert!(delivered.load(Ordering::Acquire));
    }
}
