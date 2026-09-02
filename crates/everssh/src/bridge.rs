//! Bounded, byte-opaque bridging between one authenticated noq stream and its
//! exact target TCP connection.

use crate::admission::{ConnectedTarget, ConnectedTargetParts};
use crate::error::{Error, LimitViolation};
use crate::limits::Limits;
use crate::shutdown::{CopyDirection, CopyOperation, DeadlineKind, Shutdown, TerminalCause};
use crate::transport::{
    ClientSession, ClientSessionParts, PathFailureTrigger, RouteSupervisorOwner,
};
use noq::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::Instant;

const CLOSE_CODE: VarInt = VarInt::from_u32(0x4556);

trait DeliveryWriter: AsyncWrite + Send + Unpin + 'static {
    fn delivery_confirmation(&self) -> Option<noq::Stopped>;
}

impl DeliveryWriter for SendStream {
    fn delivery_confirmation(&self) -> Option<noq::Stopped> {
        Some(self.stopped())
    }
}

struct ImmediateWriter<W>(W);

impl<W> AsyncWrite for ImmediateWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(context, bytes)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(context)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(context)
    }
}

impl<W> DeliveryWriter for ImmediateWriter<W>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    fn delivery_confirmation(&self) -> Option<noq::Stopped> {
        None
    }
}

/// Typed evidence for whether both directions completed cleanly, incompletely,
/// or only after exhausting the immutable drain deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainStatus {
    Completed,
    Incomplete,
    DeadlineExpired,
}

/// Whether all graceful finalize waits completed within their shared absolute
/// deadline. Owned fields are dropped in either case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizeStatus {
    Completed,
    DeadlineExpired,
}

/// Typed, diagnostics-safe evidence returned by a completed bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeCompletion {
    pub cause: TerminalCause,
    pub drain: DrainStatus,
    pub finalize: FinalizeStatus,
}

/// Staged owner of one admitted server stream and its exact TCP target.
pub struct TargetBridge {
    runtime: Handle,
    shutdown: Shutdown,
    limits: Limits,
    owner: BridgeOwner,
    quic_send: SendStream,
    quic_recv: RecvStream,
    tcp_read: OwnedReadHalf,
    tcp_write: OwnedWriteHalf,
    quic_to_peer_buffer: Vec<u8>,
    peer_to_quic_buffer: Vec<u8>,
    target_address: SocketAddr,
}

impl TargetBridge {
    /// Stage all fallible resources without launching work. A Request racing
    /// after this returns is checked again by atomic pair admission in `run`.
    pub async fn try_new(
        target: ConnectedTarget,
        limits: Limits,
        shutdown: Shutdown,
    ) -> Result<Self, Error> {
        let runtime = match Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => {
                shutdown.request_fatal(TerminalCause::ConstructionFailed, limits.drain_timeout());
                let _ = shutdown.begin_finalize(limits.finalize_timeout());
                drop(target);
                return Err(Error::RuntimeUnavailable);
            }
        };

        if let Err(error) = limits.validate() {
            return Err(reject_target(target, &shutdown, &limits, error).await);
        }
        if !deadlines_representable(&limits) {
            let error = Error::InvalidLimits(LimitViolation::DeadlineOverflow);
            return Err(reject_target(target, &shutdown, &limits, error).await);
        }

        let quic_to_peer_buffer = match fixed_buffer(limits.copy_buf) {
            Ok(buffer) => buffer,
            Err(error) => {
                return Err(reject_target(target, &shutdown, &limits, error).await);
            }
        };
        let peer_to_quic_buffer = match fixed_buffer(limits.copy_buf) {
            Ok(buffer) => buffer,
            Err(error) => {
                return Err(reject_target(target, &shutdown, &limits, error).await);
            }
        };
        if !shutdown.accepting_work() {
            return Err(
                reject_target(target, &shutdown, &limits, Error::BridgeAdmissionClosed).await,
            );
        }

        let ConnectedTargetParts {
            endpoint,
            connection,
            send,
            recv,
            stream,
            target_address,
        } = target.into_parts();
        let (tcp_read, tcp_write) = stream.into_split();
        Ok(Self {
            runtime,
            shutdown,
            limits,
            owner: BridgeOwner::new(endpoint, connection, None),
            quic_send: send,
            quic_recv: recv,
            tcp_read,
            tcp_write,
            quic_to_peer_buffer,
            peer_to_quic_buffer,
            target_address,
        })
    }

    /// Launch exactly two owned copy tasks, drain them to the first frozen
    /// deadline, and finalize only this bridge's resources.
    pub fn run(self) -> impl Future<Output = BridgeCompletion> + Send {
        let mut run_guard = RunGuard::new(self.shutdown.clone(), self.limits.drain_timeout());
        async move {
            let completion = self.run_inner().await;
            run_guard.disarm();
            completion
        }
    }

    async fn run_inner(self) -> BridgeCompletion {
        let Self {
            runtime,
            shutdown,
            limits,
            owner,
            quic_send,
            quic_recv,
            tcp_read,
            tcp_write,
            quic_to_peer_buffer,
            peer_to_quic_buffer,
            ..
        } = self;

        run_bridge_pair(BridgeRun {
            runtime,
            shutdown,
            limits,
            owner,
            quic_send,
            quic_recv,
            peer_read: tcp_read,
            peer_write: tcp_write,
            quic_to_peer_buffer,
            peer_to_quic_buffer,
        })
        .await
    }

    pub fn shutdown(&self) -> &Shutdown {
        &self.shutdown
    }
}

impl std::fmt::Debug for TargetBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetBridge")
            .field("target", &self.target_address)
            .field("shutdown", &self.shutdown)
            .finish_non_exhaustive()
    }
}

/// Staged owner of the public ProxyCommand stdin/stdout and authenticated
/// client endpoint. It uses the same copy and lifecycle implementation as the
/// target bridge.
pub struct StdioBridge {
    runtime: Handle,
    shutdown: Shutdown,
    limits: Limits,
    owner: BridgeOwner,
    quic_send: SendStream,
    quic_recv: RecvStream,
    stdin: Box<dyn AsyncRead + Send + Unpin>,
    stdout: Box<dyn AsyncWrite + Send + Unpin>,
    quic_to_peer_buffer: Vec<u8>,
    peer_to_quic_buffer: Vec<u8>,
}

impl StdioBridge {
    pub async fn try_new<R, W>(
        session: ClientSession,
        stdin: R,
        stdout: W,
        limits: Limits,
        shutdown: Shutdown,
    ) -> Result<Self, Error>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let runtime = match Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => {
                drop(session);
                shutdown.request_fatal(TerminalCause::ConstructionFailed, limits.drain_timeout());
                shutdown.begin_finalize(limits.finalize_timeout()).ok();
                return Err(Error::RuntimeUnavailable);
            }
        };
        if let Err(error) = limits.validate() {
            return Err(reject_client(session, &shutdown, &limits, error).await);
        }
        if !deadlines_representable(&limits) {
            return Err(reject_client(
                session,
                &shutdown,
                &limits,
                Error::InvalidLimits(LimitViolation::DeadlineOverflow),
            )
            .await);
        }
        let quic_to_peer_buffer = match fixed_buffer(limits.copy_buf) {
            Ok(buffer) => buffer,
            Err(error) => return Err(reject_client(session, &shutdown, &limits, error).await),
        };
        let peer_to_quic_buffer = match fixed_buffer(limits.copy_buf) {
            Ok(buffer) => buffer,
            Err(error) => return Err(reject_client(session, &shutdown, &limits, error).await),
        };
        if !shutdown.accepting_work() {
            return Err(
                reject_client(session, &shutdown, &limits, Error::BridgeAdmissionClosed).await,
            );
        }
        let ClientSessionParts {
            endpoint,
            connection,
            send,
            recv,
            supervisor,
        } = session.into_parts();
        if let Some(supervisor) = supervisor.as_ref() {
            supervisor.attach(shutdown.clone());
        }
        Ok(Self {
            runtime,
            shutdown,
            limits,
            owner: BridgeOwner::new(endpoint, connection, supervisor),
            quic_send: send,
            quic_recv: recv,
            stdin: Box::new(stdin),
            stdout: Box::new(stdout),
            quic_to_peer_buffer,
            peer_to_quic_buffer,
        })
    }

    pub fn run(self) -> impl Future<Output = BridgeCompletion> + Send {
        let mut guard = RunGuard::new(self.shutdown.clone(), self.limits.drain_timeout());
        async move {
            let Self {
                runtime,
                shutdown,
                limits,
                owner,
                quic_send,
                quic_recv,
                stdin,
                stdout,
                quic_to_peer_buffer,
                peer_to_quic_buffer,
            } = self;
            let completion = run_bridge_pair(BridgeRun {
                runtime,
                shutdown,
                limits,
                owner,
                quic_send,
                quic_recv,
                peer_read: stdin,
                peer_write: stdout,
                quic_to_peer_buffer,
                peer_to_quic_buffer,
            })
            .await;
            guard.disarm();
            completion
        }
    }
}

impl std::fmt::Debug for StdioBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StdioBridge")
            .field("shutdown", &self.shutdown)
            .finish_non_exhaustive()
    }
}

struct BridgeRun<R, W> {
    runtime: Handle,
    shutdown: Shutdown,
    limits: Limits,
    owner: BridgeOwner,
    quic_send: SendStream,
    quic_recv: RecvStream,
    peer_read: R,
    peer_write: W,
    quic_to_peer_buffer: Vec<u8>,
    peer_to_quic_buffer: Vec<u8>,
}

async fn run_bridge_pair<R, W>(run: BridgeRun<R, W>) -> BridgeCompletion
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let BridgeRun {
        runtime,
        shutdown,
        limits,
        owner,
        quic_send,
        quic_recv,
        peer_read,
        peer_write,
        quic_to_peer_buffer,
        peer_to_quic_buffer,
    } = run;
    let path_failure = owner.path_failure_trigger();
    let quic_to_peer = copy_direction_with_path_failure(
        quic_recv,
        ImmediateWriter(peer_write),
        quic_to_peer_buffer,
        CopyDirection::QuicToPeer,
        limits,
        shutdown.clone(),
        path_failure.clone(),
        QuicBoundary::Reader,
    );
    let peer_to_quic = copy_direction_with_path_failure(
        peer_read,
        quic_send,
        peer_to_quic_buffer,
        CopyDirection::PeerToQuic,
        limits,
        shutdown.clone(),
        path_failure,
        QuicBoundary::Writer,
    );
    let launched = shutdown.with_running_admission(move || {
        (
            OwnedTask::new(CopyDirection::QuicToPeer, runtime.spawn(quic_to_peer)),
            OwnedTask::new(CopyDirection::PeerToQuic, runtime.spawn(peer_to_quic)),
        )
    });
    let (quic_task, peer_task) = match launched {
        Some(tasks) => tasks,
        None => {
            shutdown.request_fatal(TerminalCause::ConstructionFailed, limits.drain_timeout());
            return finalize_bridge(owner, shutdown, limits, None, DrainStatus::Incomplete).await;
        }
    };
    let (remaining, drain) = drain_tasks(shutdown.clone(), limits, quic_task, peer_task).await;
    finalize_bridge(owner, shutdown, limits, remaining, drain).await
}

struct RunGuard {
    shutdown: Shutdown,
    drain_timeout: Duration,
    armed: bool,
}

impl RunGuard {
    fn new(shutdown: Shutdown, drain_timeout: Duration) -> Self {
        Self {
            shutdown,
            drain_timeout,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if self.armed {
            self.shutdown
                .request_fatal(TerminalCause::Cancelled, self.drain_timeout);
        }
    }
}

async fn reject_client(
    session: ClientSession,
    shutdown: &Shutdown,
    limits: &Limits,
    error: Error,
) -> Error {
    shutdown.request_fatal(TerminalCause::ConstructionFailed, limits.drain_timeout());
    let complete = match shutdown.begin_finalize(limits.finalize_timeout()) {
        Ok(deadline) if Instant::now() < deadline => {
            tokio::time::timeout_at(deadline, session.close())
                .await
                .is_ok()
                && Instant::now() < deadline
        }
        Ok(_) | Err(_) => {
            drop(session);
            false
        }
    };
    if complete {
        shutdown.complete_finalize();
    }
    error
}

async fn reject_target(
    target: ConnectedTarget,
    shutdown: &Shutdown,
    limits: &Limits,
    error: Error,
) -> Error {
    shutdown.request_fatal(TerminalCause::ConstructionFailed, limits.drain_timeout());
    let cleanup_complete = match shutdown.begin_finalize(limits.finalize_timeout()) {
        Ok(deadline) if Instant::now() < deadline => {
            matches!(
                tokio::time::timeout_at(deadline, target.close()).await,
                Ok(Ok(()))
            ) && Instant::now() < deadline
        }
        Ok(_) | Err(_) => {
            drop(target);
            false
        }
    };
    if cleanup_complete {
        shutdown.complete_finalize();
    }
    error
}

fn fixed_buffer(length: usize) -> Result<Vec<u8>, Error> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|_| Error::BridgeAllocation)?;
    buffer.resize(length, 0);
    Ok(buffer)
}

fn deadlines_representable(limits: &Limits) -> bool {
    let now = Instant::now();
    [
        limits.stall_timeout(),
        limits.drain_timeout(),
        limits.finalize_timeout(),
    ]
    .into_iter()
    .all(|duration| now.checked_add(duration).is_some())
}

#[derive(Debug)]
struct BridgeOwner {
    endpoint: Option<Endpoint>,
    connection: Option<Connection>,
    supervisor: Option<RouteSupervisorOwner>,
}

impl BridgeOwner {
    fn new(
        endpoint: Endpoint,
        connection: Connection,
        supervisor: Option<RouteSupervisorOwner>,
    ) -> Self {
        Self {
            endpoint: Some(endpoint),
            connection: Some(connection),
            supervisor,
        }
    }

    async fn close(mut self, deadline: Instant) -> bool {
        let supervisor_terminal = match self.supervisor.take() {
            Some(supervisor) => supervisor.join(deadline).await,
            None => Instant::now() < deadline,
        };
        self.start_close();
        drop(self.connection.take());

        let Some(endpoint) = self.endpoint.take() else {
            return supervisor_terminal && Instant::now() < deadline;
        };
        if Instant::now() >= deadline {
            drop(endpoint);
            return false;
        }
        let idle = tokio::time::timeout_at(deadline, endpoint.wait_idle()).await;
        let completed = idle.is_ok() && Instant::now() < deadline;
        drop(endpoint);
        supervisor_terminal && completed
    }

    fn path_failure_trigger(&self) -> Option<PathFailureTrigger> {
        self.supervisor
            .as_ref()
            .map(RouteSupervisorOwner::path_failure_trigger)
    }

    fn start_close(&self) {
        if let Some(connection) = self.connection.as_ref() {
            connection.close(CLOSE_CODE, b"bridge complete");
        }
        if let Some(endpoint) = self.endpoint.as_ref() {
            endpoint.set_server_config(None);
            endpoint.close(CLOSE_CODE, b"bridge complete");
        }
    }
}

impl Drop for BridgeOwner {
    fn drop(&mut self) {
        // Dropping the supervisor aborts rather than detaches its Tokio task.
        drop(self.supervisor.take());
        self.start_close();
    }
}

#[derive(Debug)]
struct OwnedTask {
    direction: CopyDirection,
    handle: JoinHandle<DirectionOutcome>,
}

impl OwnedTask {
    fn new(direction: CopyDirection, handle: JoinHandle<DirectionOutcome>) -> Self {
        Self { direction, handle }
    }
}

impl Drop for OwnedTask {
    fn drop(&mut self) {
        // Dropping a Tokio JoinHandle normally detaches its task. Bridge-owned
        // work must instead be made terminal even if its parent future is
        // cancelled before the ordinary drain/finalize joins run.
        self.handle.abort();
    }
}

enum FirstJoin {
    Quic(Result<DirectionOutcome, JoinError>),
    Peer(Result<DirectionOutcome, JoinError>),
}

async fn drain_tasks(
    shutdown: Shutdown,
    limits: Limits,
    mut quic_task: OwnedTask,
    mut peer_task: OwnedTask,
) -> (Option<OwnedTask>, DrainStatus) {
    let first = tokio::select! {
        result = &mut quic_task.handle => FirstJoin::Quic(result),
        result = &mut peer_task.handle => FirstJoin::Peer(result),
    };

    let (mut remaining, first_status) = match first {
        FirstJoin::Quic(result) => (
            Some(peer_task),
            observe_join(&shutdown, &limits, quic_task.direction, result),
        ),
        FirstJoin::Peer(result) => (
            Some(quic_task),
            observe_join(&shutdown, &limits, peer_task.direction, result),
        ),
    };
    shutdown.begin_drain();
    let (drain_deadline, deadline_status) = match shutdown.drain_deadline() {
        Some(deadline) => (deadline, None),
        None => {
            shutdown.request_fatal(
                TerminalCause::TaskFailed(CopyDirection::QuicToPeer),
                limits.drain_timeout(),
            );
            let deadline = match shutdown.drain_deadline() {
                Some(deadline) => deadline,
                None => Instant::now(),
            };
            (deadline, Some(DrainStatus::Incomplete))
        }
    };

    let mut drain = match deadline_status {
        Some(status) => combine_drain_status(first_status, status),
        None => first_status,
    };
    if let Some(mut task) = remaining.take() {
        if Instant::now() >= drain_deadline {
            task.handle.abort();
            remaining = Some(task);
            drain = combine_drain_status(drain, DrainStatus::DeadlineExpired);
            shutdown.stop_directions();
        } else {
            let sleep = tokio::time::sleep_until(drain_deadline);
            tokio::pin!(sleep);
            tokio::select! {
                biased;
                _ = &mut sleep => {
                    task.handle.abort();
                    remaining = Some(task);
                    drain = combine_drain_status(drain, DrainStatus::DeadlineExpired);
                    shutdown.stop_directions();
                }
                result = &mut task.handle => {
                    let status = observe_join(&shutdown, &limits, task.direction, result);
                    drain = combine_drain_status(drain, status);
                }
            }
        }
    }

    (remaining, drain)
}

fn observe_join(
    shutdown: &Shutdown,
    limits: &Limits,
    expected: CopyDirection,
    result: Result<DirectionOutcome, JoinError>,
) -> DrainStatus {
    match result {
        Ok(outcome) => {
            if outcome.direction != expected {
                shutdown.request_fatal(TerminalCause::TaskFailed(expected), limits.drain_timeout());
                return DrainStatus::Incomplete;
            }
            match outcome.end {
                DirectionEnd::SourceEof => DrainStatus::Completed,
                DirectionEnd::Failed => {
                    shutdown
                        .request_fatal(TerminalCause::TaskFailed(expected), limits.drain_timeout());
                    DrainStatus::Incomplete
                }
                DirectionEnd::Cancelled => {
                    shutdown.request_fatal(TerminalCause::Cancelled, limits.drain_timeout());
                    DrainStatus::Incomplete
                }
                DirectionEnd::DrainExpired => DrainStatus::DeadlineExpired,
            }
        }
        Err(_) => {
            shutdown.request_fatal(TerminalCause::TaskFailed(expected), limits.drain_timeout());
            DrainStatus::Incomplete
        }
    }
}

fn combine_drain_status(left: DrainStatus, right: DrainStatus) -> DrainStatus {
    if matches!(left, DrainStatus::Incomplete) || matches!(right, DrainStatus::Incomplete) {
        DrainStatus::Incomplete
    } else if matches!(left, DrainStatus::DeadlineExpired)
        || matches!(right, DrainStatus::DeadlineExpired)
    {
        DrainStatus::DeadlineExpired
    } else {
        DrainStatus::Completed
    }
}

async fn finalize_bridge(
    owner: BridgeOwner,
    shutdown: Shutdown,
    limits: Limits,
    remaining: Option<OwnedTask>,
    drain: DrainStatus,
) -> BridgeCompletion {
    if shutdown.cause().is_none() {
        shutdown.request_fatal(TerminalCause::ConstructionFailed, limits.drain_timeout());
    }
    shutdown.begin_drain();

    let (deadline, deadline_valid) = match shutdown.begin_finalize(limits.finalize_timeout()) {
        Ok(deadline) => (deadline, true),
        Err(_) => {
            let deadline = match shutdown.finalize_deadline() {
                Some(deadline) => deadline,
                None => Instant::now(),
            };
            (deadline, false)
        }
    };

    let tasks_terminal = match remaining {
        Some(task) => abort_and_join(task, deadline).await,
        None => Instant::now() < deadline,
    };
    let owner_idle = owner.close(deadline).await;
    let finalized = deadline_valid && tasks_terminal && owner_idle && shutdown.complete_finalize();
    let finalize = if finalized {
        FinalizeStatus::Completed
    } else {
        FinalizeStatus::DeadlineExpired
    };

    let cause = match shutdown.cause() {
        Some(cause) => cause,
        None => TerminalCause::ConstructionFailed,
    };
    BridgeCompletion {
        cause,
        drain,
        finalize,
    }
}

async fn abort_and_join(mut task: OwnedTask, deadline: Instant) -> bool {
    task.handle.abort();
    if Instant::now() >= deadline {
        return false;
    }
    let sleep = tokio::time::sleep_until(deadline);
    tokio::pin!(sleep);
    tokio::select! {
        biased;
        _ = &mut task.handle => Instant::now() < deadline,
        _ = &mut sleep => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectionEnd {
    SourceEof,
    Cancelled,
    Failed,
    DrainExpired,
}

#[derive(Debug)]
struct DirectionOutcome {
    direction: CopyDirection,
    end: DirectionEnd,
}

impl DirectionOutcome {
    fn new(direction: CopyDirection, end: DirectionEnd) -> Self {
        Self { direction, end }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationExit {
    Failed,
    Cancelled,
    Stalled,
    DrainExpired,
    DeadlineOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicBoundary {
    Reader,
    Writer,
}

#[cfg(test)]
async fn copy_direction<R, W>(
    reader: R,
    writer: W,
    buffer: Vec<u8>,
    direction: CopyDirection,
    limits: Limits,
    shutdown: Shutdown,
) -> DirectionOutcome
where
    R: AsyncRead + Send + Unpin + 'static,
    W: DeliveryWriter,
{
    copy_direction_with_path_failure(
        reader,
        writer,
        buffer,
        direction,
        limits,
        shutdown,
        None,
        QuicBoundary::Reader,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn copy_direction_with_path_failure<R, W>(
    mut reader: R,
    mut writer: W,
    mut buffer: Vec<u8>,
    direction: CopyDirection,
    limits: Limits,
    shutdown: Shutdown,
    path_failure: Option<PathFailureTrigger>,
    quic_boundary: QuicBoundary,
) -> DirectionOutcome
where
    R: AsyncRead + Send + Unpin + 'static,
    W: DeliveryWriter,
{
    let mut signal = shutdown.subscribe();
    loop {
        let read_deadline = match operation_deadline(limits.stall_timeout()) {
            Some(deadline) => deadline,
            None => {
                return terminate(
                    OperationExit::DeadlineOverflow,
                    direction,
                    CopyOperation::Read,
                    &shutdown,
                    &limits,
                );
            }
        };
        let read = bounded_io(
            reader.read(&mut buffer),
            read_deadline,
            &shutdown,
            &mut signal,
        )
        .await;
        let count = match read {
            Ok(0) => {
                shutdown.request_clean(TerminalCause::SourceEof(direction), limits.drain_timeout());
                return finish_writer(
                    writer,
                    direction,
                    limits,
                    shutdown,
                    signal,
                    path_failure,
                    quic_boundary,
                )
                .await;
            }
            Ok(count) => count,
            Err(exit) => {
                notify_path_failure(
                    path_failure.as_ref(),
                    quic_boundary,
                    CopyOperation::Read,
                    exit,
                );
                return terminate(exit, direction, CopyOperation::Read, &shutdown, &limits);
            }
        };

        let mut offset = 0usize;
        while offset < count {
            let write_deadline = match operation_deadline(limits.stall_timeout()) {
                Some(deadline) => deadline,
                None => {
                    return terminate(
                        OperationExit::DeadlineOverflow,
                        direction,
                        CopyOperation::Write,
                        &shutdown,
                        &limits,
                    );
                }
            };
            match bounded_io(
                writer.write(&buffer[offset..count]),
                write_deadline,
                &shutdown,
                &mut signal,
            )
            .await
            {
                Ok(written) if written != 0 && written <= count - offset => offset += written,
                Ok(_) => {
                    notify_path_failure(
                        path_failure.as_ref(),
                        quic_boundary,
                        CopyOperation::Write,
                        OperationExit::Failed,
                    );
                    return terminate(
                        OperationExit::Failed,
                        direction,
                        CopyOperation::Write,
                        &shutdown,
                        &limits,
                    );
                }
                Err(exit) => {
                    notify_path_failure(
                        path_failure.as_ref(),
                        quic_boundary,
                        CopyOperation::Write,
                        exit,
                    );
                    return terminate(exit, direction, CopyOperation::Write, &shutdown, &limits);
                }
            }
        }
    }
}

async fn finish_writer<W>(
    mut writer: W,
    direction: CopyDirection,
    limits: Limits,
    shutdown: Shutdown,
    mut signal: watch::Receiver<crate::shutdown::Signal>,
    path_failure: Option<PathFailureTrigger>,
    quic_boundary: QuicBoundary,
) -> DirectionOutcome
where
    W: DeliveryWriter,
{
    let flush_deadline = match operation_deadline(limits.stall_timeout()) {
        Some(deadline) => deadline,
        None => {
            return terminate(
                OperationExit::DeadlineOverflow,
                direction,
                CopyOperation::Flush,
                &shutdown,
                &limits,
            );
        }
    };
    if let Err(exit) = bounded_io(writer.flush(), flush_deadline, &shutdown, &mut signal).await {
        notify_path_failure(
            path_failure.as_ref(),
            quic_boundary,
            CopyOperation::Flush,
            exit,
        );
        return terminate(exit, direction, CopyOperation::Flush, &shutdown, &limits);
    }

    let shutdown_deadline = match operation_deadline(limits.stall_timeout()) {
        Some(deadline) => deadline,
        None => {
            return terminate(
                OperationExit::DeadlineOverflow,
                direction,
                CopyOperation::Shutdown,
                &shutdown,
                &limits,
            );
        }
    };
    if let Err(exit) =
        bounded_io(writer.shutdown(), shutdown_deadline, &shutdown, &mut signal).await
    {
        notify_path_failure(
            path_failure.as_ref(),
            quic_boundary,
            CopyOperation::Shutdown,
            exit,
        );
        return terminate(exit, direction, CopyOperation::Shutdown, &shutdown, &limits);
    }

    if let Some(stopped) = writer.delivery_confirmation() {
        let delivery_deadline = match operation_deadline(limits.stall_timeout()) {
            Some(deadline) => deadline,
            None => {
                return terminate(
                    OperationExit::DeadlineOverflow,
                    direction,
                    CopyOperation::Delivery,
                    &shutdown,
                    &limits,
                );
            }
        };
        let confirmation = async move {
            match stopped.await {
                Ok(None) => Ok(()),
                Ok(Some(_)) | Err(_) => Err(io::Error::other("QUIC delivery not acknowledged")),
            }
        };
        if let Err(exit) = bounded_io(confirmation, delivery_deadline, &shutdown, &mut signal).await
        {
            notify_path_failure(
                path_failure.as_ref(),
                quic_boundary,
                CopyOperation::Delivery,
                exit,
            );
            return terminate(exit, direction, CopyOperation::Delivery, &shutdown, &limits);
        }
    }
    DirectionOutcome::new(direction, DirectionEnd::SourceEof)
}

fn notify_path_failure(
    trigger: Option<&PathFailureTrigger>,
    boundary: QuicBoundary,
    operation: CopyOperation,
    exit: OperationExit,
) {
    let touches_quic = matches!(
        (boundary, operation),
        (QuicBoundary::Reader, CopyOperation::Read)
            | (
                QuicBoundary::Writer,
                CopyOperation::Write
                    | CopyOperation::Flush
                    | CopyOperation::Shutdown
                    | CopyOperation::Delivery
            )
    );
    if touches_quic && matches!(exit, OperationExit::Failed | OperationExit::Stalled) {
        if let Some(trigger) = trigger {
            trigger.notify();
        }
    }
}

fn terminate(
    exit: OperationExit,
    direction: CopyDirection,
    operation: CopyOperation,
    shutdown: &Shutdown,
    limits: &Limits,
) -> DirectionOutcome {
    let end = match exit {
        OperationExit::Failed => {
            shutdown.request_fatal(
                TerminalCause::OperationFailed {
                    direction,
                    operation,
                },
                limits.drain_timeout(),
            );
            DirectionEnd::Failed
        }
        OperationExit::Stalled => {
            shutdown.request_fatal(
                TerminalCause::OperationStalled {
                    direction,
                    operation,
                },
                limits.drain_timeout(),
            );
            DirectionEnd::Failed
        }
        OperationExit::DeadlineOverflow => {
            shutdown.request_fatal(
                TerminalCause::DeadlineOverflow(DeadlineKind::Operation),
                limits.drain_timeout(),
            );
            DirectionEnd::Failed
        }
        OperationExit::Cancelled => DirectionEnd::Cancelled,
        OperationExit::DrainExpired => {
            shutdown.stop_directions();
            DirectionEnd::DrainExpired
        }
    };
    DirectionOutcome::new(direction, end)
}

fn operation_deadline(timeout: std::time::Duration) -> Option<Instant> {
    Instant::now().checked_add(timeout)
}

async fn bounded_io<F, T>(
    future: F,
    stall_deadline: Instant,
    shutdown: &Shutdown,
    signal: &mut watch::Receiver<crate::shutdown::Signal>,
) -> Result<T, OperationExit>
where
    F: Future<Output = io::Result<T>>,
{
    tokio::pin!(future);
    loop {
        if signal.borrow_and_update().cancelled() {
            return Err(OperationExit::Cancelled);
        }
        let snapshot = shutdown.snapshot();
        let (deadline, drain_bound) = match snapshot.drain_deadline {
            Some(drain_deadline) if drain_deadline <= stall_deadline => (drain_deadline, true),
            _ => (stall_deadline, false),
        };
        if Instant::now() >= deadline {
            return Err(if drain_bound {
                OperationExit::DrainExpired
            } else {
                OperationExit::Stalled
            });
        }

        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);
        tokio::select! {
            biased;
            changed = signal.changed() => {
                if changed.is_err() {
                    return Err(OperationExit::Cancelled);
                }
            }
            _ = &mut sleep => {
                return Err(if drain_bound {
                    OperationExit::DrainExpired
                } else {
                    OperationExit::Stalled
                });
            }
            result = &mut future => return result.map_err(|_| OperationExit::Failed),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    #[derive(Clone, Copy)]
    enum ReaderTail {
        Eof,
        Error,
        Pending,
    }

    struct ScriptedReader {
        bytes: Vec<u8>,
        offset: usize,
        tail: ReaderTail,
    }

    impl ScriptedReader {
        fn new(bytes: &[u8], tail: ReaderTail) -> Self {
            Self {
                bytes: bytes.to_vec(),
                offset: 0,
                tail,
            }
        }
    }

    impl AsyncRead for ScriptedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.offset < self.bytes.len() {
                let count = output.remaining().min(self.bytes.len() - self.offset);
                let end = self.offset + count;
                output.put_slice(&self.bytes[self.offset..end]);
                self.offset = end;
                return Poll::Ready(Ok(()));
            }
            match self.tail {
                ReaderTail::Eof => Poll::Ready(Ok(())),
                ReaderTail::Error => Poll::Ready(Err(io::Error::other("injected read failure"))),
                ReaderTail::Pending => Poll::Pending,
            }
        }
    }

    #[derive(Debug, Default)]
    struct WriterState {
        bytes: Vec<u8>,
        flushes: usize,
        shutdowns: usize,
    }

    struct ScriptedWriter {
        state: Arc<Mutex<WriterState>>,
        max_write: usize,
        writes_before_pending: Option<usize>,
        fail_write: bool,
        pending_write: bool,
        pending_flush: bool,
        pending_shutdown: bool,
    }

    impl ScriptedWriter {
        fn capturing(max_write: usize) -> (Self, Arc<Mutex<WriterState>>) {
            let state = Arc::new(Mutex::new(WriterState::default()));
            (
                Self {
                    state: state.clone(),
                    max_write,
                    writes_before_pending: None,
                    fail_write: false,
                    pending_write: false,
                    pending_flush: false,
                    pending_shutdown: false,
                },
                state,
            )
        }

        fn failing() -> Self {
            let (mut writer, _) = Self::capturing(1);
            writer.fail_write = true;
            writer
        }

        fn blocked_write() -> Self {
            let (mut writer, _) = Self::capturing(1);
            writer.pending_write = true;
            writer
        }

        fn partially_then_blocked() -> (Self, Arc<Mutex<WriterState>>) {
            let (mut writer, state) = Self::capturing(1);
            writer.writes_before_pending = Some(1);
            (writer, state)
        }

        fn blocked_flush() -> Self {
            let (mut writer, _) = Self::capturing(1);
            writer.pending_flush = true;
            writer
        }

        fn blocked_shutdown() -> (Self, Arc<Mutex<WriterState>>) {
            let (mut writer, state) = Self::capturing(1);
            writer.pending_shutdown = true;
            (writer, state)
        }
    }

    impl AsyncWrite for ScriptedWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.fail_write {
                return Poll::Ready(Err(io::Error::other("injected write failure")));
            }
            if self.pending_write {
                return Poll::Pending;
            }
            if self.writes_before_pending == Some(0) {
                return Poll::Pending;
            }
            if let Some(remaining) = self.writes_before_pending.as_mut() {
                *remaining -= 1;
            }
            let count = bytes.len().min(self.max_write);
            self.state
                .lock()
                .unwrap()
                .bytes
                .extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.pending_flush {
                return Poll::Pending;
            }
            self.state.lock().unwrap().flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.pending_shutdown {
                return Poll::Pending;
            }
            self.state.lock().unwrap().shutdowns += 1;
            Poll::Ready(Ok(()))
        }
    }

    impl DeliveryWriter for ScriptedWriter {
        fn delivery_confirmation(&self) -> Option<noq::Stopped> {
            None
        }
    }

    fn test_limits(stall_ms: u64, drain_ms: u64) -> Limits {
        Limits {
            copy_buf: 4,
            stall_timeout_ms: stall_ms,
            drain_timeout_ms: drain_ms,
            finalize_timeout_ms: 500,
            ..Limits::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn readable_data_precedes_permanent_receive_failure_without_replay() {
        let limits = test_limits(100, 50);
        let shutdown = Shutdown::new();
        let bytes = [0x00, 0xff, 0x80, 0x41];
        let (writer, state) = ScriptedWriter::capturing(1);
        let outcome = copy_direction(
            ScriptedReader::new(&bytes, ReaderTail::Error),
            writer,
            vec![0; limits.copy_buf],
            CopyDirection::QuicToPeer,
            limits,
            shutdown.clone(),
        )
        .await;

        assert_eq!(outcome.end, DirectionEnd::Failed);
        assert_eq!(state.lock().unwrap().bytes, bytes);
        assert_eq!(
            shutdown.cause(),
            Some(TerminalCause::OperationFailed {
                direction: CopyDirection::QuicToPeer,
                operation: CopyOperation::Read,
            })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_send_failure_is_typed_and_cancels() {
        let limits = test_limits(100, 50);
        let shutdown = Shutdown::new();
        let outcome = copy_direction(
            ScriptedReader::new(&[7], ReaderTail::Pending),
            ScriptedWriter::failing(),
            vec![0; limits.copy_buf],
            CopyDirection::PeerToQuic,
            limits,
            shutdown.clone(),
        )
        .await;

        assert_eq!(outcome.end, DirectionEnd::Failed);
        assert_eq!(
            shutdown.cause(),
            Some(TerminalCause::OperationFailed {
                direction: CopyDirection::PeerToQuic,
                operation: CopyOperation::Write,
            })
        );
        let mut signal = shutdown.subscribe();
        assert!(signal.borrow_and_update().cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn timer_only_read_and_write_stalls_are_finite() {
        let limits = test_limits(100, 50);
        let read_shutdown = Shutdown::new();
        let read_task = tokio::spawn(copy_direction(
            ScriptedReader::new(&[], ReaderTail::Pending),
            ScriptedWriter::capturing(4).0,
            vec![0; limits.copy_buf],
            CopyDirection::QuicToPeer,
            limits,
            read_shutdown.clone(),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_millis(100)).await;
        assert_eq!(read_task.await.unwrap().end, DirectionEnd::Failed);
        assert_eq!(
            read_shutdown.cause(),
            Some(TerminalCause::OperationStalled {
                direction: CopyDirection::QuicToPeer,
                operation: CopyOperation::Read,
            })
        );

        let write_shutdown = Shutdown::new();
        let write_task = tokio::spawn(copy_direction(
            ScriptedReader::new(&[1, 2], ReaderTail::Pending),
            ScriptedWriter::blocked_write(),
            vec![0; limits.copy_buf],
            CopyDirection::PeerToQuic,
            limits,
            write_shutdown.clone(),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_millis(100)).await;
        assert_eq!(write_task.await.unwrap().end, DirectionEnd::Failed);
        assert_eq!(
            write_shutdown.cause(),
            Some(TerminalCause::OperationStalled {
                direction: CopyDirection::PeerToQuic,
                operation: CopyOperation::Write,
            })
        );

        let partial_shutdown = Shutdown::new();
        let (partial_writer, partial_state) = ScriptedWriter::partially_then_blocked();
        let partial_task = tokio::spawn(copy_direction(
            ScriptedReader::new(&[1, 2, 3], ReaderTail::Pending),
            partial_writer,
            vec![0; limits.copy_buf],
            CopyDirection::PeerToQuic,
            limits,
            partial_shutdown.clone(),
        ));
        tokio::task::yield_now().await;
        assert_eq!(partial_state.lock().unwrap().bytes, [1]);
        tokio::time::advance(std::time::Duration::from_millis(100)).await;
        assert_eq!(partial_task.await.unwrap().end, DirectionEnd::Failed);
        assert_eq!(partial_state.lock().unwrap().bytes, [1]);
        assert_eq!(
            partial_shutdown.cause(),
            Some(TerminalCause::OperationStalled {
                direction: CopyDirection::PeerToQuic,
                operation: CopyOperation::Write,
            })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn eof_flush_and_shutdown_stalls_are_bounded() {
        let limits = test_limits(100, 500);

        let flush_shutdown = Shutdown::new();
        let flush_task = tokio::spawn(copy_direction(
            ScriptedReader::new(&[], ReaderTail::Eof),
            ScriptedWriter::blocked_flush(),
            vec![0; limits.copy_buf],
            CopyDirection::QuicToPeer,
            limits,
            flush_shutdown.clone(),
        ));
        tokio::task::yield_now().await;
        let flush_drain = flush_shutdown.drain_deadline().unwrap();
        tokio::time::advance(std::time::Duration::from_millis(100)).await;
        assert_eq!(flush_task.await.unwrap().end, DirectionEnd::Failed);
        assert_eq!(flush_shutdown.drain_deadline(), Some(flush_drain));
        assert_eq!(
            flush_shutdown.cause(),
            Some(TerminalCause::SourceEof(CopyDirection::QuicToPeer))
        );

        let finish_shutdown = Shutdown::new();
        let (finish_writer, finish_state) = ScriptedWriter::blocked_shutdown();
        let finish_task = tokio::spawn(copy_direction(
            ScriptedReader::new(&[], ReaderTail::Eof),
            finish_writer,
            vec![0; limits.copy_buf],
            CopyDirection::PeerToQuic,
            limits,
            finish_shutdown.clone(),
        ));
        tokio::task::yield_now().await;
        let finish_drain = finish_shutdown.drain_deadline().unwrap();
        tokio::time::advance(std::time::Duration::from_millis(100)).await;
        assert_eq!(finish_task.await.unwrap().end, DirectionEnd::Failed);
        assert_eq!(finish_shutdown.drain_deadline(), Some(finish_drain));
        let finish_state = finish_state.lock().unwrap();
        assert_eq!(finish_state.flushes, 1);
        assert_eq!(finish_state.shutdowns, 0);
        assert_eq!(
            finish_shutdown.cause(),
            Some(TerminalCause::SourceEof(CopyDirection::PeerToQuic))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn eof_flushes_and_half_closes_only_its_writer() {
        let limits = test_limits(100, 50);
        let shutdown = Shutdown::new();
        let bytes = [0x00, 0xfe, 0xff];
        let (writer, state) = ScriptedWriter::capturing(2);
        let outcome = copy_direction(
            ScriptedReader::new(&bytes, ReaderTail::Eof),
            writer,
            vec![0; limits.copy_buf],
            CopyDirection::QuicToPeer,
            limits,
            shutdown.clone(),
        )
        .await;

        assert_eq!(outcome.end, DirectionEnd::SourceEof);
        let state = state.lock().unwrap();
        assert_eq!(state.bytes, bytes);
        assert_eq!(state.flushes, 1);
        assert_eq!(state.shutdowns, 1);
        assert_eq!(
            shutdown.cause(),
            Some(TerminalCause::SourceEof(CopyDirection::QuicToPeer))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn peer_fin_freezes_drain_before_blocked_final_operations() {
        let limits = test_limits(1_000, 100);
        let shutdown = Shutdown::new();
        let eof_task = tokio::spawn(copy_direction(
            ScriptedReader::new(&[], ReaderTail::Eof),
            ScriptedWriter::blocked_flush(),
            vec![0; limits.copy_buf],
            CopyDirection::QuicToPeer,
            limits,
            shutdown.clone(),
        ));
        let blocked_task = tokio::spawn(copy_direction(
            ScriptedReader::new(&[9], ReaderTail::Pending),
            ScriptedWriter::blocked_write(),
            vec![0; limits.copy_buf],
            CopyDirection::PeerToQuic,
            limits,
            shutdown.clone(),
        ));
        tokio::task::yield_now().await;

        let frozen = shutdown.drain_deadline().unwrap();
        assert_eq!(
            shutdown.request(
                TerminalCause::OperationFailed {
                    direction: CopyDirection::PeerToQuic,
                    operation: CopyOperation::Write,
                },
                std::time::Duration::from_secs(9),
            ),
            crate::shutdown::RequestStatus::Existing
        );
        assert_eq!(shutdown.drain_deadline(), Some(frozen));
        tokio::time::advance(std::time::Duration::from_millis(99)).await;
        assert!(!eof_task.is_finished());
        assert!(!blocked_task.is_finished());

        tokio::time::advance(std::time::Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        let eof_end = eof_task.await.unwrap().end;
        let blocked_end = blocked_task.await.unwrap().end;
        assert!(matches!(
            eof_end,
            DirectionEnd::DrainExpired | DirectionEnd::Cancelled
        ));
        assert!(matches!(
            blocked_end,
            DirectionEnd::DrainExpired | DirectionEnd::Cancelled
        ));
        assert_eq!(shutdown.drain_deadline(), Some(frozen));
        assert_eq!(
            shutdown.cause(),
            Some(TerminalCause::SourceEof(CopyDirection::QuicToPeer))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn drain_evidence_is_incomplete_when_eof_cleanup_later_fails() {
        let limits = test_limits(100, 500);
        let shutdown = Shutdown::new();
        let quic_handle = tokio::spawn(copy_direction(
            ScriptedReader::new(&[], ReaderTail::Eof),
            ScriptedWriter::blocked_flush(),
            vec![0; limits.copy_buf],
            CopyDirection::QuicToPeer,
            limits,
            shutdown.clone(),
        ));
        tokio::task::yield_now().await;
        assert_eq!(
            shutdown.cause(),
            Some(TerminalCause::SourceEof(CopyDirection::QuicToPeer))
        );

        let peer_handle = tokio::spawn(copy_direction(
            ScriptedReader::new(&[], ReaderTail::Pending),
            ScriptedWriter::capturing(1).0,
            vec![0; limits.copy_buf],
            CopyDirection::PeerToQuic,
            limits,
            shutdown.clone(),
        ));
        let drain_handle = tokio::spawn(drain_tasks(
            shutdown.clone(),
            limits,
            OwnedTask::new(CopyDirection::QuicToPeer, quic_handle),
            OwnedTask::new(CopyDirection::PeerToQuic, peer_handle),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(100)).await;

        let (remaining, drain) = drain_handle.await.unwrap();
        assert!(remaining.is_none());
        assert_eq!(drain, DrainStatus::Incomplete);
        assert_eq!(
            shutdown.cause(),
            Some(TerminalCause::SourceEof(CopyDirection::QuicToPeer))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mismatched_and_join_error_results_are_incomplete_after_eof() {
        let limits = test_limits(100, 500);
        let shutdown = Shutdown::new();
        shutdown.request_clean(
            TerminalCause::SourceEof(CopyDirection::QuicToPeer),
            limits.drain_timeout(),
        );

        let mismatch = observe_join(
            &shutdown,
            &limits,
            CopyDirection::QuicToPeer,
            Ok(DirectionOutcome::new(
                CopyDirection::PeerToQuic,
                DirectionEnd::SourceEof,
            )),
        );
        assert_eq!(mismatch, DrainStatus::Incomplete);

        let task = tokio::spawn(std::future::pending::<DirectionOutcome>());
        task.abort();
        let join_error = observe_join(&shutdown, &limits, CopyDirection::PeerToQuic, task.await);
        assert_eq!(join_error, DrainStatus::Incomplete);
        assert_eq!(
            shutdown.cause(),
            Some(TerminalCause::SourceEof(CopyDirection::QuicToPeer))
        );
    }

    #[tokio::test]
    async fn dropping_run_guard_latches_cancellation_without_resurrection() {
        let shutdown = Shutdown::new();
        let mut signal = shutdown.subscribe();
        drop(RunGuard::new(shutdown.clone(), Duration::from_secs(1)));

        assert_eq!(shutdown.cause(), Some(TerminalCause::Cancelled));
        assert_eq!(shutdown.phase(), crate::shutdown::Phase::Draining);
        assert!(signal.borrow_and_update().cancelled());
        assert!(shutdown.with_running_admission(|| ()).is_none());

        let eof_shutdown = Shutdown::new();
        eof_shutdown.request_clean(
            TerminalCause::SourceEof(CopyDirection::PeerToQuic),
            Duration::from_secs(2),
        );
        let frozen_deadline = eof_shutdown.drain_deadline();
        let mut eof_signal = eof_shutdown.subscribe();
        drop(RunGuard::new(eof_shutdown.clone(), Duration::from_secs(20)));

        assert_eq!(
            eof_shutdown.cause(),
            Some(TerminalCause::SourceEof(CopyDirection::PeerToQuic))
        );
        assert_eq!(eof_shutdown.drain_deadline(), frozen_deadline);
        assert_eq!(eof_shutdown.phase(), crate::shutdown::Phase::Draining);
        assert!(eof_signal.borrow_and_update().cancelled());
        assert!(eof_shutdown.with_running_admission(|| ()).is_none());
    }

    #[test]
    fn fixed_buffer_allocation_failure_is_typed() {
        assert!(matches!(
            fixed_buffer(usize::MAX),
            Err(Error::BridgeAllocation)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_an_owned_handle_aborts_instead_of_detaching() {
        struct DropMarker(Arc<AtomicBool>);

        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = dropped.clone();
        let handle = tokio::spawn(async move {
            let _marker = DropMarker(task_dropped);
            std::future::pending::<()>().await;
            DirectionOutcome::new(CopyDirection::QuicToPeer, DirectionEnd::Cancelled)
        });
        tokio::task::yield_now().await;
        drop(OwnedTask::new(CopyDirection::QuicToPeer, handle));
        tokio::task::yield_now().await;
        assert!(dropped.load(Ordering::SeqCst));
    }
}
