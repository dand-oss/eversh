//! Private per-session gateway state, bootstrap control, and ownership life cycle.

use crate::admission::GatewayGeneration;
use crate::bootstrap::{BootstrapError, BootstrapRecord};
use crate::limits::Limits;
use crate::transport::{AdmittedConnection, SharedInvitationStore};
use crate::wire::ConnectionRole;
use everpty::session::{BoundSession, StateRoot};
use everpty::sys::{PollFd, PollFlags};
use everssh::association::AssociationId;
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const CONTROL_MAGIC: &[u8; 4] = b"EUG1";
const CONTROL_REQUEST_LEN: usize = 55;
const CONTROL_POLL_SLICE_MS: u64 = 10;

#[derive(Debug)]
pub enum GatewayError {
    Everpty(everpty::Error),
    Io(std::io::Error),
    PeerIo(std::io::Error),
    Bootstrap(BootstrapError),
    Timeout,
    PeerUidMismatch,
    ControlMalformed,
    InvitationStoreUnavailable,
    GenerationMismatch,
    WriterBusy,
    ObserverCapacity,
    InvalidTakeover,
    Terminal,
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Everpty(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::PeerIo(error) => write!(formatter, "gateway control peer: {error}"),
            Self::Bootstrap(error) => write!(formatter, "{error}"),
            Self::Timeout => formatter.write_str("everudp gateway control deadline expired"),
            Self::PeerUidMismatch => {
                formatter.write_str("everudp gateway control peer UID does not match")
            }
            Self::ControlMalformed => formatter.write_str("malformed everudp gateway request"),
            Self::InvitationStoreUnavailable => {
                formatter.write_str("everudp gateway invitation store is unavailable")
            }
            Self::GenerationMismatch => {
                formatter.write_str("everudp gateway generation does not match")
            }
            Self::WriterBusy => formatter.write_str("everudp gateway writer is busy"),
            Self::ObserverCapacity => {
                formatter.write_str("everudp gateway observer capacity is exhausted")
            }
            Self::InvalidTakeover => formatter.write_str("observer cannot request writer takeover"),
            Self::Terminal => formatter.write_str("everudp gateway is terminal"),
        }
    }
}

impl std::error::Error for GatewayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Everpty(error) => Some(error),
            Self::Io(error) | Self::PeerIo(error) => Some(error),
            Self::Bootstrap(error) => Some(error),
            _ => None,
        }
    }
}

impl From<everpty::Error> for GatewayError {
    fn from(value: everpty::Error) -> Self {
        Self::Everpty(value)
    }
}

impl From<std::io::Error> for GatewayError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<BootstrapError> for GatewayError {
    fn from(value: BootstrapError) -> Self {
        Self::Bootstrap(value)
    }
}

pub enum GatewayState {
    Owner(GatewayControlListener),
    Connected(GatewayControlClient),
}

pub fn acquire_gateway_state(
    root: &StateRoot,
    session: &str,
    timeout_ms: u64,
) -> Result<GatewayState, GatewayError> {
    let everpty_limits = everpty::Limits::default();
    let directory = root.session(session, &everpty_limits)?;
    match directory.lock() {
        Ok(locked) => {
            locked.recover_stale_socket()?;
            let bound = locked.bind_broker_socket(&everpty_limits)?;
            Ok(GatewayState::Owner(GatewayControlListener { bound }))
        }
        Err(everpty::Error::AlreadyExists) => {
            connect_existing(root, session, timeout_ms, &everpty_limits)
                .map(GatewayState::Connected)
        }
        Err(error) => Err(error.into()),
    }
}

pub struct GatewayControlListener {
    bound: BoundSession,
}

impl GatewayControlListener {
    pub fn state_path(&self) -> &Path {
        self.bound.dir().path()
    }

    pub fn socket_path(&self) -> std::path::PathBuf {
        self.bound.dir().socket_path()
    }

    pub fn accept_peer(&self, timeout_ms: u64) -> Result<GatewayControlPeer, GatewayError> {
        let deadline = deadline_after(timeout_ms)?;
        loop {
            wait_fd(self.bound.listener(), PollFlags::POLLIN, deadline)?;
            if let Some(peer) = everpty::sys::accept_nonblock(self.bound.listener())? {
                if everpty::sys::peer_uid(peer.as_fd())? != everpty::sys::effective_uid() {
                    return Err(GatewayError::PeerUidMismatch);
                }
                let stream = blocking_stream(peer)?;
                let timeout = Duration::from_millis(timeout_ms);
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                return Ok(GatewayControlPeer { stream });
            }
        }
    }

    pub fn serve_invitation(
        &self,
        invitations: &SharedInvitationStore,
        context: GatewayBootstrapContext,
        limits: &Limits,
    ) -> Result<(), GatewayError> {
        limits.validate().map_err(BootstrapError::from)?;
        let mut peer = self.accept_peer(limits.initial_udp_budget_ms)?;
        let request = peer.read_request()?;
        let now_ms = everpty::sys::clock_monotonic_ms()?;
        let ticket = {
            let mut store = invitations
                .lock()
                .map_err(|_| GatewayError::InvitationStoreUnavailable)?;
            if store.generation() != context.generation {
                return Err(GatewayError::GenerationMismatch);
            }
            store
                .issue_with_takeover(
                    request.association_id,
                    request.role,
                    request.client_spki_sha256,
                    request.take_over,
                    now_ms,
                )
                .map_err(|_| GatewayError::ControlMalformed)?
        };
        let record = BootstrapRecord::new(
            context.endpoint,
            context.server_spki_sha256,
            ticket.token().clone(),
            ticket.association_id(),
            context.generation,
            context.pid,
        )?;
        peer.write_record(&record)
    }

    pub fn retire(&mut self) -> Result<(), GatewayError> {
        self.bound.retire_state().map_err(GatewayError::from)
    }
}

impl fmt::Debug for GatewayControlListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayControlListener")
            .field("state_path", &self.state_path())
            .finish_non_exhaustive()
    }
}

pub struct GatewayControlClient {
    stream: UnixStream,
}

impl GatewayControlClient {
    pub fn request_invitation(
        &mut self,
        request: GatewayControlRequest,
        limits: &Limits,
    ) -> Result<BootstrapRecord, GatewayError> {
        limits.validate().map_err(BootstrapError::from)?;
        let timeout = limits.initial_udp_budget();
        self.stream.set_read_timeout(Some(timeout))?;
        self.stream.set_write_timeout(Some(timeout))?;
        self.stream.write_all(&request.encode())?;
        self.stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::with_capacity(limits.bootstrap_record_max.min(512));
        Read::take(&mut self.stream, (limits.bootstrap_record_max + 1) as u64)
            .read_to_end(&mut response)?;
        if response.len() > limits.bootstrap_record_max {
            return Err(GatewayError::ControlMalformed);
        }
        let line = std::str::from_utf8(&response).map_err(|_| GatewayError::ControlMalformed)?;
        BootstrapRecord::parse_line(line, limits).map_err(GatewayError::from)
    }
}

impl fmt::Debug for GatewayControlClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayControlClient(<same-UID Unix stream>)")
    }
}

pub struct GatewayControlPeer {
    stream: UnixStream,
}

impl GatewayControlPeer {
    fn read_request(&mut self) -> Result<GatewayControlRequest, GatewayError> {
        let mut encoded = [0_u8; CONTROL_REQUEST_LEN];
        self.stream
            .read_exact(&mut encoded)
            .map_err(classify_peer_io)?;
        let mut trailing = [0_u8; 1];
        if self.stream.read(&mut trailing).map_err(classify_peer_io)? != 0 {
            return Err(GatewayError::ControlMalformed);
        }
        GatewayControlRequest::decode_exact(&encoded)
    }

    fn write_record(&mut self, record: &BootstrapRecord) -> Result<(), GatewayError> {
        let line = record.encode();
        self.stream
            .write_all(line.as_str().as_bytes())
            .map_err(classify_peer_io)?;
        self.stream
            .shutdown(Shutdown::Write)
            .map_err(classify_peer_io)?;
        Ok(())
    }
}

fn classify_peer_io(error: std::io::Error) -> GatewayError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        GatewayError::Timeout
    } else {
        GatewayError::PeerIo(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayControlRequest {
    association_id: AssociationId,
    role: ConnectionRole,
    client_spki_sha256: [u8; 32],
    take_over: bool,
}

impl GatewayControlRequest {
    pub fn new(
        association_id: AssociationId,
        role: ConnectionRole,
        client_spki_sha256: [u8; 32],
    ) -> Self {
        Self::with_takeover(association_id, role, client_spki_sha256, false)
    }

    pub fn with_takeover(
        association_id: AssociationId,
        role: ConnectionRole,
        client_spki_sha256: [u8; 32],
        take_over: bool,
    ) -> Self {
        Self {
            association_id,
            role,
            client_spki_sha256,
            take_over,
        }
    }

    pub fn association_id(&self) -> AssociationId {
        self.association_id
    }

    pub fn role(&self) -> ConnectionRole {
        self.role
    }

    pub fn client_spki_sha256(&self) -> [u8; 32] {
        self.client_spki_sha256
    }

    pub fn take_over(&self) -> bool {
        self.take_over
    }

    pub fn encode(self) -> [u8; CONTROL_REQUEST_LEN] {
        let mut output = [0_u8; CONTROL_REQUEST_LEN];
        output[0..4].copy_from_slice(CONTROL_MAGIC);
        output[4] = 1;
        output[5..21].copy_from_slice(self.association_id.as_bytes());
        output[21] = match self.role {
            ConnectionRole::Writer => 1,
            ConnectionRole::Observer => 2,
        };
        output[22] = u8::from(self.take_over);
        output[23..55].copy_from_slice(&self.client_spki_sha256);
        output
    }

    pub fn decode_exact(input: &[u8]) -> Result<Self, GatewayError> {
        if input.len() != CONTROL_REQUEST_LEN || &input[0..4] != CONTROL_MAGIC || input[4] != 1 {
            return Err(GatewayError::ControlMalformed);
        }
        let mut association = [0_u8; 16];
        association.copy_from_slice(&input[5..21]);
        let association_id =
            AssociationId::from_bytes(association).map_err(|_| GatewayError::ControlMalformed)?;
        let role = match input[21] {
            1 => ConnectionRole::Writer,
            2 => ConnectionRole::Observer,
            _ => return Err(GatewayError::ControlMalformed),
        };
        let take_over = match input[22] {
            0 => false,
            1 if role == ConnectionRole::Writer => true,
            _ => return Err(GatewayError::ControlMalformed),
        };
        let mut client_spki_sha256 = [0_u8; 32];
        client_spki_sha256.copy_from_slice(&input[23..55]);
        Ok(Self {
            association_id,
            role,
            client_spki_sha256,
            take_over,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayBootstrapContext {
    endpoint: SocketAddr,
    server_spki_sha256: [u8; 32],
    generation: GatewayGeneration,
    pid: u32,
}

impl GatewayBootstrapContext {
    pub fn new(
        endpoint: SocketAddr,
        server_spki_sha256: [u8; 32],
        generation: GatewayGeneration,
        pid: u32,
    ) -> Result<Self, GatewayError> {
        if pid == 0 || !usable_endpoint(endpoint) {
            return Err(GatewayError::ControlMalformed);
        }
        Ok(Self {
            endpoint,
            server_spki_sha256,
            generation,
            pid,
        })
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn server_spki_sha256(&self) -> [u8; 32] {
        self.server_spki_sha256
    }

    pub fn generation(&self) -> GatewayGeneration {
        self.generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayAction {
    CommitEverptyWriter,
    WriterResumed,
    ObserverAdded,
    ObserverResumed,
    TransferWriter {
        previous: AssociationId,
        replacement: AssociationId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalState {
    PtyExited(i32),
    Killed,
}

#[derive(Debug)]
pub struct GatewayLifecycle {
    writer: Option<AssociationId>,
    everpty_writer_committed: bool,
    observers: [Option<AssociationId>; 8],
    max_observers: usize,
    terminal: Option<TerminalState>,
}

impl GatewayLifecycle {
    pub fn new(limits: &Limits) -> Result<Self, GatewayError> {
        limits
            .validate()
            .map_err(|_| GatewayError::ControlMalformed)?;
        Ok(Self {
            writer: None,
            everpty_writer_committed: false,
            observers: [None; 8],
            max_observers: limits.max_observers,
            terminal: None,
        })
    }

    pub fn everpty_writer_committed(&self) -> bool {
        self.everpty_writer_committed
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }

    /// Apply an ownership transition only from the unforgeable result of a
    /// successful TLS, Retry, and invitation admission.
    pub fn admit(
        &mut self,
        connection: &AdmittedConnection,
        take_over: bool,
    ) -> Result<GatewayAction, GatewayError> {
        self.admit_identity(
            connection.hello().association_id(),
            connection.hello().role(),
            take_over,
        )
    }

    fn admit_identity(
        &mut self,
        association_id: AssociationId,
        role: ConnectionRole,
        take_over: bool,
    ) -> Result<GatewayAction, GatewayError> {
        if self.terminal.is_some() {
            return Err(GatewayError::Terminal);
        }
        match role {
            ConnectionRole::Writer => match self.writer {
                None => {
                    self.writer = Some(association_id);
                    self.everpty_writer_committed = true;
                    Ok(GatewayAction::CommitEverptyWriter)
                }
                Some(current) if current == association_id => Ok(GatewayAction::WriterResumed),
                Some(current) if take_over => {
                    self.writer = Some(association_id);
                    Ok(GatewayAction::TransferWriter {
                        previous: current,
                        replacement: association_id,
                    })
                }
                Some(_) => Err(GatewayError::WriterBusy),
            },
            ConnectionRole::Observer => {
                if take_over {
                    return Err(GatewayError::InvalidTakeover);
                }
                if self
                    .observers
                    .iter()
                    .flatten()
                    .any(|id| *id == association_id)
                {
                    return Ok(GatewayAction::ObserverResumed);
                }
                let slot = self.observers[..self.max_observers]
                    .iter()
                    .position(Option::is_none)
                    .ok_or(GatewayError::ObserverCapacity)?;
                self.observers[slot] = Some(association_id);
                Ok(GatewayAction::ObserverAdded)
            }
        }
    }

    pub fn pty_exited(&mut self, exit_status: i32) {
        self.terminal = Some(TerminalState::PtyExited(exit_status));
    }

    /// Permanently releases an association while retaining the gateway's
    /// broker-writer commitment. This is used for an explicit takeover, a
    /// disconnected-generation replacement, or a terminal per-peer protocol
    /// failure; ordinary network loss never calls it.
    pub fn release(&mut self, association_id: AssociationId) -> Option<ConnectionRole> {
        if self.writer == Some(association_id) {
            self.writer = None;
            return Some(ConnectionRole::Writer);
        }
        let observer = self.observers[..self.max_observers]
            .iter_mut()
            .find(|candidate| **candidate == Some(association_id))?;
        *observer = None;
        Some(ConnectionRole::Observer)
    }

    pub fn kill(&mut self) {
        self.terminal = Some(TerminalState::Killed);
    }
}

fn connect_existing(
    root: &StateRoot,
    session: &str,
    timeout_ms: u64,
    limits: &everpty::Limits,
) -> Result<GatewayControlClient, GatewayError> {
    let deadline = deadline_after(timeout_ms)?;
    loop {
        let directory = root.open_session(session, limits)?;
        match directory.connect_socket() {
            Ok(fd) => match finish_connect(fd, deadline) {
                Ok(client) => return Ok(client),
                Err(GatewayError::Everpty(everpty::Error::NotLive)) => {}
                Err(error) => return Err(error),
            },
            Err(everpty::Error::NotLive) => {}
            Err(error) => return Err(error.into()),
        }
        if everpty::sys::clock_monotonic_ms()? >= deadline {
            return Err(GatewayError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(CONTROL_POLL_SLICE_MS));
    }
}

fn finish_connect(fd: OwnedFd, deadline: u64) -> Result<GatewayControlClient, GatewayError> {
    wait_fd(fd.as_fd(), PollFlags::POLLOUT, deadline)?;
    if let Some(errno) = everpty::sys::socket_error(fd.as_fd())? {
        let error = std::io::Error::from_raw_os_error(errno);
        if matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        ) {
            return Err(GatewayError::Everpty(everpty::Error::NotLive));
        }
        return Err(GatewayError::Io(error));
    }
    if everpty::sys::peer_uid(fd.as_fd())? != everpty::sys::effective_uid() {
        return Err(GatewayError::PeerUidMismatch);
    }
    Ok(GatewayControlClient {
        stream: blocking_stream(fd)?,
    })
}

fn wait_fd(
    fd: std::os::fd::BorrowedFd<'_>,
    events: PollFlags,
    deadline: u64,
) -> Result<(), GatewayError> {
    loop {
        let now = everpty::sys::clock_monotonic_ms()?;
        if now >= deadline {
            return Err(GatewayError::Timeout);
        }
        let remaining = u32::try_from(deadline - now).unwrap_or(u32::MAX);
        let mut poll = [PollFd::new(
            fd,
            events | PollFlags::POLLERR | PollFlags::POLLHUP,
        )];
        match everpty::sys::poll(&mut poll, Some(remaining)) {
            Ok(0) => return Err(GatewayError::Timeout),
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn deadline_after(timeout_ms: u64) -> Result<u64, GatewayError> {
    Ok(everpty::sys::clock_monotonic_ms()?.saturating_add(timeout_ms))
}

fn blocking_stream(fd: OwnedFd) -> Result<UnixStream, GatewayError> {
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn usable_endpoint(endpoint: SocketAddr) -> bool {
    if endpoint.port() == 0 {
        return false;
    }
    match endpoint.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && ip != Ipv4Addr::BROADCAST,
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn association(byte: u8) -> AssociationId {
        AssociationId::from_bytes([byte; 16]).expect("association")
    }

    #[test]
    fn lifecycle_commits_writer_only_after_authenticated_transition() {
        let mut lifecycle = GatewayLifecycle::new(&Limits::default()).expect("lifecycle");
        assert!(!lifecycle.everpty_writer_committed());
        assert_eq!(
            lifecycle
                .admit_identity(association(1), ConnectionRole::Observer, false)
                .expect("observer"),
            GatewayAction::ObserverAdded
        );
        assert!(!lifecycle.everpty_writer_committed());
        assert_eq!(
            lifecycle
                .admit_identity(association(2), ConnectionRole::Writer, false)
                .expect("writer"),
            GatewayAction::CommitEverptyWriter
        );
        assert!(lifecycle.everpty_writer_committed());
        assert!(lifecycle
            .admit_identity(association(3), ConnectionRole::Writer, false)
            .is_err());
        assert_eq!(
            lifecycle
                .admit_identity(association(3), ConnectionRole::Writer, true)
                .expect("takeover"),
            GatewayAction::TransferWriter {
                previous: association(2),
                replacement: association(3),
            }
        );
        for byte in 4..=10 {
            lifecycle
                .admit_identity(association(byte), ConnectionRole::Observer, false)
                .expect("bounded observer");
        }
        assert!(lifecycle
            .admit_identity(association(11), ConnectionRole::Observer, false)
            .is_err());
        lifecycle.pty_exited(17);
        assert!(lifecycle.is_terminal());
        assert!(lifecycle
            .admit_identity(association(12), ConnectionRole::Observer, false)
            .is_err());
    }
}
