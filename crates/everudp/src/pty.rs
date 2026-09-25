//! Terminal-free asynchronous edge to one local `everpty` broker.
//!
//! The gateway owns this connection; QUIC actors never access the broker
//! socket directly. A complete everudp input operation is acknowledged only
//! after its corresponding broker frame has been accepted in full.

use crate::association::InputOperation;
use everpty::frame::{
    AttachStatus, Frame, FrameError, Kind as BrokerKind, LeaseAction, Role,
    HEADER_LEN as BROKER_HEADER_LEN, PROTOCOL_VERSION,
};
use everpty::session::SessionDir;
use everpty::sys;
use std::fmt;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::time::Duration;
use tokio::io::unix::AsyncFd;

#[derive(Debug)]
pub enum PtyError {
    Everpty(everpty::Error),
    Io(io::Error),
    Frame(FrameError),
    Timeout,
    PeerUidMismatch,
    Busy { current_writer_id: u32 },
    Protocol,
}

impl fmt::Display for PtyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Everpty(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Frame(error) => write!(formatter, "{error}"),
            Self::Timeout => formatter.write_str("everpty broker operation timed out"),
            Self::PeerUidMismatch => formatter.write_str("everpty broker peer UID does not match"),
            Self::Busy { .. } => formatter.write_str("everpty broker already has a writer"),
            Self::Protocol => formatter.write_str("everpty broker protocol violation"),
        }
    }
}

impl std::error::Error for PtyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Everpty(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Frame(error) => Some(error),
            _ => None,
        }
    }
}

impl From<everpty::Error> for PtyError {
    fn from(value: everpty::Error) -> Self {
        Self::Everpty(value)
    }
}

impl From<io::Error> for PtyError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<FrameError> for PtyError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtyEvent {
    /// A staged input operation reached its sink in full.
    InputCommitted,
    /// Number of output bytes retained in [`PtySession::output_bytes`].
    Output(usize),
    Ownership(u8),
    Exit(i32),
    /// The direct descriptor reached EOF or the broker requested revocation.
    /// The gateway must complete [`PtySession::finish_direct_release`] before
    /// polling this session again.
    DirectLeaseEnded,
}

/// Fixed-storage incremental reader for the trusted local broker protocol.
///
/// The general everpty `FrameReader` decodes `Input` and `Output` into owned
/// vectors. The gateway instead retains one complete encoded frame here so
/// steady-state terminal output can be copied directly into replay slabs.
struct BrokerFrameReader {
    bytes: Box<[u8]>,
    used: usize,
    total: Option<usize>,
    started_ms: Option<u64>,
    last_read_ms: Option<u64>,
}

impl fmt::Debug for BrokerFrameReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerFrameReader")
            .field("owned_bytes", &self.used)
            .field("started_ms", &self.started_ms)
            .field("payload", &"<REDACTED>")
            .finish()
    }
}

impl BrokerFrameReader {
    fn new(limits: &everpty::Limits) -> Result<Self, PtyError> {
        let capacity = limits
            .frame_max_body
            .checked_add(4)
            .ok_or(PtyError::Protocol)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        bytes.resize(capacity, 0);
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            used: 0,
            total: None,
            started_ms: None,
            last_read_ms: None,
        })
    }

    fn writable(&mut self) -> &mut [u8] {
        &mut self.bytes[self.used..]
    }

    /// Restricts a control/handshake read to the current frame boundary.
    /// This is mandatory immediately before an SCM_RIGHTS grant: a plain
    /// `recv` must not consume the carrier byte and discard its ancillary fd.
    fn current_frame_writable(&mut self) -> &mut [u8] {
        let end = if self.used < BROKER_HEADER_LEN {
            BROKER_HEADER_LEN
        } else {
            self.total.unwrap_or(self.bytes.len())
        };
        &mut self.bytes[self.used..end]
    }

    fn commit_read(
        &mut self,
        read: usize,
        now_ms: u64,
        limits: &everpty::Limits,
    ) -> Result<(), PtyError> {
        if read == 0 || read > self.bytes.len().saturating_sub(self.used) {
            return Err(PtyError::Protocol);
        }
        if self.used == 0 {
            self.started_ms = Some(now_ms);
        }
        self.used += read;
        self.last_read_ms = Some(now_ms);
        if self.used >= BROKER_HEADER_LEN && self.total.is_none() {
            self.total = Some(Frame::validate_header(
                &self.bytes[..BROKER_HEADER_LEN],
                limits,
            )?);
        }
        Ok(())
    }

    fn frame(&self) -> Option<&[u8]> {
        let total = self.total?;
        (self.used >= total).then_some(&self.bytes[..total])
    }

    fn started_ms(&self) -> Option<u64> {
        self.started_ms
    }

    fn consume(&mut self, limits: &everpty::Limits) -> Result<(), PtyError> {
        let total = self
            .total
            .filter(|total| self.used >= *total)
            .ok_or(PtyError::Protocol)?;
        self.bytes.copy_within(total..self.used, 0);
        self.used -= total;
        self.total = None;
        self.started_ms = if self.used == 0 {
            None
        } else {
            self.last_read_ms
        };
        if self.used >= BROKER_HEADER_LEN {
            self.total = Some(Frame::validate_header(
                &self.bytes[..BROKER_HEADER_LEN],
                limits,
            )?);
        }
        if self.used == 0 {
            self.last_read_ms = None;
        }
        if self.total.is_some_and(|next| next > self.bytes.len()) {
            return Err(PtyError::Protocol);
        }
        Ok(())
    }
}

pub struct PtySession {
    socket: AsyncFd<OwnedFd>,
    reader: BrokerFrameReader,
    send_buffer: Box<[u8]>,
    send_len: usize,
    send_offset: usize,
    send_deadline: Option<u64>,
    pending_input: PendingInput,
    limits: everpty::Limits,
    role: Role,
    direct: Option<DirectPtyLease>,
    direct_output: Box<[u8]>,
    direct_output_len: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingInput {
    None,
    DirectBytes,
    Framed,
    Signal,
    Barrier,
    WaitingBarrier,
    Complete,
}

struct DirectPtyLease {
    master: AsyncFd<OwnedFd>,
    generation: [u8; 16],
    lease_id: u64,
}

impl PtySession {
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        session: &SessionDir,
        name: &str,
        role: Role,
        take_over: bool,
        rows: u16,
        columns: u16,
        limits: everpty::Limits,
    ) -> Result<Self, PtyError> {
        let socket = session.connect_socket()?;
        Self::connect_fd(socket, name, role, take_over, rows, columns, limits, None).await
    }

    /// Connects the persistent everudp gateway as the broker writer and
    /// negotiates the optional direct-PTY fast path. A broker that cannot
    /// grant the lease returns `Unavailable` and remains on the byte-exact
    /// framed edge.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_gateway(
        session: &SessionDir,
        name: &str,
        take_over: bool,
        rows: u16,
        columns: u16,
        limits: everpty::Limits,
        generation: [u8; 16],
    ) -> Result<Self, PtyError> {
        let socket = session.connect_socket()?;
        Self::connect_fd(
            socket,
            name,
            Role::Writer,
            take_over,
            rows,
            columns,
            limits,
            Some(generation),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_fd(
        socket: OwnedFd,
        name: &str,
        role: Role,
        take_over: bool,
        rows: u16,
        columns: u16,
        limits: everpty::Limits,
        gateway_generation: Option<[u8; 16]>,
    ) -> Result<Self, PtyError> {
        sys::set_nonblocking(socket.as_fd())?;
        let socket = AsyncFd::new(socket)?;
        let deadline = deadline_after(limits.incomplete_frame_deadline_ms)?;
        wait_connected(&socket, deadline).await?;
        if sys::peer_uid(socket.get_ref().as_fd())? != sys::effective_uid() {
            return Err(PtyError::PeerUidMismatch);
        }
        let maximum_payload = limits.frame_max_body.saturating_sub(2);
        if maximum_payload == 0 {
            return Err(PtyError::Protocol);
        }
        let maximum_operation = limits.frame_max_body;
        let input_frames = maximum_operation.div_ceil(maximum_payload);
        let send_capacity = maximum_operation
            .checked_add(
                input_frames
                    .checked_mul(BROKER_HEADER_LEN)
                    .ok_or(PtyError::Protocol)?,
            )
            .and_then(|capacity| capacity.checked_add(BROKER_HEADER_LEN + 4))
            .ok_or(PtyError::Protocol)?;
        let mut send = Vec::new();
        send.try_reserve_exact(send_capacity)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        send.resize(send_capacity, 0);
        let mut direct_output = Vec::new();
        direct_output
            .try_reserve_exact(limits.read_chunk_bytes)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        direct_output.resize(limits.read_chunk_bytes, 0);
        let mut this = Self {
            socket,
            reader: BrokerFrameReader::new(&limits)?,
            send_buffer: send.into_boxed_slice(),
            send_len: 0,
            send_offset: 0,
            send_deadline: None,
            pending_input: PendingInput::None,
            limits,
            role,
            direct: None,
            direct_output: direct_output.into_boxed_slice(),
            direct_output_len: 0,
        };
        if let Some(generation) = gateway_generation {
            let pid = std::process::id();
            let process_id = i32::try_from(pid).map_err(|_| PtyError::Protocol)?;
            let start_ticks = sys::proc_start_ticks(process_id)?;
            this.stage_control_frame(&Frame::GatewayHello {
                take_over,
                name: name.to_owned(),
                rows,
                cols: columns,
                generation,
                pid,
                start_ticks,
            })?;
        } else {
            this.stage_hello(name, role, take_over, rows, columns)?;
        }
        this.flush_staged().await?;
        match this.read_handshake_frame().await? {
            Frame::HelloAck {
                client_id,
                broker_protocol_version,
                status,
            } if client_id != 0
                && broker_protocol_version == PROTOCOL_VERSION
                && matches!(
                    (role, status),
                    (Role::Writer, AttachStatus::WriterGranted)
                        | (Role::Observer, AttachStatus::ObserverAccepted)
                ) =>
            {
                if let Some(generation) = gateway_generation {
                    this.negotiate_direct_lease(generation, take_over).await?;
                }
                Ok(this)
            }
            Frame::Busy { current_writer_id } if role == Role::Writer && current_writer_id != 0 => {
                Err(PtyError::Busy { current_writer_id })
            }
            _ => Err(PtyError::Protocol),
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// Own one bounded operation until completion. Polling `next_event` drives
    /// its persistent write offset while continuing to service PTY output.
    /// No input acknowledgement is justified until `InputCommitted` is returned.
    pub fn begin_operation(&mut self, operation: InputOperation<'_>) -> Result<(), PtyError> {
        if self.pending_input != PendingInput::None || self.send_len != 0 {
            return Err(PtyError::Protocol);
        }
        self.pending_input = if let Some(direct) = self.direct.as_ref() {
            match operation {
                InputOperation::Bytes(bytes) => {
                    if bytes.len() > self.limits.frame_max_body {
                        return Err(PtyError::Protocol);
                    }
                    self.send_buffer[..bytes.len()].copy_from_slice(bytes);
                    self.send_len = bytes.len();
                    self.send_offset = 0;
                    PendingInput::DirectBytes
                }
                InputOperation::Resize(resize) => {
                    sys::set_winsize(direct.master.get_ref().as_fd(), resize.rows, resize.columns)?;
                    PendingInput::Complete
                }
                InputOperation::Signal(signal) => {
                    self.stage_payload(BrokerKind::Signal, &[signal])?;
                    PendingInput::Signal
                }
                InputOperation::Close => PendingInput::Complete,
            }
        } else {
            self.stage_operation(operation)?;
            PendingInput::Framed
        };
        Ok(())
    }

    pub fn input_pending(&self) -> bool {
        self.pending_input != PendingInput::None
    }

    /// One nonblocking write for the common small-input case. A short write,
    /// EAGAIN, or terminal error remains owned by next_event, which continues
    /// the same offset and performs the normal lease/error handling.
    pub(crate) fn try_commit_direct_input(&mut self) -> bool {
        if self.pending_input != PendingInput::DirectBytes {
            return false;
        }
        let Some(direct) = self.direct.as_ref() else {
            return false;
        };
        if self.send_offset < self.send_len {
            match sys::write_fd(
                direct.master.get_ref().as_fd(),
                &self.send_buffer[self.send_offset..self.send_len],
            ) {
                Ok(written) => self.send_offset += written,
                Err(_) => return false,
            }
        }
        if self.send_offset != self.send_len {
            return false;
        }
        self.send_len = 0;
        self.send_offset = 0;
        self.send_deadline = None;
        self.pending_input = PendingInput::None;
        true
    }

    /// Stage a size change immediately before the same writer's bytes. The
    /// framed fallback uses one buffer so neither part can interleave.
    pub(crate) fn begin_operation_resized(
        &mut self,
        operation: InputOperation<'_>,
        resize: Option<crate::wire::Resize>,
    ) -> Result<(), PtyError> {
        let Some(resize) = resize else {
            return self.begin_operation(operation);
        };
        if self.input_pending() || self.send_len != 0 {
            return Err(PtyError::Protocol);
        }
        if let Some(direct) = &self.direct {
            sys::set_winsize(direct.master.get_ref().as_fd(), resize.rows, resize.columns)?;
            return self.begin_operation(operation);
        }
        self.begin_operation(operation)?;
        let prefix = BROKER_HEADER_LEN + 4;
        let end = self
            .send_len
            .checked_add(prefix)
            .filter(|end| *end <= self.send_buffer.len())
            .ok_or(PtyError::Protocol)?;
        self.send_buffer.copy_within(..self.send_len, prefix);
        self.send_buffer[..4].copy_from_slice(&6_u32.to_be_bytes());
        self.send_buffer[4] = PROTOCOL_VERSION;
        self.send_buffer[5] = BrokerKind::Resize as u8;
        self.send_buffer[6..8].copy_from_slice(&resize.rows.to_be_bytes());
        self.send_buffer[8..10].copy_from_slice(&resize.columns.to_be_bytes());
        self.send_len = end;
        Ok(())
    }

    /// Delivers one complete ordered input operation to everpty. `Close` is
    /// a QUIC half-close only: the persistent gateway deliberately retains
    /// its broker writer connection so output and later associations live.
    pub async fn send_operation(&mut self, operation: InputOperation<'_>) -> Result<(), PtyError> {
        if self.input_pending() {
            return Err(PtyError::Protocol);
        }
        if self.direct.is_some() {
            return self.send_direct_operation(operation).await;
        }
        self.stage_operation(operation)?;
        self.flush_staged().await
    }

    async fn send_direct_operation(
        &mut self,
        operation: InputOperation<'_>,
    ) -> Result<(), PtyError> {
        match operation {
            InputOperation::Bytes(bytes) => self.write_direct_input(bytes).await,
            InputOperation::Resize(resize) => {
                let direct = self.direct.as_ref().ok_or(PtyError::Protocol)?;
                sys::set_winsize(direct.master.get_ref().as_fd(), resize.rows, resize.columns)?;
                Ok(())
            }
            InputOperation::Signal(signal) => {
                self.stage_payload(BrokerKind::Signal, &[signal])?;
                self.flush_staged().await?;
                self.lease_barrier().await
            }
            InputOperation::Close => Ok(()),
        }
    }

    async fn write_direct_input(&mut self, bytes: &[u8]) -> Result<(), PtyError> {
        let mut offset = 0;
        while offset < bytes.len() {
            let direct = self.direct.as_ref().ok_or(PtyError::Protocol)?;
            let mut writable = direct.master.writable().await?;
            match writable.try_io(|inner| sys::write_fd(inner.get_ref().as_fd(), &bytes[offset..]))
            {
                Ok(Ok(0)) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(Ok(written)) => offset += written,
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => {}
            }
        }
        Ok(())
    }

    /// Encodes one complete everudp operation into broker frames without
    /// acknowledging it. The caller flushes the staged bytes before
    /// committing the corresponding QUIC input sequence.
    pub fn stage_operation(&mut self, operation: InputOperation<'_>) -> Result<(), PtyError> {
        if self.send_len != 0 {
            return Err(PtyError::Protocol);
        }
        match operation {
            InputOperation::Bytes(bytes) => {
                let maximum = self.limits.frame_max_body.saturating_sub(2);
                if maximum == 0 || bytes.len() > self.limits.frame_max_body {
                    return Err(PtyError::Protocol);
                }
                for chunk in bytes.chunks(maximum) {
                    self.stage_payload(BrokerKind::Input, chunk)?;
                }
            }
            InputOperation::Resize(resize) => {
                let mut payload = [0_u8; 4];
                payload[..2].copy_from_slice(&resize.rows.to_be_bytes());
                payload[2..].copy_from_slice(&resize.columns.to_be_bytes());
                self.stage_payload(BrokerKind::Resize, &payload)?;
            }
            InputOperation::Signal(signal) => {
                self.stage_payload(BrokerKind::Signal, &[signal])?;
            }
            InputOperation::Close => {}
        }
        Ok(())
    }

    pub async fn flush_staged(&mut self) -> Result<(), PtyError> {
        flush_input_parts(
            &self.socket,
            &self.send_buffer,
            &mut self.send_len,
            &mut self.send_offset,
            &mut self.send_deadline,
            self.limits,
        )
        .await
    }

    /// Returns one broker event or input completion. Output events remain current until
    /// [`PtySession::consume_event`] is called, which lets the gateway defer a
    /// complete frame without allocating a pending payload. InputCommitted
    /// is a one-shot notification and must not be consumed with consume_event.
    pub async fn next_event(&mut self) -> Result<PtyEvent, PtyError> {
        enum Ready {
            Input(Result<(), PtyError>),
            Output(Result<PtyEvent, PtyError>),
        }
        let ready = tokio::select! {
            biased;
            result = advance_input_parts(
                &self.socket, self.direct.as_ref(), &mut self.send_buffer,
                &mut self.send_len, &mut self.send_offset, &mut self.send_deadline,
                &mut self.pending_input, self.limits,
            ) => Ready::Input(result),
            result = next_output_parts(
                &self.socket, self.direct.as_ref(), &mut self.reader,
                &mut self.direct_output, &mut self.direct_output_len, self.limits,
            ) => Ready::Output(result),
        };
        match ready {
            Ready::Input(Err(PtyError::Io(error)))
                if self.direct.is_some() && sys::is_pty_terminal_error(&error) =>
            {
                Ok(PtyEvent::DirectLeaseEnded)
            }
            Ready::Input(result) => result.map(|()| PtyEvent::InputCommitted),
            Ready::Output(Ok(PtyEvent::InputCommitted)) => {
                if self.pending_input != PendingInput::WaitingBarrier {
                    return Err(PtyError::Protocol);
                }
                self.pending_input = PendingInput::None;
                Ok(PtyEvent::InputCommitted)
            }
            Ready::Output(event) => event,
        }
    }

    pub fn output_bytes(&self) -> &[u8] {
        if self.direct_output_len != 0 {
            return &self.direct_output[..self.direct_output_len];
        }
        let Some(frame) = self.reader.frame() else {
            return &[];
        };
        if frame[5] != BrokerKind::Output as u8 {
            return &[];
        }
        &frame[BROKER_HEADER_LEN..]
    }

    pub fn consume_event(&mut self) -> Result<(), PtyError> {
        if self.direct_output_len != 0 {
            self.direct_output_len = 0;
            return Ok(());
        }
        self.reader.consume(&self.limits)
    }

    fn stage_hello(
        &mut self,
        name: &str,
        role: Role,
        take_over: bool,
        rows: u16,
        columns: u16,
    ) -> Result<(), PtyError> {
        if name.len() > u16::MAX as usize {
            return Err(PtyError::Protocol);
        }
        let payload_len = 8_usize.checked_add(name.len()).ok_or(PtyError::Protocol)?;
        let start = self.stage_header(BrokerKind::Hello, payload_len)?;
        let payload = &mut self.send_buffer[start..start + payload_len];
        payload[0] = role as u8;
        payload[1] = u8::from(take_over);
        payload[2..4].copy_from_slice(&(name.len() as u16).to_be_bytes());
        payload[4..4 + name.len()].copy_from_slice(name.as_bytes());
        let dimensions = 4 + name.len();
        payload[dimensions..dimensions + 2].copy_from_slice(&rows.to_be_bytes());
        payload[dimensions + 2..].copy_from_slice(&columns.to_be_bytes());
        Ok(())
    }

    fn stage_control_frame(&mut self, frame: &Frame) -> Result<(), PtyError> {
        if self.send_len != 0 {
            return Err(PtyError::Protocol);
        }
        let wire = frame.encode();
        if wire.len() > self.send_buffer.len() {
            return Err(PtyError::Protocol);
        }
        self.send_buffer[..wire.len()].copy_from_slice(&wire);
        self.send_len = wire.len();
        self.send_offset = 0;
        Ok(())
    }

    async fn read_lease_offer(&self, max_len: usize) -> Result<(Frame, Option<OwnedFd>), PtyError> {
        // Read exactly one frame with recvmsg throughout: an SCM_RIGHTS
        // capability must never be lost by a plain read or consumed with
        // the preceding ownership frame.
        let mut wire = vec![0_u8; everpty::frame::HEADER_LEN];
        let mut used = 0;
        let mut descriptor = None;
        loop {
            let (received, incoming) =
                recv_optional_fd_into(&self.socket, &mut wire[used..]).await?;
            if received == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            if let Some(incoming) = incoming {
                if descriptor.is_some() {
                    return Err(PtyError::Protocol);
                }
                descriptor = Some(incoming);
            }
            used += received;
            if used < wire.len() {
                continue;
            }
            if wire.len() == everpty::frame::HEADER_LEN {
                let total = Frame::validate_header(&wire, &self.limits)?;
                if total > max_len {
                    return Err(PtyError::Protocol);
                }
                wire.resize(total, 0);
                if used < wire.len() {
                    continue;
                }
            }
            let (frame, consumed) = Frame::decode(&wire, &self.limits)?;
            if consumed != wire.len() {
                return Err(PtyError::Protocol);
            }
            return Ok((frame, descriptor));
        }
    }

    async fn negotiate_direct_lease(
        &mut self,
        generation: [u8; 16],
        take_over: bool,
    ) -> Result<(), PtyError> {
        let grant_len = Frame::Lease {
            action: LeaseAction::Grant,
            generation,
            lease_id: 1,
        }
        .encode()
        .len();
        let (mut offer, mut descriptor) = self.read_lease_offer(grant_len).await?;
        if take_over
            && matches!(
                offer,
                Frame::Ownership(everpty::frame::OwnershipEvent::Granted)
            )
        {
            if descriptor.is_some() {
                return Err(PtyError::Protocol);
            }
            (offer, descriptor) = self.read_lease_offer(grant_len).await?;
        }
        let (lease_id, descriptor) = match (offer, descriptor) {
            (
                Frame::Lease {
                    action: LeaseAction::Grant,
                    generation: offered_generation,
                    lease_id,
                },
                Some(descriptor),
            ) if offered_generation == generation => (lease_id, descriptor),
            (
                Frame::Lease {
                    action: LeaseAction::Unavailable,
                    generation: offered_generation,
                    lease_id: 0,
                },
                None,
            ) if offered_generation == generation => return Ok(()),
            _ => return Err(PtyError::Protocol),
        };
        sys::set_nonblocking(descriptor.as_fd())?;
        let master = AsyncFd::new(descriptor)?;
        self.stage_control_frame(&Frame::Lease {
            action: LeaseAction::Commit,
            generation,
            lease_id,
        })?;
        self.flush_staged().await?;
        match self.read_handshake_frame().await? {
            Frame::Lease {
                action: LeaseAction::Committed,
                generation: committed_generation,
                lease_id: committed_id,
            } if committed_generation == generation && committed_id == lease_id => {
                self.direct = Some(DirectPtyLease {
                    master,
                    generation,
                    lease_id,
                });
                Ok(())
            }
            _ => Err(PtyError::Protocol),
        }
    }

    async fn lease_barrier(&mut self) -> Result<(), PtyError> {
        let (generation, lease_id) = self
            .direct
            .as_ref()
            .map(|lease| (lease.generation, lease.lease_id))
            .ok_or(PtyError::Protocol)?;
        self.stage_control_frame(&Frame::Lease {
            action: LeaseAction::Barrier,
            generation,
            lease_id,
        })?;
        self.flush_staged().await?;
        match self.read_handshake_frame().await? {
            Frame::Lease {
                action: LeaseAction::BarrierAck,
                generation: acknowledged_generation,
                lease_id: acknowledged_id,
            } if acknowledged_generation == generation && acknowledged_id == lease_id => Ok(()),
            _ => Err(PtyError::Protocol),
        }
    }

    pub(crate) async fn finish_direct_release(&mut self) -> Result<(), PtyError> {
        let Some(direct) = self.direct.take() else {
            return Ok(());
        };
        let generation = direct.generation;
        let lease_id = direct.lease_id;
        drop(direct);
        let mut pending_barrier = matches!(
            self.pending_input,
            PendingInput::Barrier | PendingInput::WaitingBarrier
        );
        match self.pending_input {
            PendingInput::Signal | PendingInput::Barrier => {
                // Finish a partially sent control frame before encoding Release.
                self.flush_staged().await?;
            }
            PendingInput::DirectBytes => {
                // The lease has ended. Never resend the unwritten suffix through
                // the broker or acknowledge a partially delivered operation.
                self.send_len = 0;
                self.send_offset = 0;
            }
            _ => {}
        }
        self.pending_input = PendingInput::None;
        self.stage_control_frame(&Frame::Lease {
            action: LeaseAction::Release,
            generation,
            lease_id,
        })?;
        self.flush_staged().await?;
        let mut saw_revoke = false;
        loop {
            match self.read_handshake_frame().await? {
                Frame::Lease {
                    action: LeaseAction::BarrierAck,
                    generation: acknowledged_generation,
                    lease_id: acknowledged_id,
                } if pending_barrier
                    && acknowledged_generation == generation
                    && acknowledged_id == lease_id =>
                {
                    pending_barrier = false;
                }
                Frame::Lease {
                    action: LeaseAction::Revoke,
                    generation: revoked_generation,
                    lease_id: revoked_id,
                } if !saw_revoke && revoked_generation == generation && revoked_id == lease_id => {
                    // PTY EOF and the broker's revoke notification can become
                    // readable together. Release is still authoritative; drain
                    // the racing notification before waiting for its receipt.
                    saw_revoke = true;
                }
                Frame::Lease {
                    action: LeaseAction::Released,
                    generation: released_generation,
                    lease_id: released_id,
                } if released_generation == generation && released_id == lease_id => return Ok(()),
                _ => return Err(PtyError::Protocol),
            }
        }
    }

    fn stage_payload(&mut self, kind: BrokerKind, payload: &[u8]) -> Result<(), PtyError> {
        let start = self.stage_header(kind, payload.len())?;
        self.send_buffer[start..start + payload.len()].copy_from_slice(payload);
        Ok(())
    }

    fn stage_header(&mut self, kind: BrokerKind, payload_len: usize) -> Result<usize, PtyError> {
        let body_len = payload_len.checked_add(2).ok_or(PtyError::Protocol)?;
        if body_len > self.limits.frame_max_body {
            return Err(PtyError::Protocol);
        }
        let total = BROKER_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(PtyError::Protocol)?;
        let end = self
            .send_len
            .checked_add(total)
            .filter(|end| *end <= self.send_buffer.len())
            .ok_or(PtyError::Protocol)?;
        let header = &mut self.send_buffer[self.send_len..self.send_len + BROKER_HEADER_LEN];
        header[..4].copy_from_slice(&(body_len as u32).to_be_bytes());
        header[4] = PROTOCOL_VERSION;
        header[5] = kind as u8;
        let payload_start = self.send_len + BROKER_HEADER_LEN;
        self.send_len = end;
        Ok(payload_start)
    }

    async fn read_handshake_frame(&mut self) -> Result<Frame, PtyError> {
        read_frame_ready_exact(&self.socket, &mut self.reader, self.limits).await?;
        let frame = self.reader.frame().ok_or(PtyError::Protocol)?;
        let (decoded, consumed) = Frame::decode(frame, &self.limits)?;
        if consumed != frame.len() {
            return Err(PtyError::Protocol);
        }
        self.reader.consume(&self.limits)?;
        Ok(decoded)
    }

    fn decode_event(reader: &BrokerFrameReader) -> Result<PtyEvent, PtyError> {
        let frame = reader.frame().ok_or(PtyError::Protocol)?;
        let payload = &frame[BROKER_HEADER_LEN..];
        match BrokerKind::from_u8(frame[5]).ok_or(PtyError::Protocol)? {
            BrokerKind::Output => Ok(PtyEvent::Output(payload.len())),
            BrokerKind::Ownership if payload == [1] => Ok(PtyEvent::Ownership(1)),
            BrokerKind::Ownership if payload == [2] => Ok(PtyEvent::Ownership(2)),
            BrokerKind::Exit if payload.len() == 5 => {
                let value =
                    u32::from_be_bytes(payload[1..].try_into().map_err(|_| PtyError::Protocol)?);
                match (payload[0], value) {
                    (0, value) if value <= u8::MAX as u32 => Ok(PtyEvent::Exit(value as i32)),
                    (1, value) if (1..=64).contains(&value) => {
                        Ok(PtyEvent::Exit(128 + value as i32))
                    }
                    _ => Err(PtyError::Protocol),
                }
            }
            _ => Err(PtyError::Protocol),
        }
    }

    #[cfg(test)]
    fn allocation_signature(&self) -> (usize, usize, usize, usize) {
        (
            self.reader.bytes.as_ptr() as usize,
            self.reader.bytes.len(),
            self.send_buffer.as_ptr() as usize,
            self.send_buffer.len(),
        )
    }
}

impl fmt::Debug for PtySession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PtySession")
            .field("role", &self.role)
            .field("reader", &self.reader)
            .field("payload", &"<REDACTED>")
            .finish_non_exhaustive()
    }
}

#[allow(clippy::too_many_arguments)]
async fn advance_input_parts(
    socket: &AsyncFd<OwnedFd>,
    direct: Option<&DirectPtyLease>,
    buffer: &mut [u8],
    len: &mut usize,
    offset: &mut usize,
    deadline: &mut Option<u64>,
    pending: &mut PendingInput,
    limits: everpty::Limits,
) -> Result<(), PtyError> {
    loop {
        match *pending {
            PendingInput::None | PendingInput::WaitingBarrier => {
                return std::future::pending().await
            }
            PendingInput::DirectBytes => {
                let master = &direct.ok_or(PtyError::Protocol)?.master;
                while *offset < *len {
                    let mut writable = master.writable().await?;
                    match writable.try_io(|inner| {
                        sys::write_fd(inner.get_ref().as_fd(), &buffer[*offset..*len])
                    }) {
                        Ok(Ok(0)) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                        Ok(Ok(written)) => *offset += written,
                        Ok(Err(error)) => return Err(error.into()),
                        Err(_) => {}
                    }
                }
                *len = 0;
                *offset = 0;
                *pending = PendingInput::Complete;
            }
            PendingInput::Framed | PendingInput::Signal | PendingInput::Barrier => {
                flush_input_parts(socket, buffer, len, offset, deadline, limits).await?;
                *pending = match *pending {
                    PendingInput::Signal => {
                        let lease = direct.ok_or(PtyError::Protocol)?;
                        let wire = Frame::Lease {
                            action: LeaseAction::Barrier,
                            generation: lease.generation,
                            lease_id: lease.lease_id,
                        }
                        .encode();
                        if wire.len() > buffer.len() {
                            return Err(PtyError::Protocol);
                        }
                        buffer[..wire.len()].copy_from_slice(&wire);
                        *len = wire.len();
                        PendingInput::Barrier
                    }
                    PendingInput::Barrier => PendingInput::WaitingBarrier,
                    _ => PendingInput::Complete,
                };
            }
            PendingInput::Complete => {
                *pending = PendingInput::None;
                return Ok(());
            }
        }
    }
}

async fn flush_input_parts(
    socket: &AsyncFd<OwnedFd>,
    buffer: &[u8],
    len: &mut usize,
    offset: &mut usize,
    deadline: &mut Option<u64>,
    limits: everpty::Limits,
) -> Result<(), PtyError> {
    if *len == 0 {
        return Ok(());
    }
    let expires = *deadline.get_or_insert(deadline_after(limits.incomplete_frame_deadline_ms)?);
    while *offset < *len {
        let mut writable = tokio::time::timeout(remaining(expires)?, socket.writable())
            .await
            .map_err(|_| PtyError::Timeout)??;
        match writable
            .try_io(|inner| sys::send_no_sigpipe(inner.get_ref().as_fd(), &buffer[*offset..*len]))
        {
            Ok(Ok(0)) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
            Ok(Ok(written)) => *offset += written,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {}
        }
    }
    *len = 0;
    *offset = 0;
    *deadline = None;
    Ok(())
}

async fn next_output_parts(
    socket: &AsyncFd<OwnedFd>,
    direct: Option<&DirectPtyLease>,
    reader: &mut BrokerFrameReader,
    output: &mut [u8],
    output_len: &mut usize,
    limits: everpty::Limits,
) -> Result<PtyEvent, PtyError> {
    if *output_len != 0 {
        return Ok(PtyEvent::Output(*output_len));
    }
    let Some(direct) = direct else {
        read_frame_ready_parts(socket, reader, limits).await?;
        return PtySession::decode_event(reader);
    };
    enum Ready {
        Master(io::Result<usize>),
        Broker(Result<(), PtyError>),
    }
    let ready = tokio::select! {
        biased;
        result = read_frame_ready_parts(socket, reader, limits) => Ready::Broker(result),
        result = read_direct_into(&direct.master, output) => Ready::Master(result),
    };
    match ready {
        Ready::Master(Ok(0)) => Ok(PtyEvent::DirectLeaseEnded),
        Ready::Master(Ok(read)) => {
            *output_len = read;
            Ok(PtyEvent::Output(read))
        }
        Ready::Master(Err(error)) if sys::is_pty_terminal_error(&error) => {
            Ok(PtyEvent::DirectLeaseEnded)
        }
        Ready::Master(Err(error)) => Err(error.into()),
        Ready::Broker(Ok(())) => {
            let wire = reader.frame().ok_or(PtyError::Protocol)?;
            let (frame, used) = Frame::decode(wire, &limits)?;
            if used != wire.len() {
                return Err(PtyError::Protocol);
            }
            reader.consume(&limits)?;
            match frame {
                Frame::Lease {
                    action,
                    generation,
                    lease_id,
                } if generation == direct.generation && lease_id == direct.lease_id => match action
                {
                    LeaseAction::BarrierAck => Ok(PtyEvent::InputCommitted),
                    LeaseAction::Revoke => Ok(PtyEvent::DirectLeaseEnded),
                    _ => Err(PtyError::Protocol),
                },
                _ => Err(PtyError::Protocol),
            }
        }
        Ready::Broker(Err(error)) => Err(error),
    }
}

async fn wait_connected(socket: &AsyncFd<OwnedFd>, deadline: u64) -> Result<(), PtyError> {
    let writable = tokio::time::timeout(remaining(deadline)?, socket.writable())
        .await
        .map_err(|_| PtyError::Timeout)??;
    if let Some(errno) = sys::socket_error(socket.get_ref().as_fd())? {
        return Err(io::Error::from_raw_os_error(errno).into());
    }
    drop(writable);
    Ok(())
}

async fn read_into(socket: &AsyncFd<OwnedFd>, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut readable = socket.readable().await?;
        if let Ok(result) =
            readable.try_io(|inner| match sys::recv(inner.get_ref().as_fd(), buffer)? {
                Some(read) => Ok(read),
                None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            })
        {
            return result;
        }
    }
}

async fn recv_optional_fd_into(
    socket: &AsyncFd<OwnedFd>,
    buffer: &mut [u8],
) -> io::Result<(usize, Option<OwnedFd>)> {
    loop {
        let mut readable = socket.readable().await?;
        if let Ok(result) = readable.try_io(|inner| {
            sys::recv_optional_fd(inner.get_ref().as_fd(), buffer)?
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
        }) {
            return result;
        }
    }
}

async fn read_direct_into(master: &AsyncFd<OwnedFd>, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut readable = master.readable().await?;
        if let Ok(result) = readable.try_io(|inner| sys::read_fd(inner.get_ref().as_fd(), buffer)) {
            return result;
        }
    }
}

async fn read_frame_ready_parts(
    socket: &AsyncFd<OwnedFd>,
    reader: &mut BrokerFrameReader,
    limits: everpty::Limits,
) -> Result<(), PtyError> {
    loop {
        if reader.frame().is_some() {
            return Ok(());
        }
        let read = if let Some(start) = reader.started_ms() {
            let deadline = start.saturating_add(limits.incomplete_frame_deadline_ms);
            tokio::time::timeout(remaining(deadline)?, read_into(socket, reader.writable()))
                .await
                .map_err(|_| PtyError::Timeout)??
        } else {
            read_into(socket, reader.writable()).await?
        };
        if read == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        reader.commit_read(read, sys::clock_monotonic_ms()?, &limits)?;
    }
}

async fn read_frame_ready_exact(
    socket: &AsyncFd<OwnedFd>,
    reader: &mut BrokerFrameReader,
    limits: everpty::Limits,
) -> Result<(), PtyError> {
    loop {
        if reader.frame().is_some() {
            return Ok(());
        }
        let read = if let Some(start) = reader.started_ms() {
            let deadline = start.saturating_add(limits.incomplete_frame_deadline_ms);
            tokio::time::timeout(
                remaining(deadline)?,
                read_into(socket, reader.current_frame_writable()),
            )
            .await
            .map_err(|_| PtyError::Timeout)??
        } else {
            read_into(socket, reader.current_frame_writable()).await?
        };
        if read == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        reader.commit_read(read, sys::clock_monotonic_ms()?, &limits)?;
    }
}

fn deadline_after(milliseconds: u64) -> Result<u64, PtyError> {
    Ok(sys::clock_monotonic_ms()?.saturating_add(milliseconds))
}

fn remaining(deadline: u64) -> Result<Duration, PtyError> {
    let now = sys::clock_monotonic_ms()?;
    if now >= deadline {
        return Err(PtyError::Timeout);
    }
    Ok(Duration::from_millis(deadline - now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Resize;
    use everpty::frame::OwnershipEvent;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::thread;

    fn read_frame(stream: &mut UnixStream, limits: &everpty::Limits) -> Frame {
        let mut header = [0_u8; everpty::frame::HEADER_LEN];
        stream.read_exact(&mut header).expect("read header");
        let total = Frame::validate_header(&header, limits).expect("valid header");
        let mut encoded = vec![0_u8; total];
        encoded[..header.len()].copy_from_slice(&header);
        stream
            .read_exact(&mut encoded[header.len()..])
            .expect("read body");
        Frame::decode(&encoded, limits).expect("decode frame").0
    }

    fn write_frame(stream: &mut UnixStream, frame: &Frame) {
        stream.write_all(&frame.encode()).expect("write frame");
    }

    /// A real non-reading slave forces several partial writes. Repeatedly
    /// canceling the gateway wait must neither lose wakeups nor resend a prefix.
    #[tokio::test(flavor = "current_thread")]
    async fn staged_direct_input_survives_cancellation_and_services_output() {
        let limits = everpty::Limits::default();
        let (socket, _broker) = sys::socketpair_cloexec().expect("staged input fixture");
        let (master, slave) = sys::openpty(24, 80).expect("staged input fixture");
        let attrs = sys::terminal_attributes(slave.as_fd()).expect("staged input fixture");
        sys::set_terminal_raw(slave.as_fd(), &attrs).expect("staged input fixture");
        sys::set_nonblocking(master.as_fd()).expect("staged input fixture");
        sys::set_nonblocking(socket.as_fd()).expect("staged input fixture");
        sys::set_nonblocking(slave.as_fd()).expect("staged input fixture");
        let mut session = PtySession {
            socket: AsyncFd::new(socket).expect("staged input fixture"),
            reader: BrokerFrameReader::new(&limits).expect("staged input fixture"),
            send_buffer: vec![0; limits.frame_max_body + 2 * BROKER_HEADER_LEN].into_boxed_slice(),
            send_len: 0,
            send_offset: 0,
            send_deadline: None,
            pending_input: PendingInput::None,
            limits,
            role: Role::Writer,
            direct: Some(DirectPtyLease {
                master: AsyncFd::new(master).expect("staged input fixture"),
                generation: [1; 16],
                lease_id: 1,
            }),
            direct_output: vec![0; limits.read_chunk_bytes].into_boxed_slice(),
            direct_output_len: 0,
        };
        let allocation = session.allocation_signature();
        let input: Vec<u8> = (0..limits.frame_max_body)
            .map(|n| (n % 251) as u8)
            .collect();
        session
            .begin_operation(InputOperation::Bytes(&input))
            .expect("staged input fixture");
        assert!(
            !session.try_commit_direct_input(),
            "a partial write cannot ACK"
        );
        assert!(session.send_offset > 0 && session.send_offset < input.len());
        for _ in 0..3 {
            assert!(
                tokio::time::timeout(Duration::from_millis(10), session.next_event())
                    .await
                    .is_err()
            );
        }
        assert!(session.send_offset > 0 && session.send_offset < input.len());
        assert!(session
            .begin_operation(InputOperation::Bytes(b"must not interleave"))
            .is_err());
        sys::write_fd(slave.as_fd(), b"live output").expect("staged input fixture");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), session.next_event())
                .await
                .expect("staged input fixture")
                .expect("staged input fixture"),
            PtyEvent::Output(11),
        );
        assert_eq!(session.output_bytes(), b"live output");
        session.consume_event().expect("staged input fixture");
        assert!(session.input_pending());
        let reader = tokio::spawn(async move {
            let slave = AsyncFd::new(slave).expect("staged input fixture");
            let mut received = Vec::new();
            let mut buf = [0; 4096];
            while received.len() < limits.frame_max_body {
                let read = read_direct_into(&slave, &mut buf)
                    .await
                    .expect("staged input fixture");
                received.extend_from_slice(&buf[..read]);
            }
            // Keep the slave alive until the caller has observed input commit.
            (received, slave)
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), session.next_event())
                .await
                .expect("staged input fixture")
                .expect("staged input fixture"),
            PtyEvent::InputCommitted,
        );
        let (received, _slave) = reader.await.expect("staged input fixture");
        assert_eq!(received, input);
        assert!(!session.input_pending());
        assert_eq!(session.allocation_signature(), allocation);
        session
            .begin_operation(InputOperation::Bytes(b"fast"))
            .expect("small direct operation");
        assert!(session.try_commit_direct_input());
        assert!(!session.input_pending());
        assert!(
            !session.try_commit_direct_input(),
            "completion is emitted only once"
        );
        let mut fast = [0_u8; 4];
        let ready = _slave.readable().await.expect("small input readable");
        assert_eq!(
            sys::read_fd(_slave.get_ref().as_fd(), &mut fast).expect("read small input"),
            4
        );
        drop(ready);
        assert_eq!(&fast, b"fast");

        // Signal completion waits for the matching broker barrier receipt,
        // but a blocked receipt must not prevent terminal output.
        let (release, wait) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let mut stream = UnixStream::from(_broker);
            assert_eq!(
                read_frame(&mut stream, &limits),
                Frame::Signal { signal: 2 }
            );
            assert_eq!(
                read_frame(&mut stream, &limits),
                Frame::Lease {
                    action: LeaseAction::Barrier,
                    generation: [1; 16],
                    lease_id: 1,
                }
            );
            wait.recv().expect("staged input fixture");
            write_frame(
                &mut stream,
                &Frame::Lease {
                    action: LeaseAction::BarrierAck,
                    generation: [1; 16],
                    lease_id: 1,
                },
            );
            stream
        });
        session
            .begin_operation(InputOperation::Signal(2))
            .expect("staged input fixture");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), session.next_event())
                .await
                .is_err()
        );
        sys::write_fd(_slave.get_ref().as_fd(), b"signal output").expect("staged input fixture");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), session.next_event())
                .await
                .expect("staged input fixture")
                .expect("staged input fixture"),
            PtyEvent::Output(13)
        );
        session.consume_event().expect("staged input fixture");
        assert!(session.input_pending());
        release.send(()).expect("staged input fixture");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), session.next_event())
                .await
                .expect("staged input fixture")
                .expect("staged input fixture"),
            PtyEvent::InputCommitted
        );
        let _broker = worker.join().expect("staged input fixture");
        assert!(!session.input_pending());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gateway_takeover_accepts_ownership_before_lease() {
        for direct in [false, true] {
            let limits = everpty::Limits::default();
            let generation = [7; 16];
            let (client, server) = sys::socketpair_cloexec().expect("socket pair");
            let worker = thread::spawn(move || {
                let mut stream = UnixStream::from(server);
                assert!(matches!(
                    read_frame(&mut stream, &limits),
                    Frame::GatewayHello {
                        take_over: true,
                        ..
                    }
                ));
                write_frame(
                    &mut stream,
                    &Frame::HelloAck {
                        client_id: 9,
                        broker_protocol_version: PROTOCOL_VERSION,
                        status: AttachStatus::WriterGranted,
                    },
                );
                write_frame(&mut stream, &Frame::Ownership(OwnershipEvent::Granted));
                if direct {
                    let (master, _slave) = sys::openpty(24, 80).expect("pty");
                    let grant = Frame::Lease {
                        action: LeaseAction::Grant,
                        generation,
                        lease_id: 1,
                    }
                    .encode();
                    assert_eq!(
                        sys::send_one_fd(stream.as_fd(), &grant, master.as_fd())
                            .expect("send lease"),
                        grant.len()
                    );
                    assert!(matches!(
                        read_frame(&mut stream, &limits),
                        Frame::Lease {
                            action: LeaseAction::Commit,
                            ..
                        }
                    ));
                    write_frame(
                        &mut stream,
                        &Frame::Lease {
                            action: LeaseAction::Committed,
                            generation,
                            lease_id: 1,
                        },
                    );
                } else {
                    write_frame(
                        &mut stream,
                        &Frame::Lease {
                            action: LeaseAction::Unavailable,
                            generation,
                            lease_id: 0,
                        },
                    );
                    assert_eq!(
                        read_frame(&mut stream, &limits),
                        Frame::Input(b"\r".to_vec())
                    );
                }
            });
            let mut session = PtySession::connect_fd(
                client,
                "demo",
                Role::Writer,
                true,
                24,
                80,
                limits,
                Some(generation),
            )
            .await
            .expect("takeover lease handshake");
            assert_eq!(session.direct.is_some(), direct);
            if !direct {
                session
                    .send_operation(InputOperation::Bytes(b"\r"))
                    .await
                    .expect("Enter after takeover");
            }
            worker.join().expect("broker worker");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ordered_operations_and_events_cross_the_broker_edge_exactly() {
        let limits = everpty::Limits::default();
        let (client, server) = sys::socketpair_cloexec().expect("socket pair");
        let worker = thread::spawn(move || {
            let mut stream = UnixStream::from(server);
            assert!(matches!(
                read_frame(&mut stream, &limits),
                Frame::Hello {
                    role: Role::Writer,
                    take_over: false,
                    rows: 31,
                    cols: 97,
                    ..
                }
            ));
            write_frame(
                &mut stream,
                &Frame::HelloAck {
                    client_id: 7,
                    broker_protocol_version: PROTOCOL_VERSION,
                    status: AttachStatus::WriterGranted,
                },
            );
            assert_eq!(
                read_frame(&mut stream, &limits),
                Frame::Input(vec![0, 0xff, b'x'])
            );
            assert_eq!(
                read_frame(&mut stream, &limits),
                Frame::Resize {
                    rows: 44,
                    cols: 132
                }
            );
            assert_eq!(
                read_frame(&mut stream, &limits),
                Frame::Signal { signal: 15 }
            );
            write_frame(&mut stream, &Frame::Output(vec![b'a', 0, 0xff]));
            write_frame(&mut stream, &Frame::Ownership(OwnershipEvent::Granted));
            write_frame(
                &mut stream,
                &Frame::Exit {
                    signal: true,
                    value: 9,
                },
            );
        });

        let mut session =
            PtySession::connect_fd(client, "demo", Role::Writer, false, 31, 97, limits, None)
                .await
                .expect("connect");
        let allocation = session.allocation_signature();
        session
            .send_operation(InputOperation::Bytes(&[0, 0xff, b'x']))
            .await
            .expect("input");
        session
            .send_operation(InputOperation::Resize(Resize {
                rows: 44,
                columns: 132,
                pixel_width: 0,
                pixel_height: 0,
            }))
            .await
            .expect("resize");
        session
            .send_operation(InputOperation::Signal(15))
            .await
            .expect("signal");
        session
            .send_operation(InputOperation::Close)
            .await
            .expect("half close");

        assert_eq!(
            session.next_event().await.expect("output"),
            PtyEvent::Output(3)
        );
        assert_eq!(session.output_bytes(), [b'a', 0, 0xff]);
        session.consume_event().expect("consume output");
        assert_eq!(
            session.next_event().await.expect("ownership"),
            PtyEvent::Ownership(1)
        );
        session.consume_event().expect("consume ownership");
        assert_eq!(
            session.next_event().await.expect("exit"),
            PtyEvent::Exit(137)
        );
        session.consume_event().expect("consume exit");
        assert_eq!(session.allocation_signature(), allocation);
        worker.join().expect("worker");
    }
}
