//! Authenticated noQ DATAGRAM latency floor for the v4 go/no-go gate.
//!
//! This deliberately excludes the persistent terminal actors. It keeps the
//! production SSH bootstrap, certificate pinning, client-certificate binding,
//! QUIC admission, v4 wire envelope, and exact local terminal sink.
#![allow(clippy::print_stderr)]

#[cfg(feature = "floor-single-owner")]
#[path = "support/floor_single_owner.rs"]
mod floor_single_owner;
#[path = "support/floor_trace.rs"]
mod floor_trace;
#[cfg(feature = "floor-single-owner")]
#[path = "support/native_trace.rs"]
mod native_trace;
#[cfg(feature = "floor-single-owner")]
#[path = "support/phase_timing.rs"]
mod phase_timing;
#[cfg(feature = "floor-single-owner")]
#[path = "support/reactor_trace.rs"]
mod reactor_trace;
use floor_trace::{Trace, TraceStage};
#[cfg(feature = "floor-diagnostics")]
#[path = "support/floor_alloc.rs"]
mod floor_alloc;
#[cfg(feature = "floor-diagnostics")]
#[path = "support/floor_resources.rs"]
mod floor_resources;
#[cfg(feature = "floor-diagnostics")]
#[global_allocator]
static ALLOCATOR: floor_alloc::CountingAllocator = floor_alloc::CountingAllocator;

use bytes::{Bytes, BytesMut};
use clap::{ArgAction, Parser, Subcommand};
use everssh::association::AssociationId;
use everssh::role_protocol::parse_ssh_connection;
use everssh::ssh_bootstrap::{acquire_bootstrap_bytes, verify_effective_config};
use everssh::ssh_policy::SshPlan;
use everudp::reliable_datagram::{
    decode, encode_data, AckState, Data, Direction, Frame, MAX_WIRE_LEN, VERSION,
};
use everudp::wire::ConnectionRole;
use everudp::{
    BootstrapOperation, BootstrapRecord, BootstrapRequest, ClientEndpoint, ClientHello,
    ClientIdentity, GatewayEndpoint, GatewayGeneration, GatewayIdentity, InvitationStore, Limits,
    LocalEvent, ResumePosition, SharedInvitationStore, TerminalEdge, TerminalEvent, UdpBindPolicy,
};
use noq::Connection;
use std::collections::VecDeque;
use std::error::Error;
use std::future::poll_fn;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::process::{ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command as TokioCommand;
use tokio::sync::Notify;
use tokio::time::{sleep, sleep_until, Instant};

type FloorResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const CLIENT_CAPABILITY: [u8; 8] = [b'E', b'U', VERSION, 1, 0x04, 0x00, 0x04, 0xb0];
const SERVER_CAPABILITY: [u8; 8] = [b'E', b'U', VERSION, 2, 0x04, 0x00, 0x04, 0xb0];
const FLOOR_BOOTSTRAP_ROLE: &str = "__floor-bootstrap-v1";
const FLOOR_SERVER_ROLE: &str = "__floor-server-v1";
const PACKET_POOL_SIZE: usize = 512;
const RETRANSMIT_DELAY: Duration = Duration::from_millis(2);
static TRACE: OnceLock<Trace> = OnceLock::new();
static SERVER_TRACE: OnceLock<Vec<u8>> = OnceLock::new();
#[cfg(feature = "floor-single-owner")]
static NATIVE_TRACE_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
#[cfg(feature = "floor-single-owner")]
static REACTOR_TRACE_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
#[cfg(feature = "floor-single-owner")]
static PARTITION_TRACE_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
const TRACE_ENABLE: u8 = 0xe1;
const TRACE_EXPORT: u8 = 0xe2;
const SERVER_TRACE_EVENTS: usize = 8192;
const MAX_SERVER_TRACE_BYTES: usize = 2 * 1024 * 1024;

struct BoundedTraceBytes(Vec<u8>);

impl Write for BoundedTraceBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_SERVER_TRACE_BYTES.saturating_sub(self.0.len()) {
            return Err(protocol_error("server trace exceeded export cap"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn export_server_trace(
    send: &mut noq::SendStream,
    recv: &mut noq::RecvStream,
) -> FloorResult<()> {
    // The public PTY driver grants three seconds after SIGTERM before SIGKILL.
    // Leave time for local evidence flush and terminal restoration.
    tokio::time::timeout(Duration::from_secs(2), async {
        send.write_all(&[TRACE_EXPORT]).await?;
        let mut length = [0_u8; 4];
        recv.read_exact(&mut length).await?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_SERVER_TRACE_BYTES {
            return Err(protocol_error("invalid server trace length").into());
        }
        let mut bytes = vec![0_u8; length];
        recv.read_exact(&mut bytes).await?;
        SERVER_TRACE
            .set(bytes)
            .map_err(|_| protocol_error("duplicate server trace"))?;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

fn trace(stage: TraceStage, sequence: Option<u64>) {
    if let Some(recorder) = TRACE.get() {
        recorder.record(stage, sequence);
    }
}

fn enable_noq_diagnostics() -> FloorResult<()> {
    #[cfg(feature = "floor-diagnostics")]
    noq::diagnostic::install(|event| {
        use noq::diagnostic::Event;
        let contextual = match event {
            Event::ProtocolTransmitStart { connection } => {
                Some((TraceStage::ProtocolTransmitStart, connection))
            }
            Event::ProtocolTransmitReady { connection } => {
                Some((TraceStage::ProtocolTransmitReady, connection))
            }
            Event::ProtocolTransmitIdle { connection } => {
                Some((TraceStage::ProtocolTransmitIdle, connection))
            }
            Event::DriverService { connection } => Some((TraceStage::DriverService, connection)),
            Event::InlineCallbackEnter { connection } => {
                Some((TraceStage::InlineCallbackEnter, connection))
            }
            Event::InlineCallbackExit { connection } => {
                Some((TraceStage::InlineCallbackExit, connection))
            }
            Event::InlineResponseQueued { connection } => {
                Some((TraceStage::InlineResponseQueued, connection))
            }
            Event::InlineResponseBlocked { connection } => {
                Some((TraceStage::InlineResponseBlocked, connection))
            }
            Event::InlineDriverWakeRequested { connection } => {
                Some((TraceStage::InlineDriverWakeRequested, connection))
            }
            _ => None,
        };
        if let Some((stage, connection)) = contextual {
            if let Some(recorder) = TRACE.get() {
                recorder.record_connection(stage, connection);
            }
            return;
        }
        let stage = match event {
            Event::UdpReceive => TraceStage::UdpReceive,
            Event::ReceiveCopy => TraceStage::ReceiveCopy,
            Event::DriverPoll => TraceStage::DriverPoll,
            Event::TransmitPoll => TraceStage::TransmitPoll,
            Event::TransmitAccepted => TraceStage::TransmitAccepted,
            Event::TransmitBlocked => TraceStage::TransmitBlocked,
            Event::TransmitError => TraceStage::TransmitError,
            _ => return,
        };
        trace(stage, None);
    })
    .map_err(|_| protocol_error("diagnostic hook already installed"))?;
    Ok(())
}

#[derive(Debug, Parser)]
#[command(name = "everudp-floor")]
struct Cli {
    #[command(subcommand)]
    command: FloorCommand,
}

#[derive(Debug, Subcommand)]
enum FloorCommand {
    /// Run the local authenticated DATAGRAM echo edge.
    Client {
        /// Opt-in client JSON and PATH.server.json; both must be new files.
        #[arg(long)]
        trace_json: Option<std::path::PathBuf>,
        /// Opt-in native client stage trace; requires floor-single-owner.
        #[arg(long, conflicts_with = "trace_json")]
        native_trace_json: Option<std::path::PathBuf>,
        /// Opt-in native reactor-work recording; requires floor-single-owner.
        #[arg(long, conflicts_with_all = ["trace_json", "native_trace_json"])]
        reactor_trace_json: Option<std::path::PathBuf>,
        /// Opt-in reactor phase timing; requires floor-single-owner.
        #[arg(long, conflicts_with_all = ["trace_json", "native_trace_json", "reactor_trace_json"])]
        partition_trace_json: Option<std::path::PathBuf>,
        destination: String,
        #[arg(long)]
        session: String,
        #[arg(long = "remote-program", value_name = "ABSOLUTE_PATH")]
        remote_program: String,
        #[arg(
            long = "ssh-option",
            value_name = "OPTION",
            action = ArgAction::Append,
            allow_hyphen_values = true
        )]
        ssh_option: Vec<String>,
    },
    /// Authenticated SSH parent that detaches one floor server.
    #[command(name = "__floor-bootstrap-v1", hide = true)]
    Bootstrap { request: String },
    /// Detached, one-connection authenticated DATAGRAM echo server.
    #[command(name = "__floor-server-v1", hide = true)]
    Server {
        #[arg(long = "bind-ip")]
        bind_ip: IpAddr,
        #[arg(long)]
        request: String,
    },
}

struct PacketPool {
    free: VecDeque<BytesMut>,
    retired: Vec<Bytes>,
}

struct InlineReceipt {
    delivered_base: AtomicU64,
    expected_sequence: AtomicU64,
    expected_byte: AtomicU8,
    failed: AtomicBool,
    ready: Notify,
}

impl InlineReceipt {
    fn new() -> Self {
        Self {
            delivered_base: AtomicU64::new(0),
            expected_sequence: AtomicU64::new(0),
            expected_byte: AtomicU8::new(0),
            failed: AtomicBool::new(false),
            ready: Notify::new(),
        }
    }

    fn expect(&self, sequence: u64, byte: u8) {
        self.expected_byte.store(byte, Ordering::Relaxed);
        self.expected_sequence.store(sequence, Ordering::Release);
    }

    fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        self.ready.notify_one();
    }
}

impl PacketPool {
    fn new() -> Self {
        let mut free = VecDeque::with_capacity(PACKET_POOL_SIZE);
        for _ in 0..PACKET_POOL_SIZE {
            let mut packet = BytesMut::with_capacity(MAX_WIRE_LEN);
            packet.resize(MAX_WIRE_LEN, 0);
            free.push_back(packet);
        }
        Self {
            free,
            retired: Vec::with_capacity(PACKET_POOL_SIZE),
        }
    }

    fn take(&mut self) -> FloorResult<BytesMut> {
        self.reclaim();
        self.free.pop_front().ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "DATAGRAM packet pool exhausted").into()
        })
    }

    fn retire(&mut self, packet: Bytes) {
        match packet.try_into_mut() {
            Ok(mut packet) => {
                packet.resize(MAX_WIRE_LEN, 0);
                self.free.push_back(packet);
            }
            Err(packet) => self.retired.push(packet),
        }
    }

    fn reclaim(&mut self) {
        let mut index = 0;
        while index < self.retired.len() {
            if self.retired[index].is_unique() {
                let packet = self.retired.swap_remove(index);
                match packet.try_into_mut() {
                    Ok(mut packet) => {
                        packet.resize(MAX_WIRE_LEN, 0);
                        self.free.push_back(packet);
                    }
                    Err(packet) => self.retired.push(packet),
                }
            } else {
                index += 1;
            }
        }
    }
}

fn initial_position() -> ResumePosition {
    ResumePosition {
        input_epoch: 0,
        next_input: 0,
        output_epoch: 0,
        next_output: 0,
        delivered_output_ack: 0,
    }
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn flush_now(connection: &Connection) -> FloorResult<()> {
    poll_fn(|context| Poll::Ready(connection.flush_transmit_now(context))).await?;
    Ok(())
}

async fn send_retained(connection: &Connection, packet: &Bytes) -> FloorResult<()> {
    loop {
        if connection.datagram_send_buffer_space() >= packet.len() {
            connection.send_datagram(packet.clone())?;
            flush_now(connection).await?;
            return Ok(());
        }
        trace(TraceStage::BufferBlocked, None);
        sleep(Duration::from_micros(50)).await;
    }
}

fn encode_packet(
    pool: &mut PacketPool,
    direction: Direction,
    sequence: u64,
    acknowledgement: AckState,
    payload: &[u8],
) -> FloorResult<Bytes> {
    let mut packet = pool.take()?;
    let kind = match direction {
        Direction::ClientToGateway => everudp::wire::Kind::Input,
        Direction::GatewayToClient => everudp::wire::Kind::Output,
    };
    let used = encode_data(
        Data {
            direction,
            kind,
            epoch: 1,
            sequence,
            acknowledgement,
            payload,
        },
        &mut packet,
    )?;
    packet.truncate(used);
    Ok(packet.freeze())
}

async fn await_echo(
    connection: &Connection,
    sequence: u64,
    packet: &Bytes,
    receipt: &InlineReceipt,
) -> FloorResult<()> {
    trace(TraceStage::ProtocolOffer, Some(sequence));
    send_retained(connection, packet).await?;
    let mut deadline = Instant::now() + RETRANSMIT_DELAY;
    loop {
        if receipt.failed.load(Ordering::Acquire) {
            return Err(protocol_error("floor inline output rejected a response").into());
        }
        let delivered_base = receipt.delivered_base.load(Ordering::Acquire);
        if delivered_base == sequence + 1 {
            return Ok(());
        }
        if delivered_base > sequence + 1 {
            return Err(protocol_error("floor inline output advanced too far").into());
        }
        tokio::select! {
            biased;
            () = receipt.ready.notified() => {}
            () = sleep_until(deadline) => {
                trace(TraceStage::Retry, Some(sequence));
                send_retained(connection, packet).await?;
                deadline = Instant::now() + RETRANSMIT_DELAY;
            }
        }
    }
}

fn install_inline_output(
    connection: &Connection,
    output: std::os::fd::BorrowedFd<'_>,
    receipt: Arc<InlineReceipt>,
    limits: Limits,
) -> FloorResult<()> {
    let output = everpty::sys::duplicate_cloexec(output)?;
    connection.set_inline_datagram_handler(move |incoming| {
        trace(TraceStage::CallbackEnter, None);
        let accepted = (|| {
            let Frame::Data(data) = decode(Direction::GatewayToClient, &incoming, &limits).ok()?
            else {
                return None;
            };
            trace(TraceStage::WireDecoded, Some(data.sequence));
            let delivered_base = receipt.delivered_base.load(Ordering::Acquire);
            if data.sequence < delivered_base {
                return Some(());
            }
            let expected_sequence = receipt.expected_sequence.load(Ordering::Acquire);
            let expected_byte = receipt.expected_byte.load(Ordering::Relaxed);
            if data.epoch != 1
                || data.kind != everudp::wire::Kind::Output
                || data.sequence != delivered_base
                || data.sequence != expected_sequence
                || data.payload != [expected_byte]
                || data.acknowledgement
                    != (AckState {
                        epoch: 1,
                        base: data.sequence.checked_add(1)?,
                        bits: 0,
                    })
            {
                return None;
            }
            let mut payload = data.payload;
            while !payload.is_empty() {
                match everpty::sys::write_fd(output.as_fd(), payload) {
                    Ok(0) => return None,
                    Ok(written) => payload = &payload[written..],
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return None,
                }
            }
            trace(TraceStage::SinkAccepted, Some(data.sequence));
            #[cfg(feature = "floor-diagnostics")]
            if data.sequence == 0 {
                if let Some(recorder) = TRACE.get() {
                    recorder.start_resources();
                }
            }
            receipt
                .delivered_base
                .store(data.sequence.checked_add(1)?, Ordering::Release);
            receipt.ready.notify_one();
            Some(())
        })();
        if accepted.is_none() {
            receipt.fail();
        }
        trace(TraceStage::CallbackExit, None);
        None
    });
    Ok(())
}

async fn run_client(
    destination: String,
    session: String,
    remote_program: String,
    ssh_options: Vec<String>,
) -> FloorResult<()> {
    let limits = Limits::default();
    let identity = ClientIdentity::generate()?;
    let association_id = AssociationId::generate()?;
    let request = BootstrapRequest::new(
        BootstrapOperation::Connect,
        session,
        ConnectionRole::Writer,
        false,
        24,
        80,
        association_id,
        identity.spki_sha256(),
        "floor".to_owned(),
        vec![b"floor".to_vec()],
    )?;
    let request_token = request.encode_token()?;
    let plan = SshPlan::using_config(destination, ssh_options)?.with_remote_role_invocation(
        vec![remote_program],
        FLOOR_BOOTSTRAP_ROLE,
        &[request_token],
    )?;
    let ssh_limits = everssh::Limits::default();
    verify_effective_config(&plan, &ssh_limits).await?;
    let wire = acquire_bootstrap_bytes(&plan, limits.bootstrap_record_max, &ssh_limits).await?;
    if wire.overflowed() {
        return Err(protocol_error("floor bootstrap record overflowed").into());
    }
    let line = std::str::from_utf8(wire.as_slice())?;
    let record = BootstrapRecord::parse_line(line, &limits)?;
    if record.association_id() != association_id {
        return Err(protocol_error("floor bootstrap association mismatch").into());
    }

    #[cfg(feature = "floor-single-owner")]
    if cfg!(feature = "floor-single-owner") {
        let hello = ClientHello::initial(
            association_id,
            record.generation(),
            ConnectionRole::Writer,
            initial_position(),
            record.token().clone(),
        )?;
        return floor_single_owner::run_client(record, identity, hello);
    }

    let endpoint = ClientEndpoint::bind_routed_datagram_floor(
        record.endpoint(),
        UdpBindPolicy::RouteSelected,
        &identity,
        record.server_spki_sha256(),
        limits,
    )?;
    let hello = ClientHello::initial(
        association_id,
        record.generation(),
        ConnectionRole::Writer,
        initial_position(),
        record.token().clone(),
    )?;
    let session = endpoint.connect_initial(record.endpoint(), &hello).await?;
    let (connection, mut control_send, mut control_recv) = session.into_parts();
    control_send.write_all(&CLIENT_CAPABILITY).await?;
    control_send.flush().await?;
    let mut capability = [0_u8; SERVER_CAPABILITY.len()];
    control_recv.read_exact(&mut capability).await?;
    if capability != SERVER_CAPABILITY {
        return Err(protocol_error("floor server rejected v4 capability").into());
    }
    trace(TraceStage::BootstrapComplete, None);
    if TRACE.get().is_some() {
        tokio::time::timeout(Duration::from_secs(5), async {
            control_send.write_all(&[TRACE_ENABLE]).await?;
            let mut ack = [0_u8; 1];
            control_recv.read_exact(&mut ack).await?;
            if ack != [TRACE_ENABLE] {
                return Err(protocol_error("server trace enable rejected").into());
            }
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
        .await??;
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut terminal = TerminalEdge::stage(stdin.as_fd(), stdout.as_fd(), stderr.as_fd())?;
    let mut pool = PacketPool::new();
    terminal.activate(ConnectionRole::Writer)?;
    terminal.enable_async_io()?;
    let receipt = Arc::new(InlineReceipt::new());
    install_inline_output(&connection, stdout.as_fd(), Arc::clone(&receipt), limits)?;
    let mut input = [0_u8; everudp::reliable_datagram::MAX_PAYLOAD_LEN];
    let mut sequence = 0_u64;
    loop {
        match terminal.next_local_event(&mut input, true).await? {
            LocalEvent::Stdin { bytes } => {
                trace(TraceStage::TerminalRead, Some(sequence));
                if bytes != 1 {
                    return Err(protocol_error("floor benchmark requires one-byte input").into());
                }
                receipt.expect(sequence, input[0]);
                let packet = encode_packet(
                    &mut pool,
                    Direction::ClientToGateway,
                    sequence,
                    AckState {
                        epoch: 1,
                        base: sequence,
                        bits: 0,
                    },
                    &input[..bytes],
                )?;
                trace(TraceStage::WireEncoded, Some(sequence));
                await_echo(&connection, sequence, &packet, &receipt).await?;
                pool.retire(packet);
                sequence = sequence
                    .checked_add(1)
                    .ok_or_else(|| protocol_error("floor sequence overflow"))?;
            }
            LocalEvent::StdinClosed | LocalEvent::Signal(TerminalEvent::Cancel(_)) => {
                if TRACE.get().is_some() {
                    export_server_trace(&mut control_send, &mut control_recv).await?;
                }
                return Ok(());
            }
            LocalEvent::Signal(
                TerminalEvent::Resize(_) | TerminalEvent::Suspended | TerminalEvent::Continued,
            ) => {}
        }
    }
}

async fn run_server(
    bind_ip: IpAddr,
    request: BootstrapRequest,
    mut output: std::fs::File,
) -> FloorResult<()> {
    #[cfg(feature = "floor-single-owner")]
    if cfg!(feature = "floor-single-owner") {
        return floor_single_owner::run_server(bind_ip, request, output);
    }
    let limits = Limits::default();
    let generation = GatewayGeneration::generate()?;
    let invitations: SharedInvitationStore = Arc::new(Mutex::new(InvitationStore::new(
        request.session(),
        generation,
        &limits,
    )?));
    let identity = GatewayIdentity::generate()?;
    let endpoint = GatewayEndpoint::bind_datagram_floor(
        SocketAddr::new(bind_ip, 0),
        &identity,
        Arc::clone(&invitations),
        limits,
    )?;
    let now_ms = everpty::sys::clock_monotonic_ms()?;
    let ticket = invitations
        .lock()
        .map_err(|_| protocol_error("floor invitation store unavailable"))?
        .issue(
            request.association_id(),
            request.role(),
            request.client_spki_sha256(),
            now_ms,
        )?;
    let record = BootstrapRecord::new(
        endpoint.local_addr(),
        identity.spki_sha256(),
        ticket.token().clone(),
        request.association_id(),
        generation,
        std::process::id(),
    )?;
    output.write_all(record.encode().as_str().as_bytes())?;
    output.flush()?;
    drop(output);

    let admitted = endpoint.accept_initial().await?;
    let (connection, mut control_send, mut control_recv, hello) = admitted.into_parts();
    if hello.association_id() != request.association_id() || hello.role() != ConnectionRole::Writer
    {
        return Err(protocol_error("floor admitted wrong association").into());
    }
    let mut capability = [0_u8; CLIENT_CAPABILITY.len()];
    control_recv.read_exact(&mut capability).await?;
    if capability != CLIENT_CAPABILITY {
        return Err(protocol_error("floor client omitted v4 capability").into());
    }
    let mut pool = PacketPool::new();
    connection.set_inline_datagram_handler(move |incoming| {
        trace(TraceStage::CallbackEnter, None);
        let Frame::Data(data) = decode(Direction::ClientToGateway, &incoming, &limits).ok()? else {
            return None;
        };
        if data.epoch != 1
            || data.kind != everudp::wire::Kind::Input
            || data.acknowledgement
                != (AckState {
                    epoch: 1,
                    base: data.sequence,
                    bits: 0,
                })
        {
            return None;
        }
        trace(TraceStage::WireDecoded, Some(data.sequence));
        let packet = encode_packet(
            &mut pool,
            Direction::GatewayToClient,
            data.sequence,
            AckState {
                epoch: 1,
                base: data.sequence.checked_add(1)?,
                bits: 0,
            },
            data.payload,
        )
        .ok()?;
        // Keep a pool-owned reference until noQ releases the transmitted
        // bytes. Otherwise every echo permanently consumes one pool slot.
        pool.retire(packet.clone());
        trace(TraceStage::WireEncoded, Some(data.sequence));
        #[cfg(feature = "floor-diagnostics")]
        if data.sequence == 0 {
            if let Some(recorder) = TRACE.get() {
                recorder.start_resources();
            }
        }
        trace(TraceStage::CallbackExit, Some(data.sequence));
        Some(packet)
    });
    control_send.write_all(&SERVER_CAPABILITY).await?;
    control_send.flush().await?;
    let mut exported = false;
    loop {
        let mut opcode = [0_u8; 1];
        tokio::select! {
            _ = connection.closed() => return Ok(()),
            received = control_recv.read_exact(&mut opcode) => {
                match received {
                    Ok(()) => {}
                    // The optional diagnostic control stream may finish without
                    // another operation on an ordinary untraced client exit.
                    Err(noq::ReadExactError::FinishedEarly(0)) => return Ok(()),
                    Err(error) => return Err(error.into()),
                }
            }
        }
        match opcode[0] {
            TRACE_ENABLE if TRACE.get().is_none() => {
                TRACE
                    .set(Trace::new(SERVER_TRACE_EVENTS))
                    .map_err(|_| protocol_error("server trace already enabled"))?;
                trace(TraceStage::BootstrapComplete, None);
                enable_noq_diagnostics()?;
                control_send.write_all(&[TRACE_ENABLE]).await?;
            }
            TRACE_EXPORT if TRACE.get().is_some() && !exported => {
                exported = true;
                let mut bytes = BoundedTraceBytes(Vec::with_capacity(MAX_SERVER_TRACE_BYTES));
                TRACE
                    .get()
                    .expect("checked recorder")
                    .write_json(&mut bytes)?;
                tokio::time::timeout(Duration::from_secs(5), async {
                    control_send
                        .write_all(&(bytes.0.len() as u32).to_be_bytes())
                        .await?;
                    control_send.write_all(&bytes.0).await
                })
                .await??;
            }
            _ => return Err(protocol_error("invalid diagnostic control operation").into()),
        }
    }
}

async fn run_bootstrap_parent(request_token: String) -> FloorResult<()> {
    let request = BootstrapRequest::decode_token(&request_token)?;
    let ssh_connection = std::env::var("SSH_CONNECTION")?;
    let authenticated = parse_ssh_connection(&ssh_connection)?;
    let self_exe = std::env::current_exe()?;
    let mut command = TokioCommand::new(self_exe);
    command
        .arg(FLOOR_SERVER_ROLE)
        .arg("--bind-ip")
        .arg(authenticated.local().ip().to_string())
        .arg("--request")
        .arg(request_token)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(false);
    unsafe {
        command.pre_exec(|| everpty::sys::child_setsid().map_err(io::Error::from_raw_os_error));
    }
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| protocol_error("floor server has no bootstrap pipe"))?;
    let mut wire = Vec::with_capacity(512);
    let read = tokio::time::timeout(limits().initial_udp_budget(), async {
        stdout
            .take((limits().bootstrap_record_max + 1) as u64)
            .read_to_end(&mut wire)
            .await
    })
    .await;
    let result = match read {
        Ok(Ok(_)) if wire.len() <= limits().bootstrap_record_max => {
            let line = std::str::from_utf8(&wire)?;
            let record = BootstrapRecord::parse_line(line, &limits())?;
            if record.association_id() != request.association_id() {
                Err(protocol_error("floor child association mismatch").into())
            } else {
                let stdout = io::stdout();
                let mut stdout = stdout.lock();
                stdout.write_all(&wire)?;
                stdout.flush()?;
                Ok(())
            }
        }
        Ok(Ok(_)) => Err(protocol_error("floor child bootstrap overflowed").into()),
        Ok(Err(error)) => Err(error.into()),
        Err(error) => Err(error.into()),
    };
    if result.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result
}

fn limits() -> Limits {
    Limits::default()
}

fn main() -> ExitCode {
    let command = Cli::parse().command;
    if let FloorCommand::Client {
        partition_trace_json: Some(path),
        ..
    } = &command
    {
        #[cfg(feature = "floor-single-owner")]
        let _ = PARTITION_TRACE_PATH.set(path.clone());
        #[cfg(not(feature = "floor-single-owner"))]
        {
            let _ = path;
            eprintln!("everudp-floor: reactor partition tracing requires floor-single-owner");
            return ExitCode::from(3);
        }
    }
    if let FloorCommand::Client {
        reactor_trace_json: Some(path),
        ..
    } = &command
    {
        #[cfg(feature = "floor-single-owner")]
        let _ = REACTOR_TRACE_PATH.set(path.clone());
        #[cfg(not(feature = "floor-single-owner"))]
        {
            let _ = path;
            eprintln!("everudp-floor: reactor work tracing requires floor-single-owner");
            return ExitCode::from(3);
        }
    }
    if let FloorCommand::Client {
        native_trace_json: Some(path),
        ..
    } = &command
    {
        #[cfg(feature = "floor-single-owner")]
        let _ = NATIVE_TRACE_PATH.set(path.clone());
        #[cfg(not(feature = "floor-single-owner"))]
        {
            let _ = path;
            eprintln!("everudp-floor: native stage tracing requires floor-single-owner");
            return ExitCode::from(3);
        }
    }
    #[cfg(feature = "floor-single-owner")]
    if matches!(
        &command,
        FloorCommand::Client {
            trace_json: Some(_),
            ..
        }
    ) {
        eprintln!("everudp-floor: single-owner diagnostic tracing is not implemented");
        return ExitCode::from(3);
    }
    let trace_file = match &command {
        FloorCommand::Client {
            trace_json: Some(path),
            ..
        } => {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
            {
                Ok(file) => {
                    let mut server_path = path.as_os_str().to_os_string();
                    server_path.push(".server.json");
                    let server_file = match std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(server_path)
                    {
                        Ok(file) => file,
                        Err(error) => {
                            eprintln!(
                                "everudp-floor: cannot create server diagnostic file: {error}"
                            );
                            return ExitCode::from(3);
                        }
                    };
                    let _ = TRACE.set(Trace::new(65_536));
                    trace(TraceStage::BootstrapStart, None);
                    if let Err(error) = enable_noq_diagnostics() {
                        eprintln!("everudp-floor: {error}");
                        return ExitCode::from(3);
                    }
                    Some((file, server_file))
                }
                Err(error) => {
                    eprintln!("everudp-floor: cannot create diagnostic file: {error}");
                    return ExitCode::from(3);
                }
            }
        }
        _ => None,
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("everudp-floor: {error}");
            return ExitCode::from(3);
        }
    };
    let result = runtime.block_on(async move {
        match command {
            FloorCommand::Client {
                trace_json: _,
                native_trace_json: _,
                reactor_trace_json: _,
                partition_trace_json: _,
                destination,
                session,
                remote_program,
                ssh_option,
            } => run_client(destination, session, remote_program, ssh_option).await,
            FloorCommand::Bootstrap { request } => run_bootstrap_parent(request).await,
            FloorCommand::Server { bind_ip, request } => {
                let request = BootstrapRequest::decode_token(&request)?;
                // SAFETY: this detached role creates no `Stdout` handle; it
                // exclusively owns descriptor 1 so dropping the file signals
                // bootstrap EOF while the server remains alive.
                let output = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(1) });
                run_server(bind_ip, request, output).await
            }
        }
    });
    if let (Some((file, mut server_file)), Some(recorder)) = (trace_file, TRACE.get()) {
        let mut writer = std::io::BufWriter::new(file);
        let saved = (|| -> io::Result<()> {
            write!(
                writer,
                "{{\"diagnostic_only\":true,\"run_succeeded\":{},\"trace\":",
                result.is_ok()
            )?;
            recorder.write_json(&mut writer)?;
            writer.write_all(b"}\n")?;
            writer.flush()
        })();
        if saved.is_err() {
            eprintln!("everudp-floor: diagnostic output failed");
            return ExitCode::from(3);
        }
        let remote = SERVER_TRACE.get().map(Vec::as_slice).unwrap_or(
            b"{\"diagnostic_only\":true,\"valid\":false,\"reason\":\"server trace unavailable\"}\n",
        );
        if server_file
            .write_all(remote)
            .and_then(|()| server_file.flush())
            .is_err()
        {
            eprintln!("everudp-floor: server diagnostic output failed");
            return ExitCode::from(3);
        }
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("everudp-floor: {error}");
            ExitCode::from(3)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_trace_option_is_explicit_and_excludes_legacy_trace() {
        let args = [
            "everudp-floor",
            "client",
            "target",
            "--session",
            "test",
            "--remote-program",
            "/bin/example",
            "--native-trace-json",
            "/tmp/example-trace",
        ];
        assert!(Cli::try_parse_from(args).is_ok());
        assert!(Cli::try_parse_from(
            args.into_iter()
                .chain(["--trace-json", "/tmp/legacy-trace"])
        )
        .is_err());
    }

    #[test]
    fn reactor_trace_is_explicit_and_excludes_other_recorders() {
        let args = [
            "everudp-floor",
            "client",
            "target",
            "--session",
            "test",
            "--remote-program",
            "/bin/example",
            "--reactor-trace-json",
            "/tmp/reactor-trace",
        ];
        assert!(Cli::try_parse_from(args).is_ok());
        for flag in ["--trace-json", "--native-trace-json"] {
            assert!(
                Cli::try_parse_from(args.into_iter().chain([flag, "/tmp/other-trace"])).is_err()
            );
        }
    }

    #[test]
    fn partition_trace_is_explicit_and_excludes_other_recorders() {
        let args = [
            "everudp-floor",
            "client",
            "target",
            "--session",
            "test",
            "--remote-program",
            "/bin/example",
            "--partition-trace-json",
            "/tmp/partitions",
        ];
        assert!(Cli::try_parse_from(args).is_ok());
        for flag in [
            "--trace-json",
            "--native-trace-json",
            "--reactor-trace-json",
        ] {
            assert!(Cli::try_parse_from(args.into_iter().chain([flag, "/tmp/other"])).is_err());
        }
    }

    #[test]
    fn server_export_writer_rejects_bytes_above_its_cap() {
        let mut writer = BoundedTraceBytes(vec![0; MAX_SERVER_TRACE_BYTES - 1]);
        writer.write_all(b"x").expect("last byte fits");
        assert!(writer.write_all(b"y").is_err());
        assert_eq!(writer.0.len(), MAX_SERVER_TRACE_BYTES);
    }

    #[test]
    fn transmitted_packets_are_reclaimed_beyond_pool_capacity() {
        let mut pool = PacketPool::new();
        for sequence in 0..(PACKET_POOL_SIZE as u64 * 4) {
            let packet = encode_packet(
                &mut pool,
                Direction::GatewayToClient,
                sequence,
                AckState {
                    epoch: 1,
                    base: sequence + 1,
                    bits: 0,
                },
                b"x",
            )
            .expect("reusable packet");
            pool.retire(packet.clone());
            drop(packet);
        }
        pool.reclaim();
        assert_eq!(pool.free.len(), PACKET_POOL_SIZE);
        assert!(pool.retired.is_empty());
    }
}
