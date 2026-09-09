//! Continuous local-terminal driver for one authenticated client link.

use crate::client::{ClientError, OutputOperation};
use crate::client_link::{
    ClientControlReceipt, ClientInboundReceipt, ClientLink, ClientLinkError,
    ClientOutputStageReceipt,
};
use crate::status::{LinkState, StatusFile, TerminalCause};
use crate::terminal::{LocalEvent, TerminalEdge, TerminalError, TerminalEvent, TerminalWriteEvent};
use crate::wire::{ConnectionRole, Resize};
use crate::{Limits, QueueError};
use std::fmt;
use std::future::{poll_fn, Future};
use std::task::Poll;

const OWNERSHIP_GRANTED: u8 = 1;
const OWNERSHIP_REVOKED: u8 = 2;

#[cfg(test)]
#[path = "client_driver_backpressure_tests.rs"]
mod backpressure_tests;

#[derive(Debug)]
pub enum ClientDriverError {
    Link(ClientLinkError),
    Client(ClientError),
    Terminal(TerminalError),
    InvalidOwnership(u8),
}

impl fmt::Display for ClientDriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Link(error) => write!(formatter, "{error}"),
            Self::Client(error) => write!(formatter, "{error}"),
            Self::Terminal(error) => write!(formatter, "{error}"),
            Self::InvalidOwnership(_) => {
                formatter.write_str("invalid everudp ownership transition")
            }
        }
    }
}

impl std::error::Error for ClientDriverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Link(error) => Some(error),
            Self::Client(error) => Some(error),
            Self::Terminal(error) => Some(error),
            Self::InvalidOwnership(_) => None,
        }
    }
}

impl From<ClientLinkError> for ClientDriverError {
    fn from(value: ClientLinkError) -> Self {
        Self::Link(value)
    }
}

impl From<ClientError> for ClientDriverError {
    fn from(value: ClientError) -> Self {
        Self::Client(value)
    }
}

impl From<TerminalError> for ClientDriverError {
    fn from(value: TerminalError) -> Self {
        Self::Terminal(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRunOutcome {
    NetworkLost,
    LocalCancelled { signal: i32 },
    OwnershipRevoked,
    PtyExited(i32),
    PeerClosed,
}

/// Owns terminal restoration and status reporting across one or more links.
/// Reconnect code retains this driver while replacing only `ClientLink`.
pub struct ClientDriver<'fd> {
    terminal: TerminalEdge<'fd>,
    status: Option<StatusFile>,
    stdin_buffer: Box<[u8]>,
    output_buffer: Box<[u8]>,
    delivery_timeout: std::time::Duration,
    carried: bool,
    role: ConnectionRole,
    pending_resize: Option<Resize>,
}

impl<'fd> ClientDriver<'fd> {
    pub fn activate(
        terminal: TerminalEdge<'fd>,
        authenticated: &ClientLink,
        limits: Limits,
        status: Option<StatusFile>,
    ) -> Result<Self, ClientDriverError> {
        Self::activate_authenticated(terminal, authenticated.association().role(), limits, status)
    }

    fn activate_authenticated(
        mut terminal: TerminalEdge<'fd>,
        role: ConnectionRole,
        limits: Limits,
        mut status: Option<StatusFile>,
    ) -> Result<Self, ClientDriverError> {
        limits
            .validate()
            .map_err(crate::WireError::from)
            .map_err(ClientError::from)?;
        terminal.activate(role)?;
        terminal.enable_async_io()?;
        if let Some(status) = status.as_mut() {
            let _ = status.transition(LinkState::Connected, monotonic_ms());
        }
        Ok(Self {
            terminal,
            status,
            stdin_buffer: fixed_buffer(limits.copy_buffer_bytes)?,
            output_buffer: fixed_buffer(limits.copy_buffer_bytes)?,
            delivery_timeout: limits.initial_udp_budget(),
            carried: false,
            role,
            pending_resize: None,
        })
    }

    pub fn terminal(&self) -> &TerminalEdge<'fd> {
        &self.terminal
    }

    pub fn carried(&self) -> bool {
        self.carried
    }

    pub async fn run_link(
        &mut self,
        link: &mut ClientLink,
    ) -> Result<ClientRunOutcome, ClientDriverError> {
        let result = self.run_link_inner(link).await;
        self.settle_run_result(result, link.association().ambiguous_input_operations())
    }

    async fn run_link_inner(
        &mut self,
        link: &mut ClientLink,
    ) -> Result<ClientRunOutcome, ClientDriverError> {
        loop {
            flush_pending_resize(&mut self.pending_resize, link.association_mut())?;
            self.emit_pending_gap(link.association_mut()).await?;
            if link.association().has_pending_output() {
                if let Some(outcome) = self.drain_pending_output(link).await? {
                    return Ok(outcome);
                }
                continue;
            }

            let capacity = link
                .association()
                .stdin_read_capacity()
                .min(self.stdin_buffer.len());
            let poll_stdin = self.role == ConnectionRole::Writer
                && self.pending_resize.is_none()
                && capacity > 0;
            let local_buffer = if poll_stdin {
                &mut self.stdin_buffer[..capacity]
            } else {
                &mut self.stdin_buffer[..0]
            };
            enum Ready {
                Link(Result<Option<ClientInboundReceipt>, ClientLinkError>),
                Local(Result<LocalEvent, TerminalError>),
            }
            let ready = tokio::select! {
                // Fair selection prevents continuous stream progress from
                // starving local signals, or a paste from starving the link.
                event = next_link_ready(link) => Ready::Link(event),
                local = self.terminal.next_local_event(local_buffer, poll_stdin) => Ready::Local(local),
            };
            match ready {
                Ready::Link(Ok(Some(receipt))) => {
                    if let Some(outcome) = self.handle_inbound(receipt) {
                        return Ok(outcome);
                    }
                }
                Ready::Link(Ok(None)) => {}
                Ready::Link(Err(error)) => return self.classify_link_error(error, link),
                Ready::Local(Ok(event)) => {
                    if let Some(outcome) = self.handle_local(event, link)? {
                        if matches!(outcome, ClientRunOutcome::LocalCancelled { .. }) {
                            // Distinguish an explicit local detach from a
                            // resumable transport death. Delivery is bounded
                            // and best-effort because cancellation itself
                            // must never wait indefinitely on the network.
                            let _ = link.finish_detach_delivery(self.delivery_timeout).await;
                        }
                        return Ok(outcome);
                    }
                }
                Ready::Local(Err(error)) => return Err(error.into()),
            }
        }
    }

    pub fn mark_disconnected(&mut self, ambiguous_input: usize) {
        if let Some(status) = self.status.as_mut() {
            let _ = status.transition(LinkState::Disconnected { ambiguous_input }, monotonic_ms());
        }
    }

    pub fn mark_migrating(&mut self) {
        if let Some(status) = self.status.as_mut() {
            let _ = status.transition(LinkState::Migrating, monotonic_ms());
        }
    }

    pub fn mark_reconnecting(&mut self, ambiguous_input: usize) {
        if let Some(status) = self.status.as_mut() {
            let _ = status.transition(LinkState::Reconnecting { ambiguous_input }, monotonic_ms());
        }
    }

    pub fn mark_recovering_over_ssh(&mut self, ambiguous_input: usize) {
        if let Some(status) = self.status.as_mut() {
            let _ = status.transition(
                LinkState::RecoveringOverSsh { ambiguous_input },
                monotonic_ms(),
            );
        }
    }

    pub fn mark_connected(&mut self) {
        if let Some(status) = self.status.as_mut() {
            let _ = status.transition(LinkState::Connected, monotonic_ms());
        }
    }

    pub async fn report_gateway_replacement(
        &mut self,
        ambiguous_input: usize,
    ) -> Result<(), ClientDriverError> {
        let line = format!(
            "everudp: gateway restarted; {ambiguous_input} unacknowledged input operation(s) were not replayed\n"
        );
        self.terminal
            .write_stderr_all_async(line.as_bytes())
            .await?;
        Ok(())
    }

    pub fn disconnected_heartbeat(&mut self) {
        if let Some(status) = self.status.as_mut() {
            let _ = status.heartbeat(monotonic_ms());
        }
    }

    /// Keeps signalfd live while no QUIC link exists. Stdin remains
    /// backpressured; resize is remembered for the first ordered input turn
    /// after resume, while cancellation is returned immediately.
    pub async fn next_disconnected_terminal_event(
        &mut self,
    ) -> Result<Option<i32>, ClientDriverError> {
        let mut no_stdin = [];
        match self.terminal.next_local_event(&mut no_stdin, false).await? {
            LocalEvent::Signal(TerminalEvent::Resize(resize)) => {
                self.pending_resize = Some(resize);
                Ok(None)
            }
            LocalEvent::Signal(TerminalEvent::Cancel(signal)) => Ok(Some(signal.number())),
            LocalEvent::Signal(TerminalEvent::Suspended | TerminalEvent::Continued) => Ok(None),
            LocalEvent::Stdin { .. } | LocalEvent::StdinClosed => Ok(None),
        }
    }

    pub fn deactivate_with_status(
        &mut self,
        cause: TerminalCause,
        ambiguous_input: usize,
    ) -> Result<(), ClientDriverError> {
        self.terminal_status(cause, ambiguous_input);
        self.terminal.deactivate()?;
        Ok(())
    }

    pub fn terminal_status(&mut self, cause: TerminalCause, ambiguous_input: usize) {
        if let Some(status) = self.status.as_mut() {
            let _ = status.terminal(cause, self.carried, ambiguous_input);
        }
    }

    async fn emit_pending_gap(
        &mut self,
        association: &mut crate::ClientAssociation,
    ) -> Result<(), ClientDriverError> {
        if association.take_gap_notice().is_some() {
            if let Some(status) = self.status.as_mut() {
                let _ = status.transition(LinkState::Gapped, monotonic_ms());
            }
            self.terminal.write_gap_notice_async().await?;
        }
        Ok(())
    }

    fn settle_run_result(
        &mut self,
        result: Result<ClientRunOutcome, ClientDriverError>,
        ambiguous_input: usize,
    ) -> Result<ClientRunOutcome, ClientDriverError> {
        match result {
            Ok(outcome @ (ClientRunOutcome::NetworkLost | ClientRunOutcome::PeerClosed)) => {
                self.mark_disconnected(ambiguous_input);
                Ok(outcome)
            }
            Ok(outcome) => {
                self.terminal.deactivate()?;
                Ok(outcome)
            }
            Err(error) => {
                let cause = match &error {
                    ClientDriverError::Terminal(_) => TerminalCause::Transport,
                    ClientDriverError::Link(_)
                    | ClientDriverError::Client(_)
                    | ClientDriverError::InvalidOwnership(_) => TerminalCause::Protocol,
                };
                self.terminal_status(cause, ambiguous_input);
                match self.terminal.deactivate() {
                    Ok(()) => Err(error),
                    Err(restore) => Err(restore.into()),
                }
            }
        }
    }

    fn handle_inbound(&self, receipt: ClientInboundReceipt) -> Option<ClientRunOutcome> {
        match receipt {
            ClientInboundReceipt::Control(ClientControlReceipt::Finished)
            | ClientInboundReceipt::Output(ClientOutputStageReceipt::Finished) => {
                Some(ClientRunOutcome::PeerClosed)
            }
            ClientInboundReceipt::Control(_)
            | ClientInboundReceipt::OutputStreamOpened
            | ClientInboundReceipt::Output(_)
            | ClientInboundReceipt::OutputPending => None,
        }
    }

    fn handle_local(
        &mut self,
        event: LocalEvent,
        link: &mut ClientLink,
    ) -> Result<Option<ClientRunOutcome>, ClientDriverError> {
        match event {
            LocalEvent::Stdin { bytes } => {
                #[cfg(feature = "path-io-diagnostics")]
                crate::io_trace::record_terminal(crate::io_trace::TerminalStage::Dispatch);
                link.association_mut()
                    .queue_input(&self.stdin_buffer[..bytes])?;
                Ok(None)
            }
            LocalEvent::StdinClosed => {
                link.association_mut().queue_input_close()?;
                Ok(None)
            }
            LocalEvent::Signal(event) => self.handle_terminal_event(event, link),
        }
    }

    fn handle_terminal_event(
        &mut self,
        event: TerminalEvent,
        link: &mut ClientLink,
    ) -> Result<Option<ClientRunOutcome>, ClientDriverError> {
        match event {
            TerminalEvent::Resize(resize) => {
                queue_or_defer_resize(&mut self.pending_resize, link.association_mut(), resize)?;
                Ok(None)
            }
            TerminalEvent::Cancel(signal) => Ok(Some(ClientRunOutcome::LocalCancelled {
                signal: signal.number(),
            })),
            TerminalEvent::Suspended | TerminalEvent::Continued => Ok(None),
        }
    }

    async fn drain_pending_output(
        &mut self,
        link: &mut ClientLink,
    ) -> Result<Option<ClientRunOutcome>, ClientDriverError> {
        loop {
            let view = link.association().pending_output()?;
            match view.operation {
                OutputOperation::Bytes(bytes) => {
                    let count = bytes.len().min(self.output_buffer.len());
                    self.output_buffer[..count].copy_from_slice(&bytes[..count]);
                    enum Ready {
                        Control(Result<ClientControlReceipt, ClientLinkError>),
                        Terminal(Result<TerminalWriteEvent, TerminalError>),
                    }
                    let ready = tokio::select! {
                        biased;
                        control = link.receive_control() => Ready::Control(control),
                        terminal = self.terminal.write_stdout_or_signal(&self.output_buffer[..count]) => Ready::Terminal(terminal),
                    };
                    match ready {
                        Ready::Control(Ok(ClientControlReceipt::Finished)) => {
                            return Ok(Some(ClientRunOutcome::NetworkLost));
                        }
                        Ready::Control(Ok(_)) => {
                            // GAP is carried on the independent control
                            // stream.  Applying it abandons and scrubs any
                            // old-epoch output that was staged while stdout
                            // was backpressured.  Return to the outer loop so
                            // it can emit the one gap notice and wait for
                            // replacement-epoch output; asking for the
                            // cleared staging slot would turn a valid GAP
                            // into a terminal OutputNotStaged error.
                            if !link.association().has_pending_output() {
                                return Ok(None);
                            }
                        }
                        Ready::Control(Err(error)) => {
                            return self.classify_link_error(error, link).map(Some);
                        }
                        Ready::Terminal(Ok(TerminalWriteEvent::Written { bytes })) => {
                            let complete = link.association_mut().advance_stdout(bytes)?;
                            if complete {
                                link.association_mut().finish_staged_output()?;
                                self.mark_carrying();
                                return Ok(None);
                            }
                        }
                        Ready::Terminal(Ok(TerminalWriteEvent::Signal(event))) => {
                            if let Some(outcome) = self.handle_terminal_event(event, link)? {
                                return Ok(Some(outcome));
                            }
                        }
                        Ready::Terminal(Err(error)) => return Err(error.into()),
                    }
                }
                OutputOperation::Ownership(OWNERSHIP_GRANTED) => {
                    link.association_mut().finish_staged_output()?;
                    return Ok(None);
                }
                OutputOperation::Ownership(OWNERSHIP_REVOKED) => {
                    link.association_mut().finish_staged_output()?;
                    link.finish_control_delivery(self.delivery_timeout).await?;
                    return Ok(Some(ClientRunOutcome::OwnershipRevoked));
                }
                OutputOperation::Ownership(other) => {
                    return Err(ClientDriverError::InvalidOwnership(other));
                }
                OutputOperation::Exit(status) => {
                    crate::exit_trace::record("client-stage-exit");
                    link.association_mut().finish_staged_output()?;
                    if let Err(error) = link.finish_control_delivery(self.delivery_timeout).await {
                        crate::exit_trace::record("client-final-delivery-error");
                        return Err(error.into());
                    }
                    crate::exit_trace::record("client-exit-complete");
                    return Ok(Some(ClientRunOutcome::PtyExited(status)));
                }
            }
        }
    }

    fn mark_carrying(&mut self) {
        self.carried = true;
        if let Some(status) = self.status.as_mut() {
            let _ = status.transition(LinkState::Carrying, monotonic_ms());
        }
    }

    fn classify_link_error(
        &mut self,
        error: ClientLinkError,
        link: &ClientLink,
    ) -> Result<ClientRunOutcome, ClientDriverError> {
        if error.is_transient() {
            self.mark_disconnected(link.association().ambiguous_input_operations());
            Ok(ClientRunOutcome::NetworkLost)
        } else {
            Err(error.into())
        }
    }
}

/// Polls each direction without awaiting a flow-controlled write. The read
/// future is cancellation-safe because its incremental reader lives in link.
async fn next_link_ready(
    link: &mut ClientLink,
) -> Result<Option<ClientInboundReceipt>, ClientLinkError> {
    poll_fn(|context| {
        let progress = match link.poll_outbound(context) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(progress)) => progress,
            Poll::Pending => false,
        };
        let inbound = {
            let mut future = std::pin::pin!(link.next_inbound());
            Future::poll(future.as_mut(), context)
        };
        match inbound {
            Poll::Ready(result) => Poll::Ready(result.map(Some)),
            Poll::Pending if progress => Poll::Ready(Ok(None)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

impl fmt::Debug for ClientDriver<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientDriver")
            .field("role", &self.role)
            .field("carried", &self.carried)
            .field("pending_resize", &self.pending_resize.is_some())
            .field("status", &self.status.is_some())
            .field("payload", &"<REDACTED>")
            .finish()
    }
}

fn fixed_buffer(length: usize) -> Result<Box<[u8]>, ClientDriverError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ClientError::Queue(QueueError::Allocation))?;
    bytes.resize(length, 0);
    Ok(bytes.into_boxed_slice())
}

fn queue_or_defer_resize(
    pending: &mut Option<Resize>,
    association: &mut crate::ClientAssociation,
    resize: Resize,
) -> Result<(), ClientError> {
    if pending.is_some() {
        *pending = Some(resize);
        return Ok(());
    }
    match association.queue_resize(resize) {
        Ok(_) => Ok(()),
        Err(ClientError::Queue(QueueError::Full)) => {
            *pending = Some(resize);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn flush_pending_resize(
    pending: &mut Option<Resize>,
    association: &mut crate::ClientAssociation,
) -> Result<(), ClientError> {
    let Some(resize) = *pending else {
        return Ok(());
    };
    match association.queue_resize(resize) {
        Ok(_) => {
            *pending = None;
            Ok(())
        }
        Err(ClientError::Queue(QueueError::Full)) => Ok(()),
        Err(error) => Err(error),
    }
}

fn monotonic_ms() -> u64 {
    everpty::sys::clock_monotonic_ms().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        flush_pending_resize, queue_or_defer_resize, ClientDriver, ClientDriverError,
        ClientRunOutcome,
    };
    use crate::handshake::ServerHello;
    use crate::status::TerminalCause;
    use crate::terminal::{TerminalEdge, GAP_NOTICE};
    use crate::wire::{decode_record, Ack, ConnectionRole, EpochGap, Kind, Resize, StreamRole};
    use crate::{ClientAssociation, GatewayGeneration, Limits};
    use everpty::sys;
    use everssh::association::AssociationId;
    use std::io::Read;
    use std::os::fd::AsFd;

    #[test]
    fn full_input_queue_defers_resize_then_preserves_its_order() {
        let limits = Limits::default();
        let association_id = AssociationId::from_bytes([31; 16]).expect("association");
        let generation = GatewayGeneration::from_bytes([32; 16]).expect("generation");
        let mut association =
            ClientAssociation::new(association_id, generation, ConnectionRole::Writer, limits)
                .expect("client association");
        association
            .apply_server_hello(
                ServerHello::new(
                    association_id,
                    generation,
                    ConnectionRole::Writer,
                    0,
                    0,
                    0,
                    0,
                    None,
                )
                .expect("server hello"),
            )
            .expect("apply hello");
        for _ in 0..limits.queue_operations_per_direction {
            association.queue_input(b"x").expect("fill input queue");
        }

        let resize = Resize {
            rows: 47,
            columns: 131,
            pixel_width: 0,
            pixel_height: 0,
        };
        let mut pending = None;
        queue_or_defer_resize(&mut pending, &mut association, resize).expect("defer resize");
        assert_eq!(pending, Some(resize));
        assert_eq!(
            association.ambiguous_input_operations(),
            limits.queue_operations_per_direction
        );

        association
            .accept_input_ack(Ack {
                epoch: 0,
                next_expected: 1,
            })
            .expect("free one queue slot");
        flush_pending_resize(&mut pending, &mut association).expect("queue deferred resize");
        assert_eq!(pending, None);

        let mut wire = vec![0_u8; limits.terminal_frame_max + crate::wire::HEADER_LEN];
        let copied = association
            .copy_input(limits.queue_operations_per_direction as u64, &mut wire)
            .expect("copy resize");
        let (record, consumed) =
            decode_record(StreamRole::Input, &wire[..copied.wire_len], &limits)
                .expect("decode resize");
        assert_eq!(consumed, copied.wire_len);
        assert_eq!(record.header.kind, Kind::Resize);
        assert_eq!(record.payload, resize.encode());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_outcome_and_protocol_failure_restore_local_state() {
        for result in [
            Ok(ClientRunOutcome::LocalCancelled {
                signal: sys::AttachSignal::Terminate.number(),
            }),
            Err(ClientDriverError::InvalidOwnership(99)),
        ] {
            let (_master, slave) = sys::openpty(31, 97).expect("pty");
            let before_termios = sys::terminal_attributes(slave.as_fd()).expect("termios");
            let before_mask = sys::current_signal_mask().expect("signal mask");
            let terminal =
                TerminalEdge::stage(slave.as_fd(), slave.as_fd(), slave.as_fd()).expect("stage");
            let mut driver = ClientDriver::activate_authenticated(
                terminal,
                ConnectionRole::Writer,
                Limits::default(),
                None,
            )
            .expect("activate");
            assert!(
                sys::terminal_attributes(slave.as_fd()).expect("raw termios") != before_termios
            );

            let settled = driver.settle_run_result(result, 0);
            assert!(matches!(
                settled,
                Ok(ClientRunOutcome::LocalCancelled { .. })
                    | Err(ClientDriverError::InvalidOwnership(99))
            ));
            assert!(
                sys::terminal_attributes(slave.as_fd()).expect("restored termios")
                    == before_termios
            );
            assert_eq!(
                sys::current_signal_mask().expect("restored signal mask"),
                before_mask
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn disconnected_driver_consumes_local_cancellation_and_restores_signal_mask() {
        let (stdin_read, _stdin_write) = sys::pipe_cloexec().expect("stdin");
        let (_stdout_read, stdout_write) = sys::pipe_cloexec().expect("stdout");
        let (_stderr_read, stderr_write) = sys::pipe_cloexec().expect("stderr");
        let before_mask = sys::current_signal_mask().expect("signal mask");
        let terminal = TerminalEdge::stage(
            stdin_read.as_fd(),
            stdout_write.as_fd(),
            stderr_write.as_fd(),
        )
        .expect("stage");
        let mut driver = ClientDriver::activate_authenticated(
            terminal,
            ConnectionRole::Writer,
            Limits::default(),
            None,
        )
        .expect("activate");
        let terminate = sys::AttachSignal::Terminate.number();
        sys::signal_thread(sys::current_thread_id(), terminate).expect("queue SIGTERM");
        let signal = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            driver.next_disconnected_terminal_event(),
        )
        .await
        .expect("signal deadline")
        .expect("terminal event");
        assert_eq!(signal, Some(terminate));
        driver
            .deactivate_with_status(TerminalCause::LocalCancel, 0)
            .expect("deactivate");
        assert_eq!(
            sys::current_signal_mask().expect("restored mask"),
            before_mask
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pending_gap_is_written_to_stderr_exactly_once() {
        let limits = Limits::default();
        let association_id = AssociationId::from_bytes([41; 16]).expect("association");
        let generation = GatewayGeneration::from_bytes([42; 16]).expect("generation");
        let mut association =
            ClientAssociation::new(association_id, generation, ConnectionRole::Observer, limits)
                .expect("association");
        association
            .apply_server_hello(
                ServerHello::new(
                    association_id,
                    generation,
                    ConnectionRole::Observer,
                    0,
                    0,
                    0,
                    0,
                    None,
                )
                .expect("hello"),
            )
            .expect("apply hello");
        association
            .apply_gap(EpochGap::new(0, 1).expect("gap"))
            .expect("apply gap");

        let (_input_write, input) = sys::pipe_cloexec().expect("stdin pipe");
        let (_output_read, output) = sys::pipe_cloexec().expect("stdout pipe");
        let (error_read, error_write) = sys::pipe_cloexec().expect("stderr pipe");
        let terminal =
            TerminalEdge::stage(input.as_fd(), output.as_fd(), error_write.as_fd()).expect("stage");
        let mut driver =
            ClientDriver::activate_authenticated(terminal, ConnectionRole::Observer, limits, None)
                .expect("activate");
        driver
            .emit_pending_gap(&mut association)
            .await
            .expect("first notice");
        driver
            .emit_pending_gap(&mut association)
            .await
            .expect("duplicate notice");
        drop(driver);
        drop(error_write);

        let mut error = std::fs::File::from(error_read);
        let mut bytes = Vec::new();
        error.read_to_end(&mut bytes).expect("read notice");
        assert_eq!(bytes, GAP_NOTICE);
    }
}
