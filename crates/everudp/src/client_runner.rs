//! End-to-end client ownership: SSH bootstrap, direct QUIC, and reconnect.

use crate::bootstrap::{BootstrapError, BootstrapRecord};
use crate::client::{ClientAssociation, ClientError};
use crate::client_driver::{ClientDriver, ClientDriverError, ClientRunOutcome};
use crate::client_link::{ClientLink, ClientLinkError};
use crate::handshake::{ClientHello, HandshakeError, ResumePosition};
use crate::identity::{ClientIdentity, IdentityError};
use crate::reconnect::{
    reconnect_until, GatewayReplacement, ReconnectError, ReconnectEvent, ReconnectState,
    RecoveryAction, RecoveryFailure,
};
use crate::request::{BootstrapOperation, BootstrapRequest, RequestError};
use crate::route::{RouteError, RouteSupervisor};
use crate::status::{LinkState, StatusError, StatusFile, TerminalCause};
use crate::terminal::{TerminalEdge, TerminalError};
use crate::transport::{ClientEndpoint, InitialConnectError, TransportError};
use crate::wire::ConnectionRole;
use crate::{Limits, BOOTSTRAP_PARENT_ROLE};
use everssh::association::AssociationId;
use everssh::ssh_bootstrap::{acquire_bootstrap_bytes, verify_effective_config};
use everssh::ssh_policy::SshPlan;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

/// Strict-mode failure used by `eversh --transport auto` before raw mode,
/// terminal traffic, or everpty writer commitment.
pub const UDP_UNREACHABLE_EXIT: u8 = 69;

pub struct ClientConfig {
    pub destination: String,
    pub remote_role_words: Vec<String>,
    pub ssh_options: Vec<String>,
    pub operation: BootstrapOperation,
    pub session: String,
    pub take_over: bool,
    pub rows: u16,
    pub columns: u16,
    pub origin: String,
    pub command: Vec<Vec<u8>>,
    pub status_path: Option<PathBuf>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientConfig")
            .field("destination", &"<REDACTED>")
            .field("remote_role_words", &self.remote_role_words)
            .field("ssh_option_count", &self.ssh_options.len())
            .field("operation", &self.operation)
            .field("session", &self.session)
            .field("take_over", &self.take_over)
            .field("rows", &self.rows)
            .field("columns", &self.columns)
            .field("origin", &self.origin)
            .field("command_arguments", &self.command.len())
            .field("status_path", &self.status_path)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientExit {
    PtyExited(i32),
    OwnershipRevoked,
    LocalCancelled { signal: i32 },
}

impl ClientExit {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::PtyExited(status) => u8::try_from(status).unwrap_or(1),
            Self::OwnershipRevoked => 4,
            Self::LocalCancelled { signal } => {
                u8::try_from(128_i32.saturating_add(signal)).unwrap_or(1)
            }
        }
    }
}

#[derive(Debug)]
pub enum ClientRunError {
    Everssh(everssh::Error),
    Identity(IdentityError),
    Request(RequestError),
    Bootstrap(BootstrapError),
    Handshake(HandshakeError),
    Client(ClientError),
    Transport(TransportError),
    Link(ClientLinkError),
    Driver(ClientDriverError),
    Reconnect(ReconnectError),
    Route(RouteError),
    Status(StatusError),
    Terminal(TerminalError),
    BootstrapEncoding,
    AssociationMismatch,
    InitialUdpUnavailable,
}

impl ClientRunError {
    pub fn is_initial_udp_unavailable(&self) -> bool {
        matches!(self, Self::InitialUdpUnavailable)
    }
}

impl fmt::Display for ClientRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Everssh(error) => write!(formatter, "SSH bootstrap: {error}"),
            Self::Identity(error) => write!(formatter, "identity: {error}"),
            Self::Request(error) => write!(formatter, "bootstrap request: {error}"),
            Self::Bootstrap(error) => write!(formatter, "bootstrap record: {error}"),
            Self::Handshake(error) => write!(formatter, "association handshake: {error}"),
            Self::Client(error) => write!(formatter, "client association: {error}"),
            Self::Transport(error) => write!(formatter, "QUIC transport: {error}"),
            Self::Link(error) => write!(formatter, "QUIC link: {error}"),
            Self::Driver(error) => write!(formatter, "terminal driver: {error}"),
            Self::Reconnect(error) => write!(formatter, "reconnect: {error}"),
            Self::Route(error) => write!(formatter, "route watcher: {error}"),
            Self::Status(error) => write!(formatter, "status journal: {error}"),
            Self::Terminal(error) => write!(formatter, "terminal edge: {error}"),
            Self::BootstrapEncoding => {
                formatter.write_str("everudp bootstrap record is not canonical UTF-8")
            }
            Self::AssociationMismatch => {
                formatter.write_str("everudp bootstrap association does not match")
            }
            Self::InitialUdpUnavailable => formatter.write_str(
                "direct UDP/QUIC was unreachable before the terminal association committed",
            ),
        }
    }
}

impl std::error::Error for ClientRunError {}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for ClientRunError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}

from_error!(everssh::Error, Everssh);
from_error!(IdentityError, Identity);
from_error!(RequestError, Request);
from_error!(BootstrapError, Bootstrap);
from_error!(HandshakeError, Handshake);
from_error!(ClientError, Client);
from_error!(TransportError, Transport);
from_error!(ClientLinkError, Link);
from_error!(ClientDriverError, Driver);
from_error!(ReconnectError, Reconnect);
from_error!(RouteError, Route);
from_error!(StatusError, Status);
from_error!(TerminalError, Terminal);

/// Runs one PTY-lifetime client. OpenSSH exists only while obtaining or
/// refreshing a gateway record; terminal bytes flow exclusively over QUIC.
pub async fn run_client<'fd>(
    config: ClientConfig,
    terminal: TerminalEdge<'fd>,
    limits: Limits,
) -> Result<ClientExit, ClientRunError> {
    limits
        .validate()
        .map_err(crate::WireError::from)
        .map_err(ClientError::from)?;
    let identity = Arc::new(ClientIdentity::generate()?);
    let association_id = AssociationId::generate()?;
    let role = role_for(config.operation);
    let request = make_request(&config, association_id, identity.spki_sha256(), false)?;
    let record = acquire_record(&config, &request, &limits).await?;

    let mut status = match config.status_path.as_deref() {
        Some(path) => Some(StatusFile::create_private(path)?),
        None => None,
    };
    if let Some(status) = status.as_mut() {
        status.transition(LinkState::Connecting, monotonic_ms())?;
    }

    let endpoint = ClientEndpoint::bind_routed(
        record.endpoint(),
        crate::UdpBindPolicy::RouteSelected,
        &identity,
        record.server_spki_sha256(),
        limits,
    )
    .map_err(initial_transport)?;
    let hello = ClientHello::initial(
        association_id,
        record.generation(),
        role,
        initial_position(),
        record.token().clone(),
    )?;
    let initial_deadline = tokio::time::Instant::now() + limits.initial_udp_budget();
    let session = endpoint
        .connect_initial_until(record.endpoint(), &hello, initial_deadline)
        .await
        .map_err(|error| match error {
            InitialConnectError::Unavailable(_) => ClientRunError::InitialUdpUnavailable,
            InitialConnectError::Ambiguous(error) => ClientRunError::Transport(error),
        })?;
    let association = ClientAssociation::new(association_id, record.generation(), role, limits)?;
    #[cfg(feature = "path-diagnostics")]
    let association = {
        let mut association = association;
        if let Some(path) = std::env::var_os("EVERUDP_CLIENT_PATH_TRACE") {
            association
                .enable_path_trace(std::path::Path::new(&path))
                .map_err(TerminalError::from)?;
        }
        association
    };
    let mut link = ClientLink::finish_initial_until(session, association, limits, initial_deadline)
        .await
        .map_err(ClientRunError::Link)?;
    let mut driver = ClientDriver::activate(terminal, &link, limits, status)?;
    let mut remote = record.endpoint();
    let mut generation = record.generation();
    let mut server_pin = record.server_spki_sha256();
    let mut route = match RouteSupervisor::spawn(
        endpoint.clone(),
        remote,
        crate::UdpBindPolicy::RouteSelected,
    ) {
        Ok(route) => route,
        Err(error) => {
            driver.deactivate_with_status(TerminalCause::Transport, 0)?;
            return Err(error.into());
        }
    };
    let mut endpoint = endpoint;

    loop {
        match driver.run_link(&mut link).await? {
            ClientRunOutcome::PtyExited(status) => {
                driver.terminal_status(TerminalCause::PtyExit, 0);
                route.join().await;
                return Ok(ClientExit::PtyExited(status));
            }
            ClientRunOutcome::OwnershipRevoked => {
                driver.terminal_status(TerminalCause::Killed, 0);
                route.join().await;
                return Ok(ClientExit::OwnershipRevoked);
            }
            ClientRunOutcome::LocalCancelled { signal } => {
                driver.terminal_status(
                    TerminalCause::LocalCancel,
                    link.association().ambiguous_input_operations(),
                );
                // A local cancellation is terminal for this client
                // generation. Send an application close while the endpoint
                // is still alive so the persistent gateway can release the
                // connected writer immediately; merely dropping the process
                // leaves peer liveness to the QUIC idle timeout.
                link.close();
                route.join().await;
                return Ok(ClientExit::LocalCancelled { signal });
            }
            ClientRunOutcome::NetworkLost | ClientRunOutcome::PeerClosed => {}
        }

        let ambiguous_input = link.association().ambiguous_input_operations();
        driver.mark_migrating();
        route.notify_path_failure();
        let association = link.into_resumable_association();
        let seed = jitter_seed(association.association_id());
        let reconnect = ReconnectState::new(endpoint, remote, association, seed);
        let recovery_config = Arc::new(config_for_recovery(&config));
        let recovery_identity = Arc::clone(&identity);
        let recovery_generation = generation;
        let recovery_pin = server_pin;
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let reconnect = reconnect_until(
            reconnect,
            limits,
            &mut cancel_rx,
            move |_| {
                let config = Arc::clone(&recovery_config);
                let identity = Arc::clone(&recovery_identity);
                async move {
                    classify_recovery_result(
                        recover_gateway(
                            &config,
                            &identity,
                            association_id,
                            role,
                            recovery_generation,
                            recovery_pin,
                            limits,
                        )
                        .await,
                    )
                }
            },
            move |event| {
                let _ = event_tx.send(event);
            },
        );
        tokio::pin!(reconnect);
        let success = loop {
            tokio::select! {
                biased;
                local = driver.next_disconnected_terminal_event() => {
                    match local {
                        Ok(Some(signal)) => {
                            let _ = cancel_tx.send(true);
                            let _ = reconnect.as_mut().await;
                            driver.deactivate_with_status(
                                TerminalCause::LocalCancel,
                                ambiguous_input,
                            )?;
                            route.join().await;
                            return Ok(ClientExit::LocalCancelled { signal });
                        }
                        Ok(None) => {}
                        Err(error) => {
                            let _ = cancel_tx.send(true);
                            let _ = reconnect.as_mut().await;
                            driver.deactivate_with_status(
                                TerminalCause::Transport,
                                ambiguous_input,
                            )?;
                            route.join().await;
                            return Err(error.into());
                        }
                    }
                }
                event = event_rx.recv() => {
                    if let Some(event) = event {
                        observe_reconnect_event(&mut driver, event, ambiguous_input);
                    }
                }
                result = reconnect.as_mut() => break result,
            }
        };
        drop(cancel_tx);
        let success = match success {
            Ok(success) => success,
            Err(error) => {
                let cause = reconnect_terminal_cause(&error);
                driver.deactivate_with_status(cause, ambiguous_input)?;
                route.join().await;
                return Err(error.into());
            }
        };
        driver.mark_connected();
        if success.gateway_replaced {
            if let Err(error) = driver
                .report_gateway_replacement(success.discarded_ambiguous_input)
                .await
            {
                driver.deactivate_with_status(
                    TerminalCause::Transport,
                    success.discarded_ambiguous_input,
                )?;
                route.join().await;
                return Err(error.into());
            }
        }
        endpoint = success.endpoint;
        remote = success.remote;
        generation = success.link.association().generation();
        if let Some(replacement_pin) = success.replacement_server_spki_sha256 {
            server_pin = replacement_pin;
        }
        link = success.link;
        route.join().await;
        route = match RouteSupervisor::spawn(
            endpoint.clone(),
            remote,
            crate::UdpBindPolicy::RouteSelected,
        ) {
            Ok(route) => route,
            Err(error) => {
                driver.deactivate_with_status(
                    TerminalCause::Transport,
                    link.association().ambiguous_input_operations(),
                )?;
                return Err(error.into());
            }
        };
    }
}

fn observe_reconnect_event(
    driver: &mut ClientDriver<'_>,
    event: ReconnectEvent,
    ambiguous_input: usize,
) {
    match event {
        ReconnectEvent::Waiting { .. } | ReconnectEvent::TemporaryFailure { .. } => {
            driver.mark_reconnecting(ambiguous_input);
        }
        ReconnectEvent::SshRecovery { .. } => {
            driver.mark_recovering_over_ssh(ambiguous_input);
        }
        ReconnectEvent::DisconnectedHeartbeat { .. } => driver.disconnected_heartbeat(),
        ReconnectEvent::Connected => driver.mark_connected(),
        ReconnectEvent::Attempt { .. } | ReconnectEvent::GatewayReplaced { .. } => {}
    }
}

fn reconnect_terminal_cause(error: &ReconnectError) -> TerminalCause {
    match error {
        ReconnectError::Recovery(RecoveryFailure::Authentication | RecoveryFailure::Pin) => {
            TerminalCause::Authentication
        }
        ReconnectError::Recovery(RecoveryFailure::Protocol) | ReconnectError::Link(_) => {
            TerminalCause::Protocol
        }
        ReconnectError::Recovery(RecoveryFailure::Transport)
        | ReconnectError::Transport(_)
        | ReconnectError::ClockOverflow => TerminalCause::Transport,
        ReconnectError::Cancelled => TerminalCause::LocalCancel,
    }
}

fn classify_recovery_result(
    result: Result<RecoveryAction, ClientRunError>,
) -> Result<RecoveryAction, RecoveryFailure> {
    match result {
        Ok(action) => Ok(action),
        Err(error) => match recovery_failure(&error) {
            None => Ok(RecoveryAction::Unchanged),
            Some(failure) => Err(failure),
        },
    }
}

fn recovery_failure(error: &ClientRunError) -> Option<RecoveryFailure> {
    match error {
        ClientRunError::Everssh(
            everssh::Error::SshUnavailable | everssh::Error::BootstrapTimedOut,
        ) => None,
        ClientRunError::Everssh(everssh::Error::Io(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
            ) =>
        {
            None
        }
        ClientRunError::Everssh(
            everssh::Error::SshAuthenticationRejected | everssh::Error::AuthRejected,
        ) => Some(RecoveryFailure::Authentication),
        ClientRunError::Everssh(everssh::Error::PinMismatch)
        | ClientRunError::AssociationMismatch => Some(RecoveryFailure::Pin),
        ClientRunError::Transport(error) if error.is_temporary() => None,
        ClientRunError::Transport(crate::TransportError::PinMismatch) => Some(RecoveryFailure::Pin),
        ClientRunError::Transport(
            crate::TransportError::Rejected
            | crate::TransportError::Admission(_)
            | crate::TransportError::PeerIdentity,
        ) => Some(RecoveryFailure::Authentication),
        ClientRunError::Transport(_) => Some(RecoveryFailure::Transport),
        ClientRunError::Link(error) if error.is_transient() => None,
        ClientRunError::Link(_) => Some(RecoveryFailure::Protocol),
        ClientRunError::Bootstrap(_)
        | ClientRunError::BootstrapEncoding
        | ClientRunError::Handshake(_)
        | ClientRunError::Client(_)
        | ClientRunError::Request(_)
        | ClientRunError::Everssh(_) => Some(RecoveryFailure::Protocol),
        ClientRunError::Identity(_)
        | ClientRunError::Driver(_)
        | ClientRunError::Reconnect(_)
        | ClientRunError::Route(_)
        | ClientRunError::Status(_)
        | ClientRunError::Terminal(_)
        | ClientRunError::InitialUdpUnavailable => Some(RecoveryFailure::Transport),
    }
}

fn role_for(operation: BootstrapOperation) -> ConnectionRole {
    match operation {
        BootstrapOperation::Observe => ConnectionRole::Observer,
        BootstrapOperation::Connect | BootstrapOperation::Attach => ConnectionRole::Writer,
    }
}

fn config_for_recovery(config: &ClientConfig) -> ClientConfig {
    ClientConfig {
        destination: config.destination.clone(),
        remote_role_words: config.remote_role_words.clone(),
        ssh_options: config.ssh_options.clone(),
        operation: match config.operation {
            BootstrapOperation::Observe => BootstrapOperation::Observe,
            BootstrapOperation::Connect | BootstrapOperation::Attach => BootstrapOperation::Attach,
        },
        session: config.session.clone(),
        take_over: config.take_over,
        rows: config.rows,
        columns: config.columns,
        origin: config.origin.clone(),
        command: Vec::new(),
        status_path: None,
    }
}

fn make_request(
    config: &ClientConfig,
    association_id: AssociationId,
    client_spki_sha256: [u8; 32],
    recovery: bool,
) -> Result<BootstrapRequest, RequestError> {
    BootstrapRequest::new(
        if recovery {
            match config.operation {
                BootstrapOperation::Observe => BootstrapOperation::Observe,
                BootstrapOperation::Connect | BootstrapOperation::Attach => {
                    BootstrapOperation::Attach
                }
            }
        } else {
            config.operation
        },
        config.session.clone(),
        role_for(config.operation),
        config.take_over,
        config.rows,
        config.columns,
        association_id,
        client_spki_sha256,
        config.origin.clone(),
        if recovery {
            Vec::new()
        } else {
            config.command.clone()
        },
    )
}

async fn acquire_record(
    config: &ClientConfig,
    request: &BootstrapRequest,
    limits: &Limits,
) -> Result<BootstrapRecord, ClientRunError> {
    let argument = request.encode_token()?;
    let plan = SshPlan::using_config(config.destination.clone(), config.ssh_options.clone())?
        .with_remote_role_invocation(
            config.remote_role_words.clone(),
            BOOTSTRAP_PARENT_ROLE,
            &[argument],
        )?;
    let ssh_limits = everssh::Limits::default();
    verify_effective_config(&plan, &ssh_limits).await?;
    let wire = acquire_bootstrap_bytes(&plan, limits.bootstrap_record_max, &ssh_limits).await?;
    if wire.overflowed() {
        return Err(BootstrapError::Malformed.into());
    }
    let line =
        std::str::from_utf8(wire.as_slice()).map_err(|_| ClientRunError::BootstrapEncoding)?;
    let record = BootstrapRecord::parse_line(line, limits)?;
    if record.association_id() != request.association_id() {
        return Err(ClientRunError::AssociationMismatch);
    }
    Ok(record)
}

#[allow(clippy::too_many_arguments)]
async fn recover_gateway(
    config: &ClientConfig,
    identity: &ClientIdentity,
    association_id: AssociationId,
    role: ConnectionRole,
    old_generation: crate::GatewayGeneration,
    old_pin: [u8; 32],
    limits: Limits,
) -> Result<RecoveryAction, ClientRunError> {
    let request = make_request(config, association_id, identity.spki_sha256(), true)?;
    let record = acquire_record(config, &request, &limits).await?;
    if record.generation() == old_generation {
        if old_pin != [0; 32] && record.server_spki_sha256() != old_pin {
            return Err(ClientRunError::AssociationMismatch);
        }
        return Ok(RecoveryAction::Refreshed {
            remote: record.endpoint(),
        });
    }

    let endpoint = ClientEndpoint::bind_routed(
        record.endpoint(),
        crate::UdpBindPolicy::RouteSelected,
        identity,
        record.server_spki_sha256(),
        limits,
    )?;
    let hello = ClientHello::initial(
        association_id,
        record.generation(),
        role,
        initial_position(),
        record.token().clone(),
    )?;
    let session = endpoint.connect_initial(record.endpoint(), &hello).await?;
    let association = ClientAssociation::new(association_id, record.generation(), role, limits)?;
    let link = ClientLink::finish_initial(session, association, limits).await?;
    Ok(RecoveryAction::Replacement(Box::new(GatewayReplacement {
        endpoint,
        remote: record.endpoint(),
        server_spki_sha256: record.server_spki_sha256(),
        link,
    })))
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

fn initial_transport(error: TransportError) -> ClientRunError {
    if error.is_temporary() {
        ClientRunError::InitialUdpUnavailable
    } else {
        ClientRunError::Transport(error)
    }
}

fn jitter_seed(association_id: AssociationId) -> u64 {
    u64::from_be_bytes(
        association_id.as_bytes()[..8]
            .try_into()
            .expect("association prefix is fixed-size"),
    )
}

fn monotonic_ms() -> u64 {
    everpty::sys::clock_monotonic_ms().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        classify_recovery_result, config_for_recovery, jitter_seed, ClientConfig, ClientExit,
        ClientRunError,
    };
    use crate::{BootstrapError, BootstrapOperation, RecoveryAction, RecoveryFailure};
    use everssh::association::AssociationId;

    fn config(operation: BootstrapOperation) -> ClientConfig {
        ClientConfig {
            destination: "host".to_owned(),
            remote_role_words: vec!["eversh".to_owned(), "__everudp".to_owned()],
            ssh_options: Vec::new(),
            operation,
            session: "work".to_owned(),
            take_over: false,
            rows: if operation == BootstrapOperation::Observe {
                0
            } else {
                24
            },
            columns: if operation == BootstrapOperation::Observe {
                0
            } else {
                80
            },
            origin: "client".to_owned(),
            command: vec![b"shell".to_vec()],
            status_path: None,
        }
    }

    #[test]
    fn recovery_never_recreates_the_original_command() {
        let recovered = config_for_recovery(&config(BootstrapOperation::Connect));
        assert_eq!(recovered.operation, BootstrapOperation::Attach);
        assert!(recovered.command.is_empty());
        let observed = config_for_recovery(&config(BootstrapOperation::Observe));
        assert_eq!(observed.operation, BootstrapOperation::Observe);
    }

    #[test]
    fn process_exit_mapping_is_bounded_and_stable() {
        assert_eq!(ClientExit::PtyExited(0).exit_code(), 0);
        assert_eq!(ClientExit::PtyExited(300).exit_code(), 1);
        assert_eq!(ClientExit::OwnershipRevoked.exit_code(), 4);
        assert_eq!(ClientExit::LocalCancelled { signal: 15 }.exit_code(), 143);
        let id = AssociationId::from_bytes([7; 16]).expect("association");
        assert_eq!(jitter_seed(id), u64::from_be_bytes([7; 8]));
    }

    #[test]
    fn recovery_keeps_network_loss_temporary_but_terminates_auth_pin_and_protocol() {
        assert!(matches!(
            classify_recovery_result(Err(
                ClientRunError::Everssh(everssh::Error::SshUnavailable,)
            )),
            Ok(RecoveryAction::Unchanged)
        ));
        assert!(matches!(
            classify_recovery_result(Err(ClientRunError::Everssh(
                everssh::Error::SshAuthenticationRejected,
            ))),
            Err(RecoveryFailure::Authentication)
        ));
        assert!(matches!(
            classify_recovery_result(Err(ClientRunError::AssociationMismatch)),
            Err(RecoveryFailure::Pin)
        ));
        assert!(matches!(
            classify_recovery_result(Err(ClientRunError::Bootstrap(BootstrapError::Malformed))),
            Err(RecoveryFailure::Protocol)
        ));
        for terminal in [
            everssh::Error::SshProcessFailed,
            everssh::Error::SshPolicyRejected,
            everssh::Error::Io(std::io::Error::from(std::io::ErrorKind::NotFound)),
        ] {
            assert!(matches!(
                classify_recovery_result(Err(ClientRunError::Everssh(terminal))),
                Err(RecoveryFailure::Protocol)
            ));
        }
        assert!(matches!(
            classify_recovery_result(Err(ClientRunError::Everssh(everssh::Error::Io(
                std::io::Error::from(std::io::ErrorKind::TimedOut),
            )))),
            Ok(RecoveryAction::Unchanged)
        ));
    }
}
