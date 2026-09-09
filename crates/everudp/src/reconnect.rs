//! Indefinite PTY-lifetime reconnect and bounded SSH recovery scheduling.

use crate::{
    ClientAssociation, ClientEndpoint, ClientLink, ClientLinkError, Limits, TransportError,
};
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

const PREFIX_BACKOFF_MS: [u64; 6] = [0, 100, 250, 500, 1_000, 2_000];
const TAIL_BACKOFF_MS: u64 = 5_000;
const TAIL_JITTER_MS: u64 = 1_000;

#[derive(Debug, Clone)]
pub struct ReconnectBackoff {
    attempt: u64,
    random: u64,
}

impl ReconnectBackoff {
    pub fn new(seed: u64) -> Self {
        Self {
            attempt: 0,
            random: seed.max(1),
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let index = usize::try_from(self.attempt).unwrap_or(usize::MAX);
        self.attempt = self.attempt.saturating_add(1);
        if let Some(milliseconds) = PREFIX_BACKOFF_MS.get(index) {
            return Duration::from_millis(*milliseconds);
        }
        self.random ^= self.random << 13;
        self.random ^= self.random >> 7;
        self.random ^= self.random << 17;
        let width = TAIL_JITTER_MS * 2 + 1;
        let milliseconds = TAIL_BACKOFF_MS - TAIL_JITTER_MS + self.random % width;
        Duration::from_millis(milliseconds)
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryRequest {
    pub disconnected_for: Duration,
    pub ambiguous_input: usize,
}

pub enum RecoveryAction {
    Unchanged,
    Refreshed { remote: SocketAddr },
    Replacement(Box<GatewayReplacement>),
}

/// A recovery probe reached a durable terminal boundary. Ordinary SSH/network
/// unavailability is represented by `Ok(RecoveryAction::Unchanged)` instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryFailure {
    Authentication,
    Pin,
    Protocol,
    Transport,
}

impl fmt::Display for RecoveryFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Authentication => "everudp SSH recovery authentication failed",
            Self::Pin => "everudp SSH recovery pin or association binding failed",
            Self::Protocol => "everudp SSH recovery protocol failed",
            Self::Transport => "everudp SSH recovery transport failed terminally",
        })
    }
}

pub struct GatewayReplacement {
    pub endpoint: ClientEndpoint,
    pub remote: SocketAddr,
    pub server_spki_sha256: [u8; 32],
    pub link: ClientLink,
}

impl fmt::Debug for RecoveryAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unchanged => formatter.write_str("RecoveryAction::Unchanged"),
            Self::Refreshed { remote } => formatter
                .debug_struct("RecoveryAction::Refreshed")
                .field("remote", remote)
                .finish(),
            Self::Replacement(replacement) => formatter
                .debug_struct("RecoveryAction::Replacement")
                .field("remote", &replacement.remote)
                .field("credentials", &"<REDACTED>")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectEvent {
    Waiting {
        attempt: u64,
        delay: Duration,
    },
    Attempt {
        attempt: u64,
    },
    TemporaryFailure {
        attempt: u64,
    },
    SshRecovery {
        disconnected_for: Duration,
    },
    DisconnectedHeartbeat {
        disconnected_for: Duration,
        ambiguous_input: usize,
    },
    GatewayReplaced {
        ambiguous_input: usize,
    },
    Connected,
}

#[derive(Debug)]
pub enum ReconnectError {
    Transport(TransportError),
    Link(ClientLinkError),
    Recovery(RecoveryFailure),
    Cancelled,
    ClockOverflow,
}

impl fmt::Display for ReconnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "{error}"),
            Self::Link(error) => write!(formatter, "{error}"),
            Self::Recovery(error) => write!(formatter, "{error}"),
            Self::Cancelled => formatter.write_str("everudp reconnect cancelled locally"),
            Self::ClockOverflow => formatter.write_str("everudp reconnect clock overflow"),
        }
    }
}

impl std::error::Error for ReconnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Link(error) => Some(error),
            Self::Recovery(_) | Self::Cancelled | Self::ClockOverflow => None,
        }
    }
}

pub struct ReconnectState {
    endpoint: ClientEndpoint,
    remote: SocketAddr,
    association: ClientAssociation,
    backoff: ReconnectBackoff,
}

impl ReconnectState {
    pub fn new(
        endpoint: ClientEndpoint,
        remote: SocketAddr,
        association: ClientAssociation,
        jitter_seed: u64,
    ) -> Self {
        Self {
            endpoint,
            remote,
            association,
            backoff: ReconnectBackoff::new(jitter_seed),
        }
    }
}

pub struct ReconnectSuccess {
    pub endpoint: ClientEndpoint,
    pub remote: SocketAddr,
    pub link: ClientLink,
    pub gateway_replaced: bool,
    pub replacement_server_spki_sha256: Option<[u8; 32]>,
    pub discarded_ambiguous_input: usize,
}

#[derive(Debug, Clone, Copy)]
struct RecoveryCadence {
    next_recovery: Instant,
    next_heartbeat: Instant,
    interval: Duration,
}

impl RecoveryCadence {
    fn new(started: Instant, limits: &Limits) -> Result<Self, ReconnectError> {
        Ok(Self {
            next_recovery: started
                .checked_add(limits.first_ssh_recovery())
                .ok_or(ReconnectError::ClockOverflow)?,
            next_heartbeat: started
                .checked_add(limits.ssh_recovery_interval())
                .ok_or(ReconnectError::ClockOverflow)?,
            interval: limits.ssh_recovery_interval(),
        })
    }

    fn recovery_due(&self, now: Instant) -> bool {
        now >= self.next_recovery
    }

    fn heartbeat_due(&self, now: Instant) -> bool {
        now >= self.next_heartbeat
    }

    fn recovery_completed(&mut self, now: Instant) -> Result<(), ReconnectError> {
        self.next_recovery = now
            .checked_add(self.interval)
            .ok_or(ReconnectError::ClockOverflow)?;
        Ok(())
    }

    fn heartbeat_emitted(&mut self, now: Instant) -> Result<(), ReconnectError> {
        self.next_heartbeat = now
            .checked_add(self.interval)
            .ok_or(ReconnectError::ClockOverflow)?;
        Ok(())
    }

    fn next_wake(&self, attempt_at: Instant) -> Instant {
        attempt_at.min(self.next_recovery).min(self.next_heartbeat)
    }
}

/// Retry one association forever unless cancellation or a cryptographic /
/// protocol rejection makes the state terminal. SSH recovery is rate-limited
/// independently from QUIC attempts and can return a fully authenticated link
/// for a replacement gateway generation; the old replay association is then
/// dropped without replaying its ambiguous input.
pub async fn reconnect_until<R, RF, O>(
    state: ReconnectState,
    limits: Limits,
    cancel: &mut watch::Receiver<bool>,
    recover: R,
    observe: O,
) -> Result<ReconnectSuccess, ReconnectError>
where
    R: FnMut(RecoveryRequest) -> RF,
    RF: Future<Output = Result<RecoveryAction, RecoveryFailure>>,
    O: FnMut(ReconnectEvent),
{
    limits
        .validate()
        .map_err(crate::WireError::from)
        .map_err(crate::ClientError::from)
        .map_err(ClientLinkError::from)
        .map_err(ReconnectError::Link)?;
    let started = Instant::now();
    let cadence = RecoveryCadence::new(started, &limits)?;
    reconnect_with_cadence(state, limits, cancel, recover, observe, started, cadence).await
}

async fn reconnect_with_cadence<R, RF, O>(
    mut state: ReconnectState,
    limits: Limits,
    cancel: &mut watch::Receiver<bool>,
    mut recover: R,
    mut observe: O,
    started: Instant,
    mut cadence: RecoveryCadence,
) -> Result<ReconnectSuccess, ReconnectError>
where
    R: FnMut(RecoveryRequest) -> RF,
    RF: Future<Output = Result<RecoveryAction, RecoveryFailure>>,
    O: FnMut(ReconnectEvent),
{
    let mut attempt = 0_u64;

    loop {
        let delay = state.backoff.next_delay();
        observe(ReconnectEvent::Waiting { attempt, delay });
        let mut attempt_at = Instant::now()
            .checked_add(delay)
            .ok_or(ReconnectError::ClockOverflow)?;
        loop {
            if *cancel.borrow() {
                return Err(ReconnectError::Cancelled);
            }
            let now = Instant::now();
            if cadence.recovery_due(now) {
                let request = RecoveryRequest {
                    disconnected_for: now.saturating_duration_since(started),
                    ambiguous_input: state.association.ambiguous_input_operations(),
                };
                observe(ReconnectEvent::SshRecovery {
                    disconnected_for: request.disconnected_for,
                });
                let action = tokio::select! {
                    biased;
                    changed = cancel.changed() => {
                        if changed.is_err() || *cancel.borrow() {
                            return Err(ReconnectError::Cancelled);
                        }
                        continue;
                    }
                    action = recover(request) => action.map_err(ReconnectError::Recovery)?,
                };
                cadence.recovery_completed(Instant::now())?;
                match action {
                    RecoveryAction::Unchanged => {}
                    RecoveryAction::Refreshed { remote } => {
                        state.remote = remote;
                        state.backoff.reset();
                        attempt_at = Instant::now();
                    }
                    RecoveryAction::Replacement(replacement) => {
                        let GatewayReplacement {
                            endpoint,
                            remote,
                            server_spki_sha256,
                            link,
                        } = *replacement;
                        let ambiguous_input = state.association.ambiguous_input_operations();
                        observe(ReconnectEvent::GatewayReplaced { ambiguous_input });
                        return Ok(ReconnectSuccess {
                            endpoint,
                            remote,
                            link,
                            gateway_replaced: true,
                            replacement_server_spki_sha256: Some(server_spki_sha256),
                            discarded_ambiguous_input: ambiguous_input,
                        });
                    }
                }
            }
            let now = Instant::now();
            if cadence.heartbeat_due(now) {
                observe(ReconnectEvent::DisconnectedHeartbeat {
                    disconnected_for: now.saturating_duration_since(started),
                    ambiguous_input: state.association.ambiguous_input_operations(),
                });
                cadence.heartbeat_emitted(now)?;
            }
            if now >= attempt_at {
                break;
            }
            let wake_at = cadence.next_wake(attempt_at);
            tokio::select! {
                biased;
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        return Err(ReconnectError::Cancelled);
                    }
                }
                _ = tokio::time::sleep_until(wake_at) => {}
            }
        }

        observe(ReconnectEvent::Attempt { attempt });
        let hello = state
            .association
            .resume_hello()
            .map_err(ClientLinkError::from)
            .map_err(ReconnectError::Link)?;
        let connect = state.endpoint.connect_resume(state.remote, &hello);
        let session = tokio::select! {
            biased;
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    return Err(ReconnectError::Cancelled);
                }
                continue;
            }
            result = connect => match result {
                Ok(session) => session,
                Err(error) if error.is_temporary() => {
                    observe(ReconnectEvent::TemporaryFailure { attempt });
                    attempt = attempt.saturating_add(1);
                    continue;
                }
                Err(error) => return Err(ReconnectError::Transport(error)),
            },
        };
        let finish = ClientLink::try_finish_resume(session, state.association, limits);
        let finished = tokio::select! {
            biased;
            _ = cancel.changed() => return Err(ReconnectError::Cancelled),
            result = finish => result,
        };
        match finished {
            Ok(link) => {
                observe(ReconnectEvent::Connected);
                return Ok(ReconnectSuccess {
                    endpoint: state.endpoint,
                    remote: state.remote,
                    link,
                    gateway_replaced: false,
                    replacement_server_spki_sha256: None,
                    discarded_ambiguous_input: 0,
                });
            }
            Err(failure) => {
                let (error, association) = failure.into_parts();
                state.association = association;
                if error.is_transient() {
                    observe(ReconnectEvent::TemporaryFailure { attempt });
                    attempt = attempt.saturating_add(1);
                    continue;
                }
                return Err(ReconnectError::Link(error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        reconnect_with_cadence, GatewayReplacement, ReconnectBackoff, ReconnectEvent,
        ReconnectState, RecoveryAction, RecoveryCadence, PREFIX_BACKOFF_MS,
    };
    use crate::wire::ConnectionRole;
    use crate::{
        ClientAssociation, ClientEndpoint, ClientHello, ClientIdentity, ClientLink,
        GatewayEndpoint, GatewayGeneration, GatewayIdentity, GatewayLifecycle, GatewayLink,
        GatewayReplaySlabs, InvitationStore, Limits, ResumePosition,
    };
    use everssh::association::AssociationId;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::watch;
    use tokio::time::Instant;

    fn association(byte: u8) -> AssociationId {
        AssociationId::from_bytes([byte; 16]).expect("association")
    }

    fn generation(byte: u8) -> GatewayGeneration {
        GatewayGeneration::from_bytes([byte; 16]).expect("generation")
    }

    fn loopback() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
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

    #[test]
    fn retry_prefix_is_exact_and_tail_is_bounded_jitter_forever() {
        let mut backoff = ReconnectBackoff::new(0x1234_5678);
        for expected in PREFIX_BACKOFF_MS {
            assert_eq!(backoff.next_delay(), Duration::from_millis(expected));
        }
        for _ in 0..10_000 {
            let delay = backoff.next_delay();
            assert!(delay >= Duration::from_secs(4));
            assert!(delay <= Duration::from_secs(6));
        }
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::ZERO);
    }

    #[test]
    fn ssh_recovery_starts_at_thirty_seconds_then_is_rate_limited_for_a_minute() {
        let limits = Limits::default();
        let started = Instant::now();
        let mut cadence = RecoveryCadence::new(started, &limits).expect("cadence");

        assert!(!cadence.recovery_due(started + Duration::from_millis(29_999)));
        assert!(cadence.recovery_due(started + Duration::from_secs(30)));
        cadence
            .recovery_completed(started + Duration::from_secs(35))
            .expect("complete recovery");
        assert!(!cadence.recovery_due(started + Duration::from_millis(94_999)));
        assert!(cadence.recovery_due(started + Duration::from_secs(95)));

        assert!(!cadence.heartbeat_due(started + Duration::from_millis(59_999)));
        assert!(cadence.heartbeat_due(started + Duration::from_secs(60)));
        cadence
            .heartbeat_emitted(started + Duration::from_secs(60))
            .expect("heartbeat");
        assert!(!cadence.heartbeat_due(started + Duration::from_millis(119_999)));
        assert!(cadence.heartbeat_due(started + Duration::from_secs(120)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gateway_replacement_drops_and_reports_ambiguous_old_input() {
        tokio::time::timeout(Duration::from_secs(8), async {
            let limits = Limits::default();
            let replacement_generation = generation(72);
            let replacement_association = association(73);
            let invitations = Arc::new(Mutex::new(
                InvitationStore::new("replacement", replacement_generation, &limits)
                    .expect("invitations"),
            ));
            let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
            let gateway = GatewayEndpoint::bind(
                loopback(),
                &gateway_identity,
                Arc::clone(&invitations),
                limits,
            )
            .expect("gateway");
            let replacement_identity = ClientIdentity::generate().expect("client identity");
            let ticket = invitations
                .lock()
                .expect("invitations lock")
                .issue(
                    replacement_association,
                    ConnectionRole::Writer,
                    replacement_identity.spki_sha256(),
                    everpty::sys::clock_monotonic_ms().expect("clock"),
                )
                .expect("ticket");
            let hello = ClientHello::initial(
                replacement_association,
                replacement_generation,
                ConnectionRole::Writer,
                initial_position(),
                ticket.token().clone(),
            )
            .expect("hello");
            let replacement_endpoint = ClientEndpoint::bind(
                loopback(),
                &replacement_identity,
                gateway_identity.spki_sha256(),
                limits,
            )
            .expect("replacement endpoint");
            let replacement_remote = gateway.local_addr();
            let (admitted, session) = tokio::join!(
                gateway.accept_initial(),
                replacement_endpoint.connect_initial(replacement_remote, &hello)
            );
            let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
            let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
            let replacement_client = ClientAssociation::new(
                replacement_association,
                replacement_generation,
                ConnectionRole::Writer,
                limits,
            )
            .expect("replacement association");
            let (server_link, replacement_link) = tokio::join!(
                GatewayLink::accept_initial(
                    admitted.expect("admission"),
                    &mut lifecycle,
                    &mut slabs,
                    limits,
                ),
                ClientLink::finish_initial(session.expect("session"), replacement_client, limits,)
            );
            let server_link = server_link.expect("server link").0;
            let replacement_link = replacement_link.expect("replacement link");

            let old_identity = ClientIdentity::generate().expect("old identity");
            let old_endpoint = ClientEndpoint::bind(
                loopback(),
                &old_identity,
                gateway_identity.spki_sha256(),
                limits,
            )
            .expect("old endpoint");
            let mut old_association = ClientAssociation::new(
                association(74),
                generation(75),
                ConnectionRole::Writer,
                limits,
            )
            .expect("old association");
            old_association.queue_input(b"first").expect("first input");
            old_association
                .queue_input(b"second")
                .expect("second input");
            let state = ReconnectState::new(
                old_endpoint,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
                old_association,
                1,
            );
            let replacement = GatewayReplacement {
                endpoint: replacement_endpoint,
                remote: replacement_remote,
                server_spki_sha256: gateway_identity.spki_sha256(),
                link: replacement_link,
            };
            let started = Instant::now();
            let cadence = RecoveryCadence {
                next_recovery: started,
                next_heartbeat: started + limits.ssh_recovery_interval(),
                interval: limits.ssh_recovery_interval(),
            };
            let (_cancel_tx, mut cancel) = watch::channel(false);
            let mut replacement = Some(replacement);
            let mut events = Vec::new();
            let success = reconnect_with_cadence(
                state,
                limits,
                &mut cancel,
                |_| {
                    let action = RecoveryAction::Replacement(Box::new(
                        replacement.take().expect("one recovery"),
                    ));
                    async move { Ok(action) }
                },
                |event| events.push(event),
                started,
                cadence,
            )
            .await
            .expect("replacement");

            assert!(success.gateway_replaced);
            assert_eq!(success.discarded_ambiguous_input, 2);
            assert_eq!(success.link.association().ambiguous_input_operations(), 0);
            assert!(matches!(
                events.as_slice(),
                [
                    ReconnectEvent::Waiting { .. },
                    ReconnectEvent::SshRecovery { .. },
                    ReconnectEvent::GatewayReplaced { ambiguous_input: 2 }
                ]
            ));
            success.link.close();
            server_link.close();
        })
        .await
        .expect("replacement test deadline");
    }
}
