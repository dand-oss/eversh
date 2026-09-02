//! Authenticated SSH endpoint types and one-use stream admission.

use crate::bootstrap::{
    ct_eq, decode_auth_frame, sha256, SecretAuthFrame, SecretToken, AUTH_FRAME_LEN,
};
use crate::error::{DeadlinePhase, EndpointViolation, Error};
use crate::limits::Limits;
use noq::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

const CLOSE_CODE: VarInt = VarInt::from_u32(0x4556);

/// Already-parsed endpoints from an authenticated SSH connection. Text and
/// environment parsing deliberately belongs to Slice 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedConnection {
    peer: SocketAddr,
    local: SocketAddr,
}

impl AuthenticatedConnection {
    pub fn new(peer: SocketAddr, local: SocketAddr) -> Result<Self, Error> {
        validate_literal(peer)?;
        validate_literal(local)?;
        if peer.is_ipv4() != local.is_ipv4() {
            return Err(Error::InvalidEndpoint(EndpointViolation::FamilyMismatch));
        }
        Ok(Self { peer, local })
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn local(&self) -> SocketAddr {
        self.local
    }

    pub fn authorized_target_addr(&self) -> SocketAddr {
        self.authorized_target().address
    }

    fn authorized_target(&self) -> AuthorizedTarget {
        let address = match self.local {
            SocketAddr::V4(_) => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.local.port())
            }
            SocketAddr::V6(_) => {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), self.local.port())
            }
        };
        AuthorizedTarget { address }
    }
}

fn validate_literal(address: SocketAddr) -> Result<(), Error> {
    if address.port() == 0 {
        return Err(Error::InvalidEndpoint(EndpointViolation::ZeroPort));
    }
    match address {
        SocketAddr::V4(address) => {
            let ip = *address.ip();
            if ip.is_unspecified() {
                return Err(Error::InvalidEndpoint(
                    EndpointViolation::UnspecifiedAddress,
                ));
            }
            if ip.is_multicast() {
                return Err(Error::InvalidEndpoint(EndpointViolation::MulticastAddress));
            }
            if ip == Ipv4Addr::BROADCAST {
                return Err(Error::InvalidEndpoint(EndpointViolation::BroadcastAddress));
            }
        }
        SocketAddr::V6(address) => {
            let ip = *address.ip();
            if ip.is_unspecified() {
                return Err(Error::InvalidEndpoint(
                    EndpointViolation::UnspecifiedAddress,
                ));
            }
            if ip.is_multicast() {
                return Err(Error::InvalidEndpoint(EndpointViolation::MulticastAddress));
            }
            if ip.is_unicast_link_local() && address.scope_id() == 0 {
                return Err(Error::InvalidEndpoint(EndpointViolation::MissingIpv6Scope));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AuthorizedTarget {
    address: SocketAddr,
}

/// Linearizable owner of the server's one-use token. The raw token is erased
/// at successful consumption. A one-way verifier remains solely to distinguish
/// a genuine later reuse from a wrong token without retaining the raw secret.
pub struct OneUseToken {
    state: Mutex<TokenState>,
}

enum TokenStatus {
    Available(SecretToken),
    Consumed,
}

struct TokenState {
    status: TokenStatus,
    verifier: [u8; 32],
}

impl OneUseToken {
    pub(crate) fn new(token: SecretToken) -> Self {
        let verifier = sha256(token.as_bytes());
        Self {
            state: Mutex::new(TokenState {
                status: TokenStatus::Available(token),
                verifier,
            }),
        }
    }

    fn claim(&self, candidate: &[u8]) -> Result<(), Error> {
        let candidate_verifier = Zeroizing::new(sha256(candidate));
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::TokenStateUnavailable)?;
        let is_consumed_token = ct_eq(&candidate_verifier[..], &state.verifier);
        match &mut state.status {
            TokenStatus::Available(expected) => {
                if !ct_eq(candidate, expected.as_bytes()) {
                    return Err(Error::AuthRejected);
                }
                expected.zeroize();
                state.status = TokenStatus::Consumed;
                Ok(())
            }
            TokenStatus::Consumed if is_consumed_token => Err(Error::TokenReuse),
            TokenStatus::Consumed => Err(Error::AuthRejected),
        }
    }
}

impl std::fmt::Debug for OneUseToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OneUseToken(<REDACTED>)")
    }
}

impl Drop for TokenState {
    fn drop(&mut self) {
        self.verifier.zeroize();
    }
}

/// The only capability from which production target TCP may be opened.
pub struct AdmittedStream {
    endpoint: Endpoint,
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    target: AuthorizedTarget,
    deadline: Instant,
    finalize_timeout: Duration,
    retry_observed: bool,
}

impl AdmittedStream {
    pub fn authorized_target_addr(&self) -> SocketAddr {
        self.target.address
    }

    pub fn retry_observed(&self) -> bool {
        self.retry_observed
    }

    #[cfg(test)]
    pub(crate) fn connection_for_test(&self) -> &Connection {
        &self.connection
    }

    pub async fn connect_target(self) -> Result<ConnectedTarget, Error> {
        self.connect_with(TcpStream::connect).await
    }

    async fn connect_with<F, Fut>(self, connector: F) -> Result<ConnectedTarget, Error>
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: Future<Output = std::io::Result<TcpStream>>,
    {
        let target_address = self.target.address;
        let stream = connect_authorized_once(self.target, self.deadline, connector).await?;
        Ok(ConnectedTarget {
            endpoint: self.endpoint,
            connection: self.connection,
            send: self.send,
            recv: self.recv,
            stream,
            target_address,
            finalize_timeout: self.finalize_timeout,
        })
    }
}

async fn connect_authorized_once<T, F, Fut>(
    target: AuthorizedTarget,
    deadline: Instant,
    connector: F,
) -> Result<T, Error>
where
    F: FnOnce(SocketAddr) -> Fut,
    Fut: Future<Output = std::io::Result<T>>,
{
    ensure_deadline(deadline, DeadlinePhase::TargetConnect)?;
    let result = tokio::time::timeout_at(deadline, connector(target.address))
        .await
        .map_err(|_| Error::DeadlineExpired(DeadlinePhase::TargetConnect))?;
    ensure_deadline(deadline, DeadlinePhase::TargetConnect)?;
    result.map_err(Error::TargetConnect)
}

fn ensure_deadline(deadline: Instant, phase: DeadlinePhase) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::DeadlineExpired(phase))
    } else {
        Ok(())
    }
}

impl std::fmt::Debug for AdmittedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmittedStream")
            .field("target", &self.target.address)
            .field("retry_observed", &self.retry_observed)
            .finish_non_exhaustive()
    }
}

/// Post-admission owner of the exact target and both QUIC stream halves.
pub struct ConnectedTarget {
    endpoint: Endpoint,
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    stream: TcpStream,
    target_address: SocketAddr,
    finalize_timeout: Duration,
}

pub(crate) struct ConnectedTargetParts {
    pub(crate) endpoint: Endpoint,
    pub(crate) connection: Connection,
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
    pub(crate) stream: TcpStream,
    pub(crate) target_address: SocketAddr,
}

impl ConnectedTarget {
    pub fn target_address(&self) -> SocketAddr {
        self.target_address
    }

    pub fn tcp_stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub fn quic_send_mut(&mut self) -> &mut SendStream {
        &mut self.send
    }

    pub fn quic_recv_mut(&mut self) -> &mut RecvStream {
        &mut self.recv
    }

    pub(crate) fn into_parts(self) -> ConnectedTargetParts {
        let Self {
            endpoint,
            connection,
            send,
            recv,
            stream,
            target_address,
            ..
        } = self;
        ConnectedTargetParts {
            endpoint,
            connection,
            send,
            recv,
            stream,
            target_address,
        }
    }

    pub async fn close(self) -> Result<(), Error> {
        let finalize_timeout = self.finalize_timeout;
        let deadline = Instant::now().checked_add(finalize_timeout);
        let Self {
            endpoint,
            connection,
            send,
            recv,
            stream,
            ..
        } = self;

        connection.close(CLOSE_CODE, b"slice1 complete");
        endpoint.set_server_config(None);
        endpoint.close(CLOSE_CODE, b"slice1 complete");
        drop(send);
        drop(recv);
        drop(stream);
        drop(connection);

        let deadline = match deadline {
            Some(deadline) => deadline,
            None => {
                drop(endpoint);
                return Err(Error::InvalidLimits(
                    crate::error::LimitViolation::DeadlineOverflow,
                ));
            }
        };
        let idle = tokio::time::timeout_at(deadline, endpoint.wait_idle())
            .await
            .map_err(|_| Error::DeadlineExpired(DeadlinePhase::Finalize));
        drop(endpoint);
        idle
    }
}

impl std::fmt::Debug for ConnectedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectedTarget")
            .field("target", &self.target_address)
            .finish_non_exhaustive()
    }
}

pub(crate) async fn admit_first_stream(
    endpoint: Endpoint,
    connection: Connection,
    token: &OneUseToken,
    authenticated: AuthenticatedConnection,
    limits: &Limits,
    deadline: Instant,
    retry_observed: bool,
) -> Result<AdmittedStream, Error> {
    if let Err(error) = ensure_deadline(deadline, DeadlinePhase::Authentication) {
        connection.close(CLOSE_CODE, b"authentication deadline expired");
        return Err(error);
    }
    let stream = tokio::time::timeout_at(deadline, connection.accept_bi())
        .await
        .map_err(|_| Error::DeadlineExpired(DeadlinePhase::Authentication))?
        .map_err(|_| Error::StreamOpen);
    let (send, mut recv) = match stream {
        Ok(stream) => stream,
        Err(error) => {
            connection.close(CLOSE_CODE, b"stream admission failed");
            return Err(error);
        }
    };
    if let Err(error) = ensure_deadline(deadline, DeadlinePhase::Authentication) {
        connection.close(CLOSE_CODE, b"authentication deadline expired");
        return Err(error);
    }

    let mut raw = [0; AUTH_FRAME_LEN];
    let read_result = read_exact_prefix(&mut recv, &mut raw, deadline).await;
    if let Err(error) = read_result {
        raw.zeroize();
        connection.close(CLOSE_CODE, b"authentication failed");
        return Err(error);
    }
    if let Err(error) = ensure_deadline(deadline, DeadlinePhase::Authentication) {
        raw.zeroize();
        connection.close(CLOSE_CODE, b"authentication deadline expired");
        return Err(error);
    }
    let frame = SecretAuthFrame::take_bytes(&mut raw);
    let target = match validate_authentication(frame.as_ref(), token, authenticated, limits) {
        Ok(target) => target,
        Err(error) => {
            connection.close(CLOSE_CODE, b"authentication failed");
            return Err(error);
        }
    };

    Ok(AdmittedStream {
        endpoint,
        connection,
        send,
        recv,
        target,
        deadline,
        finalize_timeout: limits.finalize_timeout(),
        retry_observed,
    })
}

fn validate_authentication(
    frame: &[u8],
    token: &OneUseToken,
    authenticated: AuthenticatedConnection,
    limits: &Limits,
) -> Result<AuthorizedTarget, Error> {
    let (candidate, target_port) = decode_auth_frame(frame, limits)?;
    let target = authenticated.authorized_target();
    if target_port != target.address.port() {
        return Err(Error::TargetUnauthorized);
    }
    token.claim(candidate.as_bytes())?;
    Ok(target)
}

async fn read_exact_prefix(
    recv: &mut RecvStream,
    frame: &mut [u8; AUTH_FRAME_LEN],
    deadline: Instant,
) -> Result<(), Error> {
    let mut filled = 0;
    while filled < frame.len() {
        ensure_deadline(deadline, DeadlinePhase::Authentication)?;
        let read = tokio::time::timeout_at(deadline, recv.read(&mut frame[filled..]))
            .await
            .map_err(|_| Error::DeadlineExpired(DeadlinePhase::Authentication))?
            .map_err(|_| Error::StreamRead)?;
        match read {
            Some(0) | None => return Err(Error::AuthRejected),
            Some(read) => filled += read,
        }
    }
    ensure_deadline(deadline, DeadlinePhase::Authentication)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::bootstrap::{encode_auth_frame, try_encode_auth_frame};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    #[test]
    fn token_claim_is_linearizable_and_typed() {
        let valid = SecretToken::from_bytes([7; 32]);
        let owner = Arc::new(OneUseToken::new(valid.clone()));
        assert!(matches!(owner.claim(&[8; 32]), Err(Error::AuthRejected)));

        let barrier = Arc::new(Barrier::new(12));
        let mut threads = Vec::new();
        for _ in 0..12 {
            let owner = owner.clone();
            let barrier = barrier.clone();
            let candidate = valid.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                owner.claim(candidate.as_bytes())
            }));
        }
        let mut admitted = 0;
        let mut reused = 0;
        for thread in threads {
            match thread.join() {
                Ok(Ok(())) => admitted += 1,
                Ok(Err(Error::TokenReuse)) => reused += 1,
                outcome => panic!("unexpected token outcome: {outcome:?}"),
            }
        }
        assert_eq!(admitted, 1);
        assert_eq!(reused, 11);
        assert!(matches!(owner.claim(&[8; 32]), Err(Error::AuthRejected)));
        assert!(matches!(
            owner.claim(valid.as_bytes()),
            Err(Error::TokenReuse)
        ));
    }

    #[test]
    fn endpoint_validation_fails_closed() {
        let local = SocketAddr::from(([192, 0, 2, 2], 22));
        for peer in [
            SocketAddr::from(([0, 0, 0, 0], 1)),
            SocketAddr::from(([224, 0, 0, 1], 1)),
            SocketAddr::from(([255, 255, 255, 255], 1)),
        ] {
            assert!(AuthenticatedConnection::new(peer, local).is_err());
        }
    }

    #[test]
    fn version_selector_and_wrong_token_do_not_consume() {
        let limits = Limits::default();
        let authenticated = AuthenticatedConnection::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 50_000)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 2222)),
        )
        .unwrap();
        let valid = SecretToken::from_bytes([0x31; 32]);
        let valid_frame = encode_auth_frame(&valid, 2222, &limits);

        let version_owner = OneUseToken::new(valid.clone());
        let mut wrong_version = valid_frame.as_ref().to_vec();
        wrong_version[0] = 2;
        assert!(matches!(
            validate_authentication(&wrong_version, &version_owner, authenticated, &limits),
            Err(Error::VersionUnsupported)
        ));
        assert!(validate_authentication(
            valid_frame.as_ref(),
            &version_owner,
            authenticated,
            &limits
        )
        .is_ok());

        let selector_owner = OneUseToken::new(valid.clone());
        let wrong_selector = try_encode_auth_frame(&valid, 2223, &limits).unwrap();
        assert!(matches!(
            validate_authentication(
                wrong_selector.as_ref(),
                &selector_owner,
                authenticated,
                &limits
            ),
            Err(Error::TargetUnauthorized)
        ));
        assert!(validate_authentication(
            valid_frame.as_ref(),
            &selector_owner,
            authenticated,
            &limits
        )
        .is_ok());

        let token_owner = OneUseToken::new(valid.clone());
        let wrong_token = SecretToken::from_bytes([0x32; 32]);
        let wrong_token_frame = try_encode_auth_frame(&wrong_token, 2222, &limits).unwrap();
        assert!(matches!(
            validate_authentication(
                wrong_token_frame.as_ref(),
                &token_owner,
                authenticated,
                &limits
            ),
            Err(Error::AuthRejected)
        ));
        assert!(validate_authentication(
            valid_frame.as_ref(),
            &token_owner,
            authenticated,
            &limits
        )
        .is_ok());
        assert!(matches!(
            validate_authentication(valid_frame.as_ref(), &token_owner, authenticated, &limits),
            Err(Error::TokenReuse)
        ));
    }

    #[tokio::test]
    async fn connector_seam_receives_exact_target_once_and_is_bounded() {
        let target_address = SocketAddr::from((Ipv4Addr::LOCALHOST, 2222));
        let target = AuthorizedTarget {
            address: target_address,
        };
        let calls = AtomicUsize::new(0);
        let seen = Mutex::new(None);
        let result = connect_authorized_once::<(), _, _>(
            target,
            Instant::now() + Duration::from_secs(1),
            |address| {
                calls.fetch_add(1, Ordering::SeqCst);
                *seen.lock().unwrap() = Some(address);
                std::future::ready(Err(std::io::Error::new(
                    std::io::ErrorKind::OutOfMemory,
                    "injected connector allocation failure",
                )))
            },
        )
        .await;
        assert!(matches!(result, Err(Error::TargetConnect(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(*seen.lock().unwrap(), Some(target_address));

        let expired = connect_authorized_once::<(), _, _>(
            target,
            Instant::now() + Duration::from_millis(10),
            |_| std::future::pending(),
        )
        .await;
        assert!(matches!(
            expired,
            Err(Error::DeadlineExpired(DeadlinePhase::TargetConnect))
        ));

        let expired_calls = AtomicUsize::new(0);
        let already_expired = connect_authorized_once::<(), _, _>(target, Instant::now(), |_| {
            expired_calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(()))
        })
        .await;
        assert!(matches!(
            already_expired,
            Err(Error::DeadlineExpired(DeadlinePhase::TargetConnect))
        ));
        assert_eq!(expired_calls.load(Ordering::SeqCst), 0);
    }
}
