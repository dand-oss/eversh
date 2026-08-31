//! Deterministic UDP policy and locked noq/rustls transport.

use crate::admission::{
    self, AdmittedStream, AuthenticatedConnection, ConnectedTarget, OneUseToken,
};
use crate::bootstrap::{try_encode_auth_frame, SecretToken, ALPN};
use crate::error::{DeadlinePhase, EndpointViolation, Error, LimitViolation, UdpPolicyViolation};
use crate::identity::EphemeralIdentity;
use crate::limits::Limits;
use crate::pinning::{PinMismatchMarker, PinMismatchState, SpkiPinVerifier};
use noq::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use noq::rustls::client::Resumption;
use noq::rustls::crypto::CryptoProvider;
use noq::rustls::server::{ClientHello, NoServerSessionStorage, ResolvesServerCert};
use noq::rustls::sign::CertifiedKey;
use noq::rustls::{ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig};
use noq::{
    ClientConfig, Connection, ConnectionError, Endpoint, EndpointConfig, IdleTimeout, NoneTokenLog,
    NoneTokenStore, RecvStream, SendStream, ServerConfig, TokioRuntime, TransportConfig, VarInt,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::Arc;
use tokio::time::Instant;

const CLOSE_CODE: VarInt = VarInt::from_u32(0x4556);

/// The only three UDP binding policies accepted by Slice 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpBindPolicy {
    RouteSelected,
    RouteSelectedPortRange { start: u16, end: u16 },
    Explicit(SocketAddr),
}

/// Successfully bound socket plus the exact endpoint verified from the kernel.
pub struct BoundUdp {
    socket: UdpSocket,
    local_address: SocketAddr,
}

impl BoundUdp {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_address
    }

    fn into_socket(self) -> UdpSocket {
        self.socket
    }
}

impl std::fmt::Debug for BoundUdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundUdp")
            .field("local_address", &self.local_address)
            .finish_non_exhaustive()
    }
}

/// Observable values that drive the private noq setters. Tests use this only
/// where noq 1.1.1 keeps the corresponding fields private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedTransportProfile {
    pub tls13_only: bool,
    pub alpn: &'static [u8],
    pub client_resumption: bool,
    pub early_data: bool,
    pub server_half_rtt_data: bool,
    pub tls13_tickets: usize,
    pub requested_tls13_tickets: usize,
    pub new_tokens: bool,
    pub preferred_addresses: bool,
    pub server_incoming_bidi: u32,
    pub client_incoming_bidi: u32,
    pub incoming_uni: u32,
    pub datagrams: bool,
    pub address_discovery: bool,
    pub multipath: bool,
    pub nat_traversal: bool,
    pub handshake_migration: bool,
    pub standard_migration: bool,
    pub max_incoming: usize,
    pub incoming_buffer_size: u64,
    pub incoming_buffer_size_total: u64,
    pub send_window: u64,
    pub receive_window: u64,
    pub idle_timeout_ms: u64,
}

/// Bind one socket using only a literal peer and kernel routing. No resolver,
/// interface inventory, or address guessing is involved.
pub fn bind_udp(
    peer: SocketAddr,
    policy: UdpBindPolicy,
    limits: &Limits,
) -> Result<BoundUdp, Error> {
    limits.validate()?;
    validate_remote(peer)?;
    match policy {
        UdpBindPolicy::Explicit(local) => bind_explicit(peer, local),
        UdpBindPolicy::RouteSelected => {
            if peer.ip().is_loopback() {
                return Err(Error::InvalidUdpPolicy(
                    UdpPolicyViolation::PeerLoopbackRequiresExplicit,
                ));
            }
            let selected = kernel_selected_source(peer)?;
            bind_route_selected(selected, None, limits)
        }
        UdpBindPolicy::RouteSelectedPortRange { start, end } => {
            if peer.ip().is_loopback() {
                return Err(Error::InvalidUdpPolicy(
                    UdpPolicyViolation::PeerLoopbackRequiresExplicit,
                ));
            }
            validate_range(start, end, limits)?;
            let selected = kernel_selected_source(peer)?;
            bind_route_selected(selected, Some((start, end)), limits)
        }
    }
}

fn validate_remote(address: SocketAddr) -> Result<(), Error> {
    if address.port() == 0 {
        return Err(Error::InvalidEndpoint(EndpointViolation::ZeroPort));
    }
    validate_usable_local(address).map_err(Error::InvalidEndpoint)
}

fn validate_usable_local(address: SocketAddr) -> Result<(), EndpointViolation> {
    match address {
        SocketAddr::V4(address) => {
            let ip = *address.ip();
            if ip.is_unspecified() {
                return Err(EndpointViolation::UnspecifiedAddress);
            }
            if ip.is_multicast() {
                return Err(EndpointViolation::MulticastAddress);
            }
            if ip == Ipv4Addr::BROADCAST {
                return Err(EndpointViolation::BroadcastAddress);
            }
        }
        SocketAddr::V6(address) => {
            let ip = *address.ip();
            if ip.is_unspecified() {
                return Err(EndpointViolation::UnspecifiedAddress);
            }
            if ip.is_multicast() {
                return Err(EndpointViolation::MulticastAddress);
            }
            if ip.is_unicast_link_local() && address.scope_id() == 0 {
                return Err(EndpointViolation::MissingIpv6Scope);
            }
        }
    }
    Ok(())
}

fn bind_explicit(peer: SocketAddr, local: SocketAddr) -> Result<BoundUdp, Error> {
    if local.is_ipv4() != peer.is_ipv4() {
        return Err(Error::InvalidUdpPolicy(
            UdpPolicyViolation::ExplicitFamilyMismatch,
        ));
    }
    if local.port() == 0 {
        return Err(Error::InvalidUdpPolicy(
            UdpPolicyViolation::ExplicitPortZero,
        ));
    }
    validate_usable_local(local).map_err(Error::InvalidEndpoint)?;
    bind_exact(local, false).map_err(map_bind_failure)
}

fn validate_range(start: u16, end: u16, limits: &Limits) -> Result<(), Error> {
    if start == 0 {
        return Err(Error::InvalidUdpPolicy(
            UdpPolicyViolation::RangeStartsAtZero,
        ));
    }
    if start > end {
        return Err(Error::InvalidUdpPolicy(UdpPolicyViolation::RangeInverted));
    }
    let width = u32::from(end) - u32::from(start) + 1;
    if width > limits.max_udp_port_span {
        return Err(Error::InvalidUdpPolicy(UdpPolicyViolation::RangeTooWide));
    }
    Ok(())
}

fn kernel_selected_source(peer: SocketAddr) -> Result<SocketAddr, Error> {
    let wildcard = match peer {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let probe = UdpSocket::bind(wildcard).map_err(Error::RouteSelection)?;
    probe.connect(peer).map_err(Error::RouteSelection)?;
    let selected = probe.local_addr().map_err(Error::RouteSelection)?;
    if selected.is_ipv4() != peer.is_ipv4()
        || validate_usable_local(selected).is_err()
        || selected.ip().is_loopback() != peer.ip().is_loopback()
    {
        return Err(Error::InvalidUdpPolicy(
            UdpPolicyViolation::SelectedAddressUnusable,
        ));
    }
    Ok(selected)
}

fn bind_route_selected(
    selected: SocketAddr,
    range: Option<(u16, u16)>,
    limits: &Limits,
) -> Result<BoundUdp, Error> {
    bind_route_selected_with(selected, range, limits, bind_exact)
}

fn bind_route_selected_with<F>(
    selected: SocketAddr,
    range: Option<(u16, u16)>,
    limits: &Limits,
    mut binder: F,
) -> Result<BoundUdp, Error>
where
    F: FnMut(SocketAddr, bool) -> Result<BoundUdp, BindFailure>,
{
    validate_usable_local(selected)
        .map_err(|_| Error::InvalidUdpPolicy(UdpPolicyViolation::SelectedAddressUnusable))?;
    match range {
        None => binder(with_port(selected, 0), true).map_err(map_bind_failure),
        Some((start, end)) => {
            validate_range(start, end, limits)?;
            for port in u32::from(start)..=u32::from(end) {
                let requested = with_port(selected, port as u16);
                match binder(requested, false) {
                    Ok(bound) => return Ok(bound),
                    Err(BindFailure::AddressInUse(_)) => {}
                    Err(error) => return Err(map_bind_failure(error)),
                }
            }
            Err(Error::PortRangeExhausted)
        }
    }
}

fn with_port(address: SocketAddr, port: u16) -> SocketAddr {
    match address {
        SocketAddr::V4(address) => SocketAddr::new(IpAddr::V4(*address.ip()), port),
        SocketAddr::V6(address) => SocketAddr::V6(SocketAddrV6::new(
            *address.ip(),
            port,
            address.flowinfo(),
            address.scope_id(),
        )),
    }
}

enum BindFailure {
    AddressInUse(std::io::Error),
    Io(std::io::Error),
    Mismatch,
}

fn map_bind_failure(error: BindFailure) -> Error {
    match error {
        BindFailure::AddressInUse(source) | BindFailure::Io(source) => Error::UdpBind(source),
        BindFailure::Mismatch => Error::InvalidUdpPolicy(UdpPolicyViolation::ExactBindMismatch),
    }
}

fn bind_exact(requested: SocketAddr, ephemeral: bool) -> Result<BoundUdp, BindFailure> {
    let socket = UdpSocket::bind(requested).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AddrInUse {
            BindFailure::AddressInUse(source)
        } else {
            BindFailure::Io(source)
        }
    })?;
    let actual = socket.local_addr().map_err(BindFailure::Io)?;
    let exact = if ephemeral {
        actual.ip() == requested.ip() && actual.port() != 0
    } else {
        actual == requested
    };
    if !exact {
        return Err(BindFailure::Mismatch);
    }
    Ok(BoundUdp {
        socket,
        local_address: actual,
    })
}

/// Server endpoint frozen at readiness. Constructing it never opens target TCP.
pub struct ServerEndpoint {
    endpoint: Endpoint,
    local_address: SocketAddr,
    authenticated: AuthenticatedConnection,
    token: Arc<OneUseToken>,
    accept_config: Arc<ServerConfig>,
    limits: Limits,
    lease_deadline: Instant,
    profile: LockedTransportProfile,
}

impl ServerEndpoint {
    pub fn bind(
        authenticated: AuthenticatedConnection,
        policy: UdpBindPolicy,
        identity: &EphemeralIdentity,
        limits: Limits,
    ) -> Result<Self, Error> {
        require_tokio_runtime()?;
        limits.validate()?;
        let bound = bind_udp(authenticated.peer(), policy, &limits)?;
        let lease_deadline = Instant::now()
            .checked_add(limits.server_lease())
            .ok_or(Error::InvalidLimits(LimitViolation::DeadlineOverflow))?;
        let local_address = bound.local_addr();
        let provider = ring_provider();
        let rustls = locked_server_tls(identity, provider)?;
        let (server_config, profile) = locked_server_config(rustls, &limits)?;
        let accept_config = Arc::new(server_config.clone());
        let endpoint = endpoint_from_socket(bound, Some(server_config))?;
        Ok(Self {
            endpoint,
            local_address,
            authenticated,
            token: identity.token_owner(),
            accept_config,
            limits,
            lease_deadline,
            profile,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_address
    }

    pub fn profile(&self) -> &LockedTransportProfile {
        &self.profile
    }

    /// The immutable one-shot lease anchored when the endpoint was bound.
    pub fn lease_deadline(&self) -> Instant {
        self.lease_deadline
    }

    /// Close a bound endpoint that was never released for admission.
    pub async fn close(self) -> Result<(), Error> {
        close_endpoint(
            self.endpoint,
            self.limits.finalize_timeout(),
            b"server startup cancelled",
        )
        .await
    }

    pub async fn accept(self) -> Result<AdmittedStream, Error> {
        let cleanup = self.endpoint.clone();
        let finalize_timeout = self.limits.finalize_timeout();
        match self.accept_inner().await {
            Ok(admitted) => {
                drop(cleanup);
                Ok(admitted)
            }
            Err(first) => {
                let _ = close_endpoint(cleanup, finalize_timeout, b"server admission failed").await;
                Err(first)
            }
        }
    }

    pub(crate) async fn accept_for_role(self) -> Result<RoleAdmission, Error> {
        let cleanup = self.endpoint.clone();
        let finalize_timeout = self.limits.finalize_timeout();
        match self.accept_inner().await {
            Ok(admitted) => Ok(RoleAdmission {
                admitted,
                cleanup,
                finalize_timeout,
            }),
            Err(first) => {
                let _ = close_endpoint(cleanup, finalize_timeout, b"server admission failed").await;
                Err(first)
            }
        }
    }

    async fn accept_inner(self) -> Result<AdmittedStream, Error> {
        let Self {
            endpoint,
            authenticated,
            token,
            accept_config,
            limits,
            lease_deadline,
            ..
        } = self;
        let mut handshake_deadline = None;
        let mut retry_observed = false;
        let mut attempts = 0usize;

        loop {
            let deadline = handshake_deadline.unwrap_or(lease_deadline);
            let incoming = tokio::time::timeout_at(deadline, endpoint.accept())
                .await
                .map_err(|_| {
                    if handshake_deadline.is_some() {
                        Error::DeadlineExpired(DeadlinePhase::Handshake)
                    } else {
                        Error::LeaseExpired
                    }
                })?
                .ok_or(Error::EndpointClosed)?;
            if Instant::now() >= deadline {
                incoming.refuse();
                return Err(if handshake_deadline.is_some() {
                    Error::DeadlineExpired(DeadlinePhase::Handshake)
                } else {
                    Error::LeaseExpired
                });
            }

            if handshake_deadline.is_none() {
                let candidate = Instant::now()
                    .checked_add(limits.handshake_timeout())
                    .ok_or(Error::InvalidLimits(LimitViolation::DeadlineOverflow))?;
                handshake_deadline = Some(candidate.min(lease_deadline));
            }
            if attempts >= limits.max_retry_attempts {
                incoming.refuse();
                return Err(Error::RetryLimitExceeded);
            }
            attempts += 1;

            if !incoming.remote_address_validated() {
                incoming.retry().map_err(|_| Error::RetryFailed)?;
                retry_observed = true;
                continue;
            }
            if !retry_observed {
                incoming.refuse();
                return Err(Error::AddressNotValidated);
            }

            endpoint.set_server_config(None);
            let connecting = incoming
                .accept_with(accept_config)
                .map_err(|error| map_connection_error(&error))?;
            let absolute =
                handshake_deadline.ok_or(Error::InvalidLimits(LimitViolation::DeadlineOverflow))?;
            let connection = tokio::time::timeout_at(absolute, connecting)
                .await
                .map_err(|_| Error::DeadlineExpired(DeadlinePhase::Handshake))?
                .map_err(|error| map_connection_error(&error))?;
            ensure_deadline(absolute, DeadlinePhase::Handshake)?;
            return admission::admit_first_stream(
                endpoint,
                connection,
                token.as_ref(),
                authenticated,
                &limits,
                absolute,
                retry_observed,
            )
            .await;
        }
    }
}

impl std::fmt::Debug for ServerEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerEndpoint")
            .field("local_address", &self.local_address)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

pub(crate) struct RoleAdmission {
    admitted: AdmittedStream,
    cleanup: Endpoint,
    finalize_timeout: std::time::Duration,
}

impl RoleAdmission {
    pub(crate) async fn connect_target(self) -> Result<ConnectedTarget, Error> {
        let Self {
            admitted,
            cleanup,
            finalize_timeout,
        } = self;
        match admitted.connect_target().await {
            Ok(target) => {
                drop(cleanup);
                Ok(target)
            }
            Err(first) => {
                let _ = close_endpoint(cleanup, finalize_timeout, b"target connect failed").await;
                Err(first)
            }
        }
    }
}

impl std::fmt::Debug for RoleAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RoleAdmission { .. }")
    }
}

/// Pinned client endpoint bound through the same exact literal policy.
pub struct ClientEndpoint {
    endpoint: Endpoint,
    server_address: SocketAddr,
    limits: Limits,
    profile: LockedTransportProfile,
    pin_mismatch: PinMismatchState,
}

impl ClientEndpoint {
    pub fn bind(
        server_address: SocketAddr,
        policy: UdpBindPolicy,
        spki_sha256: [u8; 32],
        limits: Limits,
    ) -> Result<Self, Error> {
        require_tokio_runtime()?;
        limits.validate()?;
        validate_remote(server_address)?;
        let bound = bind_udp(server_address, policy, &limits)?;
        let provider = ring_provider();
        let (rustls, pin_mismatch) = locked_client_tls(spki_sha256, provider)?;
        let (client_config, profile) = locked_client_config(rustls, &limits)?;
        let endpoint = endpoint_from_socket(bound, None)?;
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint,
            server_address,
            limits,
            profile,
            pin_mismatch,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.endpoint.local_addr().map_err(Error::UdpBind)
    }

    pub fn profile(&self) -> &LockedTransportProfile {
        &self.profile
    }

    pub async fn connect_and_authenticate(
        self,
        token: &SecretToken,
        target_port: u16,
    ) -> Result<ClientSession, Error> {
        let cleanup = self.endpoint.clone();
        let finalize_timeout = self.limits.finalize_timeout();
        match self
            .connect_and_authenticate_inner(token, target_port)
            .await
        {
            Ok(session) => {
                drop(cleanup);
                Ok(session)
            }
            Err(first) => {
                let _ = close_endpoint(cleanup, finalize_timeout, b"client connect failed").await;
                Err(first)
            }
        }
    }

    async fn connect_and_authenticate_inner(
        self,
        token: &SecretToken,
        target_port: u16,
    ) -> Result<ClientSession, Error> {
        let limits = self.limits;
        let frame = try_encode_auth_frame(token, target_port, &limits)?;
        let mut transport = self.connect_transport().await?;
        tokio::time::timeout_at(transport.deadline, transport.send.write_all(frame.as_ref()))
            .await
            .map_err(|_| Error::DeadlineExpired(DeadlinePhase::ClientConnect))?
            .map_err(|_| Error::StreamWrite)?;
        ensure_deadline(transport.deadline, DeadlinePhase::ClientConnect)?;
        Ok(transport.into_session())
    }

    async fn connect_transport(self) -> Result<ClientTransport, Error> {
        let deadline = Instant::now()
            .checked_add(self.limits.handshake_timeout())
            .ok_or(Error::InvalidLimits(LimitViolation::DeadlineOverflow))?;
        let connecting = self
            .endpoint
            .connect(self.server_address, "localhost")
            .map_err(|_| Error::QuicConnect)?;
        let connection = tokio::time::timeout_at(deadline, connecting)
            .await
            .map_err(|_| {
                if self.pin_mismatch.observed() {
                    Error::PinMismatch
                } else {
                    Error::DeadlineExpired(DeadlinePhase::ClientConnect)
                }
            })?
            .map_err(|error| map_client_connection_error(&error, &self.pin_mismatch))?;
        ensure_deadline(deadline, DeadlinePhase::ClientConnect)?;
        let (send, recv) = tokio::time::timeout_at(deadline, connection.open_bi())
            .await
            .map_err(|_| Error::DeadlineExpired(DeadlinePhase::ClientConnect))?
            .map_err(|_| Error::StreamOpen)?;
        ensure_deadline(deadline, DeadlinePhase::ClientConnect)?;
        Ok(ClientTransport {
            endpoint: self.endpoint,
            connection,
            send,
            recv,
            deadline,
        })
    }
}

impl std::fmt::Debug for ClientEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientEndpoint")
            .field("server_address", &self.server_address)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

struct ClientTransport {
    endpoint: Endpoint,
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    deadline: Instant,
}

impl ClientTransport {
    fn into_session(self) -> ClientSession {
        ClientSession {
            endpoint: self.endpoint,
            connection: self.connection,
            send: self.send,
            recv: self.recv,
        }
    }
}

/// Client owner returned only after the auth prefix was written under the
/// original absolute connection deadline.
pub struct ClientSession {
    endpoint: Endpoint,
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
}

pub(crate) struct ClientSessionParts {
    pub(crate) endpoint: Endpoint,
    pub(crate) connection: Connection,
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
}

impl ClientSession {
    pub fn quic_send_mut(&mut self) -> &mut SendStream {
        &mut self.send
    }

    pub fn quic_recv_mut(&mut self) -> &mut RecvStream {
        &mut self.recv
    }

    pub(crate) fn into_parts(self) -> ClientSessionParts {
        let Self {
            endpoint,
            connection,
            send,
            recv,
        } = self;
        ClientSessionParts {
            endpoint,
            connection,
            send,
            recv,
        }
    }

    pub async fn close(self) {
        let Self {
            endpoint,
            connection,
            send,
            recv,
        } = self;
        connection.close(CLOSE_CODE, b"slice1 client complete");
        drop(send);
        drop(recv);
        drop(connection);
        endpoint.close(CLOSE_CODE, b"slice1 client complete");
        endpoint.wait_idle().await;
    }
}

impl std::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientSession { .. }")
    }
}

async fn close_endpoint(
    endpoint: Endpoint,
    timeout: std::time::Duration,
    reason: &'static [u8],
) -> Result<(), Error> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(Error::InvalidLimits(LimitViolation::DeadlineOverflow))?;
    endpoint.set_server_config(None);
    endpoint.close(CLOSE_CODE, reason);
    tokio::time::timeout_at(deadline, endpoint.wait_idle())
        .await
        .map_err(|_| Error::DeadlineExpired(DeadlinePhase::Finalize))?;
    Ok(())
}

fn require_tokio_runtime() -> Result<(), Error> {
    tokio::runtime::Handle::try_current()
        .map(|_| ())
        .map_err(|_| Error::RuntimeUnavailable)
}

fn ensure_deadline(deadline: Instant, phase: DeadlinePhase) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::DeadlineExpired(phase))
    } else {
        Ok(())
    }
}

fn map_connection_error(error: &ConnectionError) -> Error {
    if let ConnectionError::TransportError(transport) = error {
        if let Some(crypto) = &transport.crypto {
            if let Some(noq::rustls::Error::InvalidCertificate(
                noq::rustls::CertificateError::Other(other),
            )) = crypto.downcast_ref::<noq::rustls::Error>()
            {
                if other.0.downcast_ref::<PinMismatchMarker>().is_some() {
                    return Error::PinMismatch;
                }
            }
        }
    }
    Error::QuicConnection
}

fn map_client_connection_error(error: &ConnectionError, mismatch: &PinMismatchState) -> Error {
    if mismatch.observed() {
        Error::PinMismatch
    } else {
        map_connection_error(error)
    }
}

fn endpoint_from_socket(
    bound: BoundUdp,
    server_config: Option<ServerConfig>,
) -> Result<Endpoint, Error> {
    let expected = bound.local_addr();
    let socket = bound.into_socket();
    socket.set_nonblocking(true).map_err(Error::UdpBind)?;
    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        server_config,
        socket,
        Arc::new(TokioRuntime),
    )
    .map_err(Error::UdpBind)?;
    let actual = endpoint.local_addr().map_err(Error::UdpBind)?;
    if actual != expected {
        endpoint.close(CLOSE_CODE, b"exact bind mismatch");
        return Err(Error::InvalidUdpPolicy(
            UdpPolicyViolation::ExactBindMismatch,
        ));
    }
    Ok(endpoint)
}

fn ring_provider() -> Arc<CryptoProvider> {
    Arc::new(noq::rustls::crypto::ring::default_provider())
}

#[derive(Clone)]
struct SingleCertResolver(Arc<CertifiedKey>);

impl std::fmt::Debug for SingleCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SingleCertResolver(<REDACTED>)")
    }
}

impl ResolvesServerCert for SingleCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn locked_server_tls(
    identity: &EphemeralIdentity,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<RustlsServerConfig>, Error> {
    let mut config = RustlsServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&noq::rustls::version::TLS13])
        .map_err(|_| Error::TlsConfiguration)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertResolver(identity.certified_key())));
    config.alpn_protocols = ALPN.iter().map(|protocol| protocol.to_vec()).collect();
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    config.send_tls13_tickets = 0;
    config.max_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(Arc::new(config))
}

fn locked_client_tls(
    spki_sha256: [u8; 32],
    provider: Arc<CryptoProvider>,
) -> Result<(Arc<RustlsClientConfig>, PinMismatchState), Error> {
    let (verifier, mismatch) = SpkiPinVerifier::tracked(spki_sha256, provider.clone());
    let mut config = RustlsClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&noq::rustls::version::TLS13])
        .map_err(|_| Error::TlsConfiguration)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = ALPN.iter().map(|protocol| protocol.to_vec()).collect();
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok((Arc::new(config), mismatch))
}

fn locked_server_config(
    rustls: Arc<RustlsServerConfig>,
    limits: &Limits,
) -> Result<(ServerConfig, LockedTransportProfile), Error> {
    let crypto = QuicServerConfig::try_from(rustls).map_err(|_| Error::TlsConfiguration)?;
    let (transport, profile) = locked_transport(Side::Server, limits)?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport);
    config.max_incoming(limits.max_pending_handshakes);
    config.incoming_buffer_size(limits.incoming_buffer_size);
    config.incoming_buffer_size_total(limits.incoming_buffer_total()?);
    config.migration(true);
    config.preferred_address_v4(None);
    config.preferred_address_v6(None);
    config.retry_token_lifetime(limits.handshake_timeout());
    let mut validation_tokens = noq::ValidationTokenConfig::default();
    validation_tokens.sent(0);
    validation_tokens.log(Arc::new(NoneTokenLog));
    config.validation_token_config(validation_tokens);
    Ok((config, profile))
}

fn locked_client_config(
    rustls: Arc<RustlsClientConfig>,
    limits: &Limits,
) -> Result<(ClientConfig, LockedTransportProfile), Error> {
    let crypto = QuicClientConfig::try_from(rustls).map_err(|_| Error::TlsConfiguration)?;
    let (transport, profile) = locked_transport(Side::Client, limits)?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport);
    config.token_store(Arc::new(NoneTokenStore));
    Ok((config, profile))
}

#[derive(Clone, Copy)]
enum Side {
    Server,
    Client,
}

fn locked_transport(
    side: Side,
    limits: &Limits,
) -> Result<(Arc<TransportConfig>, LockedTransportProfile), Error> {
    limits.validate()?;
    let receive_window = VarInt::from_u64(limits.receive_window)
        .map_err(|_| Error::InvalidLimits(LimitViolation::WindowTooLarge))?;
    let idle_timeout = IdleTimeout::try_from(limits.idle_timeout())
        .map_err(|_| Error::InvalidLimits(LimitViolation::DeadlineOverflow))?;
    let incoming_bidi = match side {
        Side::Server => VarInt::from_u32(1),
        Side::Client => VarInt::from_u32(0),
    };
    let mut config = TransportConfig::default();
    config.max_concurrent_bidi_streams(incoming_bidi);
    config.max_concurrent_uni_streams(VarInt::from_u32(0));
    config.receive_window(receive_window);
    config.stream_receive_window(receive_window);
    config.send_window(limits.send_window);
    config.max_idle_timeout(Some(idle_timeout));
    config.datagram_receive_buffer_size(None);
    config.datagram_send_buffer_size(0);
    config.send_observed_address_reports(false);
    config.receive_observed_address_reports(false);
    config.max_concurrent_multipath_paths(0);
    config.max_remote_nat_traversal_addresses(0);
    config.server_handshake_migration(false);

    let profile = LockedTransportProfile {
        tls13_only: true,
        alpn: ALPN[0],
        client_resumption: false,
        early_data: false,
        server_half_rtt_data: false,
        tls13_tickets: 0,
        requested_tls13_tickets: 0,
        new_tokens: false,
        preferred_addresses: false,
        server_incoming_bidi: 1,
        client_incoming_bidi: 0,
        incoming_uni: 0,
        datagrams: false,
        address_discovery: false,
        multipath: false,
        nat_traversal: false,
        handshake_migration: false,
        standard_migration: true,
        max_incoming: limits.max_pending_handshakes,
        incoming_buffer_size: limits.incoming_buffer_size,
        incoming_buffer_size_total: limits.incoming_buffer_total()?,
        send_window: limits.send_window,
        receive_window: limits.receive_window,
        idle_timeout_ms: limits.idle_timeout_ms,
    };
    Ok((Arc::new(config), profile))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::bootstrap::AUTH_FRAME_LEN;
    use std::io::ErrorKind;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpSocket};
    use tokio::sync::Mutex;

    static SOCKET_TEST_LOCK: Mutex<()> = Mutex::const_new(());

    fn free_udp_v4() -> SocketAddr {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap_or_else(|error| panic!("cannot reserve a test UDP endpoint: {error}"));
        socket
            .local_addr()
            .unwrap_or_else(|error| panic!("cannot inspect a test UDP endpoint: {error}"))
    }

    async fn loopback_listener() -> TcpListener {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("cannot create a target listener: {error}"))
    }

    fn test_limits(handshake_timeout_ms: u64) -> Limits {
        Limits {
            handshake_timeout_ms,
            server_lease_ms: handshake_timeout_ms.saturating_mul(4),
            idle_timeout_ms: handshake_timeout_ms.saturating_mul(4),
            ..Limits::default()
        }
    }

    fn bind_pair(
        identity: &EphemeralIdentity,
        authenticated: AuthenticatedConnection,
        pin: [u8; 32],
        limits: Limits,
    ) -> (ServerEndpoint, ClientEndpoint) {
        let server_address = free_udp_v4();
        let server = ServerEndpoint::bind(
            authenticated,
            UdpBindPolicy::Explicit(server_address),
            identity,
            limits,
        )
        .unwrap_or_else(|error| panic!("cannot bind test server: {error}"));
        let client_address = free_udp_v4();
        let client = ClientEndpoint::bind(
            server.local_addr(),
            UdpBindPolicy::Explicit(client_address),
            pin,
            limits,
        )
        .unwrap_or_else(|error| panic!("cannot bind test client: {error}"));
        (server, client)
    }

    async fn assert_listener_idle(listener: &TcpListener) {
        match tokio::time::timeout(Duration::from_millis(40), listener.accept()).await {
            Err(_) => {}
            Ok(Ok(_)) => panic!("target accepted a connection before admission"),
            Ok(Err(error)) => panic!("target listener failed: {error}"),
        }
    }

    async fn assert_udp_released(address: SocketAddr) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match UdpSocket::bind(address) {
                Ok(socket) => {
                    drop(socket);
                    return;
                }
                Err(error) if error.kind() == ErrorKind::AddrInUse && Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) if error.kind() == ErrorKind::AddrInUse => {
                    panic!("UDP endpoint remained bound after its cleanup deadline")
                }
                Err(error) => panic!("cannot verify released UDP endpoint: {error}"),
            }
        }
    }

    async fn close_client(result: Result<ClientSession, Error>) {
        if let Ok(session) = result {
            let closed = tokio::time::timeout(Duration::from_secs(1), session.close()).await;
            assert!(closed.is_ok(), "client endpoint did not become idle");
        }
    }

    async fn write_at_deadline(transport: &mut ClientTransport, bytes: &[u8]) -> Result<(), Error> {
        tokio::time::timeout_at(transport.deadline, transport.send.write_all(bytes))
            .await
            .map_err(|_| Error::DeadlineExpired(DeadlinePhase::ClientConnect))?
            .map_err(|_| Error::StreamWrite)
    }

    async fn authenticate_incrementally(
        client: ClientEndpoint,
        token: &SecretToken,
        target_port: u16,
        suffix: &[u8],
    ) -> Result<ClientSession, Error> {
        let frame = try_encode_auth_frame(token, target_port, &client.limits)?;
        let mut transport = client.connect_transport().await?;
        for chunk in frame.as_ref().chunks(3) {
            write_at_deadline(&mut transport, chunk).await?;
            tokio::task::yield_now().await;
        }
        write_at_deadline(&mut transport, suffix).await?;
        Ok(transport.into_session())
    }

    #[test]
    fn locked_configuration_has_no_implicit_capabilities() {
        let limits = Limits::default();
        let identity = EphemeralIdentity::generate().unwrap();
        let server_tls = locked_server_tls(&identity, ring_provider()).unwrap();
        assert_eq!(server_tls.alpn_protocols, vec![b"eversh-link/1".to_vec()]);
        assert_eq!(server_tls.max_early_data_size, 0);
        assert!(!server_tls.send_half_rtt_data);
        assert_eq!(server_tls.send_tls13_tickets, 0);
        assert_eq!(server_tls.max_tls13_tickets, 0);
        assert!(!server_tls.session_storage.can_cache());

        let (client_tls, pin_mismatch) =
            locked_client_tls(identity.spki_sha256(), ring_provider()).unwrap();
        assert!(!pin_mismatch.observed());
        assert_eq!(client_tls.alpn_protocols, vec![b"eversh-link/1".to_vec()]);
        assert!(client_tls.check_selected_alpn);
        assert!(!client_tls.enable_early_data);

        let (_, server) = locked_server_config(server_tls, &limits).unwrap();
        let (_, client) = locked_client_config(client_tls, &limits).unwrap();
        assert_eq!(server, client);
        assert!(server.tls13_only);
        assert_eq!(server.alpn, b"eversh-link/1");
        assert!(!server.client_resumption);
        assert!(!server.early_data);
        assert!(!server.server_half_rtt_data);
        assert_eq!(server.tls13_tickets, 0);
        assert_eq!(server.requested_tls13_tickets, 0);
        assert!(!server.new_tokens);
        assert!(!server.preferred_addresses);
        assert_eq!(server.server_incoming_bidi, 1);
        assert_eq!(server.client_incoming_bidi, 0);
        assert_eq!(server.incoming_uni, 0);
        assert!(!server.datagrams);
        assert!(!server.address_discovery);
        assert!(!server.multipath);
        assert!(!server.nat_traversal);
        assert!(!server.handshake_migration);
        assert!(server.standard_migration);
        assert_eq!(server.max_incoming, limits.max_pending_handshakes);
        assert_eq!(server.incoming_buffer_size, limits.incoming_buffer_size);
        assert_eq!(
            server.incoming_buffer_size_total,
            limits.incoming_buffer_total().unwrap()
        );
        assert!(server.send_window > 0);
        assert!(server.receive_window > 0);
        assert!(server.idle_timeout_ms > 0);
    }

    #[test]
    fn invalid_caps_fail_before_transport_allocation() {
        let limits = Limits {
            incoming_buffer_size: u64::MAX,
            ..Limits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(Error::InvalidLimits(LimitViolation::IncomingTotalOverflow))
        ));

        let limits = Limits {
            max_pending_handshakes: 0,
            ..Limits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(Error::InvalidLimits(LimitViolation::ZeroValue))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn kernel_route_probe_is_family_exact_before_loopback_policy_rejection() {
        let _socket_guard = SOCKET_TEST_LOCK.lock().await;
        assert!(matches!(
            bind_udp(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
                UdpBindPolicy::RouteSelected,
                &Limits::default()
            ),
            Err(Error::InvalidUdpPolicy(
                UdpPolicyViolation::PeerLoopbackRequiresExplicit
            ))
        ));

        let v4 = kernel_selected_source(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)))
            .unwrap_or_else(|error| panic!("IPv4 kernel route probe failed: {error}"));
        assert!(v4.is_ipv4());
        assert_eq!(v4.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        let explicit_address = free_udp_v4();
        let bound = bind_udp(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
            UdpBindPolicy::Explicit(explicit_address),
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(bound.local_addr(), explicit_address);
        drop(bound);

        let v6 = kernel_selected_source(SocketAddr::from((Ipv6Addr::LOCALHOST, 9)))
            .unwrap_or_else(|error| panic!("IPv6 kernel route probe failed: {error}"));
        assert!(v6.is_ipv6());
        assert_eq!(v6.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));

        let explicit_v6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let explicit_v6_address = explicit_v6.local_addr().unwrap();
        drop(explicit_v6);
        let bound_v6 = bind_udp(
            SocketAddr::from((Ipv6Addr::LOCALHOST, 9)),
            UdpBindPolicy::Explicit(explicit_v6_address),
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(bound_v6.local_addr(), explicit_v6_address);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn public_route_policies_bind_selected_address_and_release() {
        let _socket_guard = SOCKET_TEST_LOCK.lock().await;
        let limits = Limits::default();
        let peer = SocketAddr::from(([192, 0, 2, 1], 9));
        let selected = kernel_selected_source(peer)
            .unwrap_or_else(|error| panic!("kernel route selection failed: {error}"));
        assert!(selected.is_ipv4());
        assert!(!selected.ip().is_loopback());

        let ephemeral = bind_udp(peer, UdpBindPolicy::RouteSelected, &limits)
            .unwrap_or_else(|error| panic!("public route-selected bind failed: {error}"));
        let ephemeral_address = ephemeral.local_addr();
        assert_eq!(ephemeral_address.ip(), selected.ip());
        assert!(ephemeral_address.is_ipv4());
        assert_ne!(ephemeral_address.port(), 0);
        drop(ephemeral);
        assert_udp_released(ephemeral_address).await;

        let reservation = UdpSocket::bind(with_port(selected, 0))
            .unwrap_or_else(|error| panic!("cannot reserve a route-selected range port: {error}"));
        let range_port = reservation
            .local_addr()
            .unwrap_or_else(|error| panic!("cannot inspect a reserved range port: {error}"))
            .port();
        drop(reservation);

        let ranged = bind_udp(
            peer,
            UdpBindPolicy::RouteSelectedPortRange {
                start: range_port,
                end: range_port,
            },
            &limits,
        )
        .unwrap_or_else(|error| panic!("public route-selected range bind failed: {error}"));
        let ranged_address = ranged.local_addr();
        assert_eq!(ranged_address.ip(), selected.ip());
        assert!(ranged_address.is_ipv4());
        assert_eq!(ranged_address.port(), range_port);
        drop(ranged);
        assert_udp_released(ranged_address).await;
    }

    #[test]
    fn range_binding_distinguishes_bind_failure_from_exhaustion() {
        let limits = Limits::default();
        let selected = SocketAddr::from(([192, 0, 2, 10], 1));
        let start = 40_000;
        let end = 40_002;

        let mut denied_attempts = Vec::new();
        let denied = bind_route_selected_with(
            selected,
            Some((start, end)),
            &limits,
            |requested, ephemeral| {
                assert!(!ephemeral);
                denied_attempts.push(requested);
                Err(BindFailure::Io(std::io::Error::new(
                    ErrorKind::PermissionDenied,
                    "injected bind denial",
                )))
            },
        );
        match denied {
            Err(Error::UdpBind(source)) => {
                assert_eq!(source.kind(), ErrorKind::PermissionDenied);
                assert_eq!(source.to_string(), "injected bind denial");
            }
            outcome => panic!("unexpected non-retryable bind outcome: {outcome:?}"),
        }
        assert_eq!(denied_attempts, [with_port(selected, start)]);

        let mut occupied_attempts = Vec::new();
        let exhausted = bind_route_selected_with(
            selected,
            Some((start, end)),
            &limits,
            |requested, ephemeral| {
                assert!(!ephemeral);
                occupied_attempts.push(requested);
                Err(BindFailure::AddressInUse(std::io::Error::new(
                    ErrorKind::AddrInUse,
                    "injected occupied port",
                )))
            },
        );
        assert!(matches!(exhausted, Err(Error::PortRangeExhausted)));
        let expected = (start..=end)
            .map(|port| with_port(selected, port))
            .collect::<Vec<_>>();
        assert_eq!(occupied_attempts, expected);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn range_validation_and_exhaustion_are_finite() {
        let _socket_guard = SOCKET_TEST_LOCK.lock().await;
        let limits = Limits::default();
        assert!(validate_range(0, 1, &limits).is_err());
        assert!(validate_range(20, 19, &limits).is_err());
        assert!(validate_range(1, limits.max_udp_port_span as u16 + 1, &limits).is_err());

        let peer = SocketAddr::from(([192, 0, 2, 1], 22));
        assert!(matches!(
            bind_udp(
                peer,
                UdpBindPolicy::RouteSelectedPortRange { start: 0, end: 1 },
                &limits
            ),
            Err(Error::InvalidUdpPolicy(
                UdpPolicyViolation::RangeStartsAtZero
            ))
        ));
        assert!(matches!(
            bind_udp(
                peer,
                UdpBindPolicy::Explicit(SocketAddr::from((Ipv6Addr::LOCALHOST, 9))),
                &limits
            ),
            Err(Error::InvalidUdpPolicy(
                UdpPolicyViolation::ExplicitFamilyMismatch
            ))
        ));
        assert!(matches!(
            bind_udp(
                peer,
                UdpBindPolicy::Explicit(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
                &limits
            ),
            Err(Error::InvalidUdpPolicy(
                UdpPolicyViolation::ExplicitPortZero
            ))
        ));
        assert!(matches!(
            bind_udp(
                peer,
                UdpBindPolicy::Explicit(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9))),
                &limits
            ),
            Err(Error::InvalidEndpoint(
                EndpointViolation::UnspecifiedAddress
            ))
        ));
        assert!(matches!(
            bind_udp(
                peer,
                UdpBindPolicy::Explicit(SocketAddr::from(([224, 0, 0, 1], 9))),
                &limits
            ),
            Err(Error::InvalidEndpoint(EndpointViolation::MulticastAddress))
        ));

        let occupied = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap_or_else(|error| panic!("cannot reserve occupied UDP endpoint: {error}"));
        let port = occupied.local_addr().unwrap().port();
        assert!(matches!(
            bind_udp(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
                UdpBindPolicy::Explicit(occupied.local_addr().unwrap()),
                &limits
            ),
            Err(Error::UdpBind(_))
        ));
        let selected = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        assert!(matches!(
            bind_route_selected(selected, Some((port, port)), &limits),
            Err(Error::PortRangeExhausted)
        ));
        drop(occupied);
        assert!(bind_route_selected(selected, Some((port, port)), &limits).is_ok());
        assert!(UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_noq_retry_stream_lock_and_exact_target_once() {
        let _socket_guard = SOCKET_TEST_LOCK.lock().await;
        const SUFFIX: &[u8] = b"post-prefix";
        let listener = loopback_listener().await;
        let target_address = listener.local_addr().unwrap();
        let authenticated = AuthenticatedConnection::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 2222)),
            target_address,
        )
        .unwrap();
        let limits = test_limits(1_500);
        let identity = EphemeralIdentity::generate().unwrap();
        let token = identity.take_bootstrap_token().unwrap();
        let (server, client) = bind_pair(&identity, authenticated, identity.spki_sha256(), limits);
        let server_address = server.local_addr();
        let client_address = client.local_addr().unwrap();
        assert_eq!(server.profile(), client.profile());

        let second_client_address = free_udp_v4();
        let second_client = ClientEndpoint::bind(
            server.local_addr(),
            UdpBindPolicy::Explicit(second_client_address),
            identity.spki_sha256(),
            limits,
        )
        .unwrap();

        let (server_result, client_result) = tokio::join!(
            server.accept(),
            authenticate_incrementally(client, &token, target_address.port(), SUFFIX)
        );
        let admitted = server_result.unwrap();
        let client_session = client_result.unwrap();
        assert!(admitted.retry_observed());
        assert_eq!(admitted.authorized_target_addr(), target_address);
        assert_listener_idle(&listener).await;

        let extra_client_stream = tokio::time::timeout(
            Duration::from_millis(40),
            client_session.connection.open_bi(),
        )
        .await;
        assert!(!matches!(extra_client_stream, Ok(Ok(_))));
        let server_opened_stream = tokio::time::timeout(
            Duration::from_millis(40),
            admitted.connection_for_test().open_bi(),
        )
        .await;
        assert!(!matches!(server_opened_stream, Ok(Ok(_))));

        let second_connection = tokio::time::timeout(
            Duration::from_millis(300),
            second_client.connect_and_authenticate(&token, target_address.port()),
        )
        .await;
        if let Ok(Ok(session)) = second_connection {
            close_client(Ok(session)).await;
            panic!("one-shot endpoint accepted a second connection");
        }
        assert_listener_idle(&listener).await;

        let mut connected = admitted.connect_target().await.unwrap();
        let (mut accepted, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(connected.target_address(), target_address);
        assert_eq!(accepted.local_addr().unwrap(), target_address);
        let mut suffix = [0; SUFFIX.len()];
        connected
            .quic_recv_mut()
            .read_exact(&mut suffix)
            .await
            .unwrap();
        assert_eq!(&suffix, SUFFIX);
        assert_listener_idle(&listener).await;

        let (server_closed, ()) = tokio::join!(connected.close(), client_session.close());
        server_closed.unwrap();
        let mut target_eof = [0; 1];
        let target_read =
            tokio::time::timeout(Duration::from_secs(1), accepted.read(&mut target_eof))
                .await
                .expect("target TCP close did not become observable")
                .expect("target TCP close produced a read error");
        assert_eq!(target_read, 0, "target TCP remained open after close");
        drop(accepted);
        assert_udp_released(server_address).await;
        assert_udp_released(client_address).await;
        assert_udp_released(second_client_address).await;

        let (reuse_server, reuse_client) =
            bind_pair(&identity, authenticated, identity.spki_sha256(), limits);
        let (reuse_result, reuse_client_result) = tokio::join!(
            reuse_server.accept(),
            reuse_client.connect_and_authenticate(&token, target_address.port())
        );
        assert!(matches!(reuse_result, Err(Error::TokenReuse)));
        assert_listener_idle(&listener).await;
        close_client(reuse_client_result).await;
    }

    #[derive(Clone, Copy)]
    enum InvalidAuthentication {
        WrongVersion,
        WrongToken,
        WrongSelector,
        Truncated,
        TrickledPastDeadline,
    }

    async fn exercise_invalid_authentication(case: InvalidAuthentication) {
        let listener = loopback_listener().await;
        let target_address = listener.local_addr().unwrap();
        let authenticated = AuthenticatedConnection::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 2222)),
            target_address,
        )
        .unwrap();
        let limits = test_limits(1_500);
        let identity = EphemeralIdentity::generate().unwrap();
        let token = identity.take_bootstrap_token().unwrap();
        let (server, client) = bind_pair(&identity, authenticated, identity.spki_sha256(), limits);

        let client_future = async {
            match case {
                InvalidAuthentication::WrongToken => {
                    let mut wrong_bytes = *token.as_bytes();
                    wrong_bytes[0] ^= 0xff;
                    let wrong = SecretToken::from_bytes(wrong_bytes);
                    client
                        .connect_and_authenticate(&wrong, target_address.port())
                        .await
                }
                InvalidAuthentication::WrongSelector => {
                    let wrong_port = if target_address.port() == u16::MAX {
                        target_address.port() - 1
                    } else {
                        target_address.port() + 1
                    };
                    client.connect_and_authenticate(&token, wrong_port).await
                }
                InvalidAuthentication::WrongVersion
                | InvalidAuthentication::Truncated
                | InvalidAuthentication::TrickledPastDeadline => {
                    let frame = try_encode_auth_frame(&token, target_address.port(), &limits)?;
                    let mut bytes = frame.as_ref().to_vec();
                    if matches!(case, InvalidAuthentication::WrongVersion) {
                        bytes[0] = 2;
                    }
                    let mut transport = client.connect_transport().await?;
                    match case {
                        InvalidAuthentication::WrongVersion => {
                            write_at_deadline(&mut transport, &bytes).await?;
                        }
                        InvalidAuthentication::Truncated => {
                            write_at_deadline(&mut transport, &bytes[..12]).await?;
                            transport.send.finish().map_err(|_| Error::StreamWrite)?;
                        }
                        InvalidAuthentication::TrickledPastDeadline => {
                            for byte in bytes.iter().take(AUTH_FRAME_LEN) {
                                if transport
                                    .send
                                    .write_all(std::slice::from_ref(byte))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(45)).await;
                            }
                        }
                        InvalidAuthentication::WrongToken
                        | InvalidAuthentication::WrongSelector => unreachable!(),
                    }
                    Ok(transport.into_session())
                }
            }
        };

        let started = Instant::now();
        let (server_result, client_result) = tokio::join!(server.accept(), client_future);
        match case {
            InvalidAuthentication::WrongVersion => {
                assert!(
                    matches!(&server_result, Err(Error::VersionUnsupported)),
                    "unexpected wrong-version result: {server_result:?}"
                );
            }
            InvalidAuthentication::WrongToken => {
                assert!(matches!(server_result, Err(Error::AuthRejected)));
            }
            InvalidAuthentication::WrongSelector => {
                assert!(matches!(server_result, Err(Error::TargetUnauthorized)));
            }
            InvalidAuthentication::Truncated => {
                assert!(matches!(server_result, Err(Error::AuthRejected)));
            }
            InvalidAuthentication::TrickledPastDeadline => {
                assert!(
                    matches!(
                        &server_result,
                        Err(Error::DeadlineExpired(DeadlinePhase::Authentication))
                    ),
                    "unexpected trickle result: {server_result:?}"
                );
                assert!(started.elapsed() < Duration::from_secs(3));
            }
        }
        assert_listener_idle(&listener).await;
        close_client(client_result).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_noq_pre_admission_failures_never_open_target() {
        let _socket_guard = SOCKET_TEST_LOCK.lock().await;
        for case in [
            InvalidAuthentication::WrongVersion,
            InvalidAuthentication::WrongToken,
            InvalidAuthentication::WrongSelector,
            InvalidAuthentication::Truncated,
            InvalidAuthentication::TrickledPastDeadline,
        ] {
            exercise_invalid_authentication(case).await;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_noq_wrong_pin_is_typed_and_opens_no_target() {
        let _socket_guard = SOCKET_TEST_LOCK.lock().await;
        let listener = loopback_listener().await;
        let target_address = listener.local_addr().unwrap();
        let authenticated = AuthenticatedConnection::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 2222)),
            target_address,
        )
        .unwrap();
        let limits = test_limits(1_500);
        let identity = EphemeralIdentity::generate().unwrap();
        let token = identity.take_bootstrap_token().unwrap();
        let mut wrong_pin = identity.spki_sha256();
        wrong_pin[0] ^= 0xff;
        let (server, client) = bind_pair(&identity, authenticated, wrong_pin, limits);
        let (server_result, client_result) = tokio::join!(
            server.accept(),
            client.connect_and_authenticate(&token, target_address.port())
        );
        assert!(server_result.is_err());
        assert!(
            matches!(&client_result, Err(Error::PinMismatch)),
            "unexpected wrong-pin client result: {client_result:?}"
        );
        assert_listener_idle(&listener).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bind_anchored_lease_expiry_closes_endpoint_without_target_access() {
        let _socket_guard = SOCKET_TEST_LOCK.lock().await;
        let listener = loopback_listener().await;
        let target_address = listener.local_addr().unwrap();
        let authenticated = AuthenticatedConnection::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 2222)),
            target_address,
        )
        .unwrap();
        let identity = EphemeralIdentity::generate().unwrap();
        let limits = Limits {
            server_lease_ms: 50,
            handshake_timeout_ms: 40,
            finalize_timeout_ms: 500,
            ..Limits::default()
        };
        let server_address = free_udp_v4();
        let server = ServerEndpoint::bind(
            authenticated,
            UdpBindPolicy::Explicit(server_address),
            &identity,
            limits,
        )
        .unwrap();
        let started = Instant::now();
        assert!(matches!(server.accept().await, Err(Error::LeaseExpired)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_listener_idle(&listener).await;
        assert_udp_released(server_address).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn endpoint_close_and_target_connector_failure_are_bounded() {
        let _socket_guard = SOCKET_TEST_LOCK.lock().await;
        let guard_listener = loopback_listener().await;
        let identity = EphemeralIdentity::generate().unwrap();
        let token = identity.take_bootstrap_token().unwrap();
        let limits = test_limits(1_500);

        let closed_socket = TcpSocket::new_v4()
            .unwrap_or_else(|error| panic!("cannot create closed target socket: {error}"));
        closed_socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let closed_target = closed_socket.local_addr().unwrap();
        let authenticated = AuthenticatedConnection::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 2222)),
            closed_target,
        )
        .unwrap();
        let (server, client) = bind_pair(&identity, authenticated, identity.spki_sha256(), limits);
        let (server_result, client_result) = tokio::join!(
            server.accept(),
            client.connect_and_authenticate(&token, closed_target.port())
        );
        let admitted = server_result.unwrap();
        assert_listener_idle(&guard_listener).await;
        assert!(matches!(
            admitted.connect_target().await,
            Err(Error::TargetConnect(_))
        ));
        assert_listener_idle(&guard_listener).await;
        close_client(client_result).await;

        let fresh_identity = EphemeralIdentity::generate().unwrap();
        let fresh_token = fresh_identity.take_bootstrap_token().unwrap();
        let (closed_server, closed_client) = bind_pair(
            &fresh_identity,
            authenticated,
            fresh_identity.spki_sha256(),
            limits,
        );
        let closed_server_address = closed_server.local_addr();
        let closed_client_address = closed_client.local_addr().unwrap();
        closed_server
            .endpoint
            .close(CLOSE_CODE, b"test endpoint close");
        closed_server.endpoint.set_server_config(None);
        let closed_result = closed_server.accept().await;
        assert!(matches!(closed_result, Err(Error::EndpointClosed)));
        drop(closed_client);
        drop(fresh_token);
        assert_listener_idle(&guard_listener).await;
        assert_udp_released(closed_server_address).await;
        assert_udp_released(closed_client_address).await;
    }
}
