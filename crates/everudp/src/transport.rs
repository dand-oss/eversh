//! Locked noq/rustls transport and first-connection admission.

use crate::admission::{AdmissionError, InvitationStore};
use crate::association::AssociationAuthorization;
use crate::handshake::{ClientHello, HandshakeError};
use crate::identity::{ClientIdentity, GatewayIdentity};
use crate::limits::Limits;
use crate::wire::ALPN;
use crate::wire::{decode_record, encode_record, Kind, StreamRole, HEADER_LEN};
use crate::{LimitViolation, WireError};
use everssh::bootstrap::sha256;
use everssh::pinning::{extract_spki, PinMismatchState, SpkiPinVerifier};
use everssh::transport::{bind_udp, RouteIdentity, UdpBindPolicy};
use noq::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use noq::rustls::client::{ResolvesClientCert, Resumption};
use noq::rustls::crypto::CryptoProvider;
use noq::rustls::pki_types::CertificateDer;
use noq::rustls::server::{
    ClientHello as RustlsClientHello, NoServerSessionStorage, ResolvesServerCert,
};
use noq::rustls::sign::CertifiedKey;
use noq::rustls::{ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig};
use noq::{
    AckFrequencyConfig, ClientConfig, Connection, ConnectionError, Endpoint, EndpointConfig,
    IdleTimeout, NoneTokenLog, NoneTokenStore, RecvStream, SendStream, ServerConfig, TokioRuntime,
    TransportConfig, VarInt,
};
use std::fmt;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CLOSE_CODE: VarInt = VarInt::from_u32(0x4555);
pub(crate) const WRITER_BUSY_CLOSE_CODE: VarInt = VarInt::from_u32(0x4557);
pub(crate) const ASSOCIATION_CAPACITY_CLOSE_CODE: VarInt = VarInt::from_u32(0x4558);
const MAX_INCOMING: usize = 8;
const INCOMING_BUFFER_SIZE: u64 = 64 * 1024;
const INCOMING_BUFFER_TOTAL: u64 = MAX_INCOMING as u64 * INCOMING_BUFFER_SIZE;
const MAX_CONTROL_WIRE: usize = 4 * 1024 + HEADER_LEN;
const FAST_DATAGRAM_BUFFER_BYTES: usize = 64 * 1024;
pub(crate) const CONTROL_STREAM_PRIORITY: i32 = 2;
pub(crate) const INPUT_STREAM_PRIORITY: i32 = 1;
pub(crate) const OUTPUT_STREAM_PRIORITY: i32 = 0;
#[cfg(feature = "stream-floor")]
pub const STREAM_FLOOR_ALPN: &[u8] = b"everudp-stream-floor/1";

pub type SharedInvitationStore = Arc<Mutex<InvitationStore>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicAckPolicy {
    Disabled,
    EveryPacket1ms,
    EveryOtherPacket5ms,
    EveryOtherPacket1ms,
}

#[cfg(feature = "tuning")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevelopmentTransportTuning {
    initial_rtt_ms: u64,
    ack_policy: QuicAckPolicy,
    segmentation_offload: bool,
}

#[cfg(feature = "tuning")]
impl DevelopmentTransportTuning {
    pub const PREREGISTERED_DEFAULT: Self = Self {
        initial_rtt_ms: 100,
        ack_policy: QuicAckPolicy::EveryPacket1ms,
        segmentation_offload: false,
    };

    pub const fn new(
        initial_rtt_ms: u64,
        ack_policy: QuicAckPolicy,
        segmentation_offload: bool,
    ) -> Option<Self> {
        if !matches!(initial_rtt_ms, 25 | 100 | 333)
            || matches!(ack_policy, QuicAckPolicy::EveryOtherPacket1ms)
        {
            return None;
        }
        Some(Self {
            initial_rtt_ms,
            ack_policy,
            segmentation_offload,
        })
    }

    pub const fn matrix() -> [Self; 18] {
        let mut profiles = [Self::PREREGISTERED_DEFAULT; 18];
        let rtts = [25, 100, 333];
        let acknowledgements = [
            QuicAckPolicy::Disabled,
            QuicAckPolicy::EveryPacket1ms,
            QuicAckPolicy::EveryOtherPacket5ms,
        ];
        let mut index = 0;
        let mut rtt = 0;
        while rtt < rtts.len() {
            let mut ack = 0;
            while ack < acknowledgements.len() {
                profiles[index] = Self {
                    initial_rtt_ms: rtts[rtt],
                    ack_policy: acknowledgements[ack],
                    segmentation_offload: false,
                };
                profiles[index + 1] = Self {
                    initial_rtt_ms: rtts[rtt],
                    ack_policy: acknowledgements[ack],
                    segmentation_offload: true,
                };
                index += 2;
                ack += 1;
            }
            rtt += 1;
        }
        profiles
    }

    pub const fn initial_rtt_ms(self) -> u64 {
        self.initial_rtt_ms
    }

    pub const fn ack_policy(self) -> QuicAckPolicy {
        self.ack_policy
    }

    pub const fn segmentation_offload(self) -> bool {
        self.segmentation_offload
    }
}

#[derive(Debug)]
pub enum TransportError {
    InvalidLimits(LimitViolation),
    Io(std::io::Error),
    Route(everssh::Error),
    RuntimeUnavailable,
    TlsConfiguration,
    EndpointClosed,
    Timeout,
    PinMismatch,
    Rejected,
    Retry,
    Connection,
    Stream,
    Protocol(WireError),
    Handshake(HandshakeError),
    Admission(AdmissionError),
    PeerIdentity,
    InvitationStoreUnavailable,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Route(error) => write!(formatter, "{error}"),
            Self::RuntimeUnavailable => {
                formatter.write_str("everudp requires an active Tokio runtime")
            }
            Self::TlsConfiguration => formatter.write_str("invalid everudp TLS configuration"),
            Self::EndpointClosed => formatter.write_str("everudp endpoint is closed"),
            Self::Timeout => formatter.write_str("everudp transport deadline expired"),
            Self::PinMismatch => formatter.write_str("everudp gateway SPKI pin mismatch"),
            Self::Rejected => formatter.write_str("everudp association was rejected"),
            Self::Retry => formatter.write_str("everudp QUIC Retry failed"),
            Self::Connection => formatter.write_str("everudp QUIC connection failed"),
            Self::Stream => formatter.write_str("everudp QUIC stream failed"),
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::Handshake(error) => write!(formatter, "{error}"),
            Self::Admission(error) => write!(formatter, "{error}"),
            Self::PeerIdentity => formatter.write_str("everudp peer identity is unavailable"),
            Self::InvitationStoreUnavailable => {
                formatter.write_str("everudp invitation store is unavailable")
            }
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidLimits(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Route(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Handshake(error) => Some(error),
            Self::Admission(error) => Some(error),
            _ => None,
        }
    }
}

impl From<LimitViolation> for TransportError {
    fn from(value: LimitViolation) -> Self {
        Self::InvalidLimits(value)
    }
}

impl From<std::io::Error> for TransportError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<everssh::Error> for TransportError {
    fn from(value: everssh::Error) -> Self {
        Self::Route(value)
    }
}

impl From<WireError> for TransportError {
    fn from(value: WireError) -> Self {
        Self::Protocol(value)
    }
}

impl From<HandshakeError> for TransportError {
    fn from(value: HandshakeError) -> Self {
        Self::Handshake(value)
    }
}

impl From<AdmissionError> for TransportError {
    fn from(value: AdmissionError) -> Self {
        Self::Admission(value)
    }
}

impl TransportError {
    pub fn is_temporary(&self) -> bool {
        matches!(
            self,
            Self::Io(_) | Self::Route(_) | Self::Timeout | Self::Connection | Self::Stream
        )
    }
}

/// Initial connection failure split at the point where a complete
/// `CLIENT_HELLO` may have reached the gateway. Only `Unavailable` is safe
/// for the combined binary's one-shot SSH fallback.
#[derive(Debug)]
pub enum InitialConnectError {
    Unavailable(TransportError),
    Ambiguous(TransportError),
}

impl InitialConnectError {
    pub fn into_error(self) -> TransportError {
        match self {
            Self::Unavailable(error) | Self::Ambiguous(error) => error,
        }
    }

    pub fn fallback_safe(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedTransportProfile {
    pub tls13_only: bool,
    pub alpn: &'static [u8],
    pub client_certificate_required: bool,
    pub retry_required: bool,
    pub resumption: bool,
    pub early_data: bool,
    pub server_half_rtt_data: bool,
    pub tls13_tickets: usize,
    pub new_tokens: bool,
    pub preferred_addresses: bool,
    pub server_incoming_bidi: u32,
    pub server_incoming_uni: u32,
    pub client_incoming_bidi: u32,
    pub client_incoming_uni: u32,
    pub datagrams: bool,
    pub address_discovery: bool,
    pub multipath: bool,
    pub nat_traversal: bool,
    pub handshake_migration: bool,
    pub standard_migration: bool,
    pub mtu_discovery: bool,
    pub segmentation_offload: bool,
    pub initial_mtu: u16,
    pub initial_rtt_ms: u64,
    pub ack_policy: QuicAckPolicy,
    pub control_stream_priority: i32,
    pub input_stream_priority: i32,
    pub output_stream_priority: i32,
    pub keepalive_ms: u64,
    pub idle_timeout_ms: u64,
}

impl LockedTransportProfile {
    /// Explicit profile for the closed v4 measurement example. Enabling the
    /// feature alone must not change the protocol used by stream actors.
    #[cfg(feature = "reliable-datagram-spike")]
    pub fn for_datagram_floor(limits: &Limits) -> Result<Self, TransportError> {
        let mut profile = Self::for_limits(limits)?;
        profile.alpn = crate::reliable_datagram::ALPN;
        profile.server_incoming_uni = 0;
        profile.client_incoming_uni = 0;
        Ok(profile)
    }

    /// Explicit reliable-stream floor profile. This remains independent from
    /// the datagram experiment even when the crate is compiled `--all-features`.
    #[cfg(feature = "stream-floor")]
    pub fn for_stream_floor(limits: &Limits) -> Result<Self, TransportError> {
        Self::with_transport_profile(
            limits,
            100,
            QuicAckPolicy::EveryPacket1ms,
            true,
            false,
            STREAM_FLOOR_ALPN,
        )
    }

    pub fn for_limits(limits: &Limits) -> Result<Self, TransportError> {
        let ack_policy = if cfg!(feature = "quic-ack-threshold-spike") {
            QuicAckPolicy::EveryOtherPacket1ms
        } else if cfg!(feature = "quic-ack-coalescing-spike") {
            QuicAckPolicy::EveryOtherPacket5ms
        } else {
            QuicAckPolicy::EveryPacket1ms
        };
        Self::with_transport_tuning(limits, 100, ack_policy, true)
    }

    fn with_transport_tuning(
        limits: &Limits,
        initial_rtt_ms: u64,
        ack_policy: QuicAckPolicy,
        segmentation_offload: bool,
    ) -> Result<Self, TransportError> {
        Self::with_transport_profile(
            limits,
            initial_rtt_ms,
            if cfg!(feature = "datagram-spike") {
                QuicAckPolicy::Disabled
            } else {
                ack_policy
            },
            segmentation_offload,
            cfg!(feature = "datagram-spike"),
            ALPN,
        )
    }

    fn with_transport_profile(
        limits: &Limits,
        initial_rtt_ms: u64,
        ack_policy: QuicAckPolicy,
        segmentation_offload: bool,
        datagrams: bool,
        alpn: &'static [u8],
    ) -> Result<Self, TransportError> {
        limits.validate()?;
        Ok(Self {
            tls13_only: true,
            alpn,
            client_certificate_required: true,
            retry_required: true,
            resumption: false,
            early_data: false,
            server_half_rtt_data: false,
            tls13_tickets: 0,
            new_tokens: false,
            preferred_addresses: false,
            server_incoming_bidi: limits.max_bidi_streams,
            server_incoming_uni: limits.max_client_uni_streams,
            client_incoming_bidi: 0,
            client_incoming_uni: limits.max_server_uni_streams,
            datagrams,
            address_discovery: false,
            multipath: false,
            nat_traversal: false,
            handshake_migration: false,
            standard_migration: true,
            mtu_discovery: true,
            segmentation_offload,
            initial_mtu: limits.safe_initial_mtu,
            initial_rtt_ms,
            ack_policy,
            control_stream_priority: CONTROL_STREAM_PRIORITY,
            input_stream_priority: INPUT_STREAM_PRIORITY,
            output_stream_priority: OUTPUT_STREAM_PRIORITY,
            keepalive_ms: limits.keepalive_ms,
            idle_timeout_ms: limits.idle_timeout_ms,
        })
    }

    #[cfg(feature = "tuning")]
    fn for_development_tuning(
        limits: &Limits,
        tuning: DevelopmentTransportTuning,
    ) -> Result<Self, TransportError> {
        Self::with_transport_tuning(
            limits,
            tuning.initial_rtt_ms,
            tuning.ack_policy,
            tuning.segmentation_offload,
        )
    }
}

#[derive(Clone)]
pub struct GatewayEndpoint {
    endpoint: Endpoint,
    accept_config: Arc<ServerConfig>,
    local_addr: SocketAddr,
    invitations: SharedInvitationStore,
    session: String,
    generation: crate::GatewayGeneration,
    limits: Limits,
    profile: LockedTransportProfile,
}

impl GatewayEndpoint {
    #[cfg(feature = "reliable-datagram-spike")]
    pub fn bind_datagram_floor(
        bind: SocketAddr,
        identity: &GatewayIdentity,
        invitations: SharedInvitationStore,
        limits: Limits,
    ) -> Result<Self, TransportError> {
        let profile = LockedTransportProfile::for_datagram_floor(&limits)?;
        Self::bind_with_profile(bind, identity, invitations, limits, profile)
    }

    pub fn bind(
        bind: SocketAddr,
        identity: &GatewayIdentity,
        invitations: SharedInvitationStore,
        limits: Limits,
    ) -> Result<Self, TransportError> {
        let profile = LockedTransportProfile::for_limits(&limits)?;
        Self::bind_with_profile(bind, identity, invitations, limits, profile)
    }

    #[cfg(feature = "tuning")]
    #[doc(hidden)]
    pub fn bind_for_development_tuning(
        bind: SocketAddr,
        identity: &GatewayIdentity,
        invitations: SharedInvitationStore,
        limits: Limits,
        tuning: DevelopmentTransportTuning,
    ) -> Result<Self, TransportError> {
        let profile = LockedTransportProfile::for_development_tuning(&limits, tuning)?;
        Self::bind_with_profile(bind, identity, invitations, limits, profile)
    }

    fn bind_with_profile(
        bind: SocketAddr,
        identity: &GatewayIdentity,
        invitations: SharedInvitationStore,
        limits: Limits,
        profile: LockedTransportProfile,
    ) -> Result<Self, TransportError> {
        require_runtime()?;
        let (session, generation) = {
            let store = invitations
                .lock()
                .map_err(|_| TransportError::InvitationStoreUnavailable)?;
            (store.session().to_owned(), store.generation())
        };
        let provider = ring_provider();
        let rustls = locked_server_tls(identity, provider, profile.alpn)?;
        let server_config = locked_server_config(rustls, &limits, &profile)?;
        let accept_config = Arc::new(server_config.clone());
        let socket = UdpSocket::bind(bind)?;
        socket.set_nonblocking(true)?;
        let local_addr = socket.local_addr()?;
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(TokioRuntime),
        )?;
        Ok(Self {
            endpoint,
            accept_config,
            local_addr,
            invitations,
            session,
            generation,
            limits,
            profile,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn profile(&self) -> &LockedTransportProfile {
        &self.profile
    }

    pub fn generation(&self) -> crate::GatewayGeneration {
        self.generation
    }

    /// Keeps the UDP driver alive until every explicitly closed connection
    /// has completed QUIC's draining period. Terminal delivery calls this
    /// before releasing the gateway process so the final close packet cannot
    /// race endpoint teardown.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }

    pub async fn accept_initial(&self) -> Result<AdmittedConnection, TransportError> {
        let connection = self.accept_transport().await?;
        self.authenticate_initial(connection).await
    }

    pub async fn accept_resume(
        &self,
        authorization: AssociationAuthorization,
    ) -> Result<AdmittedConnection, TransportError> {
        let connection = self.accept_transport().await?;
        self.authenticate_resume(connection, authorization).await
    }

    /// Accepts either a one-use invitation or a resume for one of the
    /// gateway's bounded live associations. This is the persistent gateway
    /// entry point: a single endpoint must not race independent accept loops
    /// that could consume each other's connections.
    pub async fn accept_any(
        &self,
        authorizations: &[Option<AssociationAuthorization>],
    ) -> Result<AdmittedConnection, TransportError> {
        let connection = self.accept_transport().await?;
        self.authenticate_any(connection, authorizations).await
    }

    async fn accept_transport(&self) -> Result<Connection, TransportError> {
        loop {
            let incoming = self
                .endpoint
                .accept()
                .await
                .ok_or(TransportError::EndpointClosed)?;
            if !incoming.remote_address_validated() {
                incoming.retry().map_err(|_| TransportError::Retry)?;
                continue;
            }

            let connecting = incoming
                .accept_with(self.accept_config.clone())
                .map_err(|_| TransportError::Connection)?;
            crate::exit_trace::record("gateway-transport-handshake-wait");
            let connection = tokio::time::timeout(self.limits.initial_udp_budget(), connecting)
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(|_| TransportError::Connection)?;
            crate::exit_trace::record("gateway-transport-handshake-complete");
            return Ok(connection);
        }
    }

    async fn authenticate_initial(
        &self,
        connection: Connection,
    ) -> Result<AdmittedConnection, TransportError> {
        let failed_connection = connection.clone();
        let outcome = async {
            crate::exit_trace::record("gateway-initial-wait-control-stream");
            let (control_send, mut control_recv) =
                tokio::time::timeout(self.limits.initial_udp_budget(), connection.accept_bi())
                    .await
                    .map_err(|_| {
                        #[cfg(feature = "path-diagnostics")]
                        crate::exit_trace::connection_counters(
                            "gateway-initial-timeout",
                            &connection,
                        );
                        TransportError::Timeout
                    })?
                    .map_err(|_| TransportError::Stream)?;
            crate::exit_trace::record("gateway-initial-control-stream-accepted");
            let hello = read_client_hello(&mut control_recv, &self.limits).await?;
            let ClientHello::Initial { token, .. } = &hello else {
                return Err(TransportError::Admission(AdmissionError::TokenRejected));
            };
            let client_spki_sha256 = client_spki_from_connection(&connection)?;
            let now_ms = everpty::sys::clock_monotonic_ms()?;
            let take_over = self
                .invitations
                .lock()
                .map_err(|_| TransportError::InvitationStoreUnavailable)?
                .claim(
                    token.as_bytes(),
                    hello.association_id(),
                    &self.session,
                    self.generation,
                    hello.role(),
                    client_spki_sha256,
                    now_ms,
                )?;
            Ok(AdmittedConnection {
                connection,
                control_send,
                control_recv,
                hello,
                client_spki_sha256,
                take_over,
                address_was_validated: true,
            })
        }
        .await;
        if outcome.is_err() {
            failed_connection.close(CLOSE_CODE, b"everudp admission rejected");
        }
        outcome
    }

    async fn authenticate_resume(
        &self,
        connection: Connection,
        authorization: AssociationAuthorization,
    ) -> Result<AdmittedConnection, TransportError> {
        let failed_connection = connection.clone();
        let outcome = async {
            let (control_send, mut control_recv) =
                tokio::time::timeout(self.limits.initial_udp_budget(), connection.accept_bi())
                    .await
                    .map_err(|_| TransportError::Timeout)?
                    .map_err(|_| TransportError::Stream)?;
            let hello = read_client_hello(&mut control_recv, &self.limits).await?;
            let client_spki_sha256 = client_spki_from_connection(&connection)?;
            authorization.authorize(&hello, client_spki_sha256)?;
            Ok(AdmittedConnection {
                connection,
                control_send,
                control_recv,
                hello,
                client_spki_sha256,
                take_over: false,
                address_was_validated: true,
            })
        }
        .await;
        if outcome.is_err() {
            failed_connection.close(CLOSE_CODE, b"everudp resume rejected");
        }
        outcome
    }

    async fn authenticate_any(
        &self,
        connection: Connection,
        authorizations: &[Option<AssociationAuthorization>],
    ) -> Result<AdmittedConnection, TransportError> {
        let failed_connection = connection.clone();
        let outcome = async {
            crate::exit_trace::record("gateway-admission-wait-control-stream");
            let (control_send, mut control_recv) =
                tokio::time::timeout(self.limits.initial_udp_budget(), connection.accept_bi())
                    .await
                    .map_err(|_| TransportError::Timeout)?
                    .map_err(|_| TransportError::Stream)?;
            crate::exit_trace::record("gateway-admission-wait-client-hello");
            let hello = read_client_hello(&mut control_recv, &self.limits).await?;
            crate::exit_trace::record("gateway-admission-client-hello-read");
            let client_spki_sha256 = client_spki_from_connection(&connection)?;
            let take_over = match &hello {
                ClientHello::Initial { token, .. } => {
                    let now_ms = everpty::sys::clock_monotonic_ms()?;
                    self.invitations
                        .lock()
                        .map_err(|_| TransportError::InvitationStoreUnavailable)?
                        .claim(
                            token.as_bytes(),
                            hello.association_id(),
                            &self.session,
                            self.generation,
                            hello.role(),
                            client_spki_sha256,
                            now_ms,
                        )?
                }
                ClientHello::Resume { .. } => {
                    let authorized = authorizations.iter().flatten().any(|authorization| {
                        authorization.authorize(&hello, client_spki_sha256).is_ok()
                    });
                    if !authorized {
                        return Err(TransportError::Admission(AdmissionError::BindingMismatch));
                    }
                    false
                }
            };
            Ok(AdmittedConnection {
                connection,
                control_send,
                control_recv,
                hello,
                client_spki_sha256,
                take_over,
                address_was_validated: true,
            })
        }
        .await;
        if outcome.is_err() {
            failed_connection.close(CLOSE_CODE, b"everudp admission rejected");
        }
        outcome
    }
}

#[derive(Clone)]
pub struct ClientEndpoint {
    endpoint: Endpoint,
    limits: Limits,
    profile: LockedTransportProfile,
    route: Arc<Mutex<Option<RouteIdentity>>>,
    pin_mismatch: PinMismatchState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebindOutcome {
    pub local_addr: SocketAddr,
    pub route: Option<RouteIdentity>,
    pub rebound: bool,
}

impl ClientEndpoint {
    #[cfg(feature = "reliable-datagram-spike")]
    pub fn bind_routed_datagram_floor(
        remote: SocketAddr,
        policy: UdpBindPolicy,
        identity: &ClientIdentity,
        server_spki_sha256: [u8; 32],
        limits: Limits,
    ) -> Result<Self, TransportError> {
        let bound = bind_udp(remote, policy, &everssh::Limits::default())?;
        let route = bound.route_identity();
        let profile = LockedTransportProfile::for_datagram_floor(&limits)?;
        Self::from_socket(
            bound.into_socket(),
            route,
            identity,
            server_spki_sha256,
            limits,
            profile,
        )
    }

    pub fn bind(
        bind: SocketAddr,
        identity: &ClientIdentity,
        server_spki_sha256: [u8; 32],
        limits: Limits,
    ) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(bind)?;
        let profile = LockedTransportProfile::for_limits(&limits)?;
        Self::from_socket(socket, None, identity, server_spki_sha256, limits, profile)
    }

    #[cfg(feature = "tuning")]
    #[doc(hidden)]
    pub fn bind_for_development_tuning(
        bind: SocketAddr,
        identity: &ClientIdentity,
        server_spki_sha256: [u8; 32],
        limits: Limits,
        tuning: DevelopmentTransportTuning,
    ) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(bind)?;
        let profile = LockedTransportProfile::for_development_tuning(&limits, tuning)?;
        Self::from_socket(socket, None, identity, server_spki_sha256, limits, profile)
    }

    pub fn bind_routed(
        remote: SocketAddr,
        policy: UdpBindPolicy,
        identity: &ClientIdentity,
        server_spki_sha256: [u8; 32],
        limits: Limits,
    ) -> Result<Self, TransportError> {
        let bound = bind_udp(remote, policy, &everssh::Limits::default())?;
        let route = bound.route_identity();
        let profile = LockedTransportProfile::for_limits(&limits)?;
        Self::from_socket(
            bound.into_socket(),
            route,
            identity,
            server_spki_sha256,
            limits,
            profile,
        )
    }

    fn from_socket(
        socket: UdpSocket,
        route: Option<RouteIdentity>,
        identity: &ClientIdentity,
        server_spki_sha256: [u8; 32],
        limits: Limits,
        profile: LockedTransportProfile,
    ) -> Result<Self, TransportError> {
        require_runtime()?;
        let provider = ring_provider();
        let (rustls, pin_mismatch) =
            locked_client_tls(server_spki_sha256, provider, identity, profile.alpn)?;
        let client_config = locked_client_config(rustls, &limits, &profile)?;
        socket.set_nonblocking(true)?;
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )?;
        #[cfg(everudp_quinn_evaluation)]
        let mut endpoint = endpoint;
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint,
            limits,
            profile,
            route: Arc::new(Mutex::new(route)),
            pin_mismatch,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr().map_err(TransportError::Io)
    }

    pub fn profile(&self) -> &LockedTransportProfile {
        &self.profile
    }

    pub fn route_identity(&self) -> Option<RouteIdentity> {
        match self.route.lock() {
            Ok(route) => *route,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    pub async fn connect_initial(
        &self,
        remote: SocketAddr,
        hello: &ClientHello,
    ) -> Result<ClientSession, TransportError> {
        if !matches!(hello, ClientHello::Initial { .. }) {
            return Err(TransportError::Admission(AdmissionError::TokenRejected));
        }
        self.connect(remote, hello).await
    }

    /// Uses one caller-owned absolute deadline and reports whether fallback
    /// remains provably pre-commit. Once the QUIC connection exists, any
    /// stream/open/write failure is ambiguous because the gateway may have
    /// accepted the complete client hello.
    pub async fn connect_initial_until(
        &self,
        remote: SocketAddr,
        hello: &ClientHello,
        deadline: tokio::time::Instant,
    ) -> Result<ClientSession, InitialConnectError> {
        if !matches!(hello, ClientHello::Initial { .. }) {
            return Err(InitialConnectError::Ambiguous(TransportError::Admission(
                AdmissionError::TokenRejected,
            )));
        }
        let connecting = self
            .endpoint
            .connect(remote, "localhost")
            .map_err(|_| InitialConnectError::Unavailable(TransportError::Connection))?;
        let connection = tokio::time::timeout_at(deadline, connecting)
            .await
            .map_err(|_| InitialConnectError::Unavailable(TransportError::Timeout))?
            .map_err(|error| {
                let error = map_client_connection_error(&error, &self.pin_mismatch);
                if error.is_temporary() {
                    InitialConnectError::Unavailable(error)
                } else {
                    InitialConnectError::Ambiguous(error)
                }
            })?;
        let established = async {
            let (mut control_send, control_recv) = connection
                .open_bi()
                .await
                .map_err(|_| TransportError::Stream)?;
            write_client_hello(&mut control_send, hello, &self.limits).await?;
            Ok(ClientSession {
                connection,
                control_send,
                control_recv,
            })
        };
        tokio::time::timeout_at(deadline, established)
            .await
            .map_err(|_| InitialConnectError::Ambiguous(TransportError::Timeout))?
            .map_err(InitialConnectError::Ambiguous)
    }

    pub async fn connect_resume(
        &self,
        remote: SocketAddr,
        hello: &ClientHello,
    ) -> Result<ClientSession, TransportError> {
        if !matches!(hello, ClientHello::Resume { .. }) {
            return Err(TransportError::Admission(AdmissionError::BindingMismatch));
        }
        self.connect(remote, hello).await
    }

    async fn connect(
        &self,
        remote: SocketAddr,
        hello: &ClientHello,
    ) -> Result<ClientSession, TransportError> {
        let connecting = self
            .endpoint
            .connect(remote, "localhost")
            .map_err(|_| TransportError::Connection)?;
        let connection = tokio::time::timeout(self.limits.initial_udp_budget(), connecting)
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| map_client_connection_error(&error, &self.pin_mismatch))?;
        let (mut control_send, control_recv) = connection
            .open_bi()
            .await
            .map_err(|_| TransportError::Stream)?;
        write_client_hello(&mut control_send, hello, &self.limits).await?;
        Ok(ClientSession {
            connection,
            control_send,
            control_recv,
        })
    }

    pub fn rebind(&self, socket: UdpSocket) -> Result<SocketAddr, TransportError> {
        socket.set_nonblocking(true)?;
        let local_addr = socket.local_addr()?;
        self.endpoint.rebind(socket)?;
        Ok(local_addr)
    }

    pub fn rebind_routed(
        &self,
        remote: SocketAddr,
        policy: UdpBindPolicy,
        force: bool,
    ) -> Result<RebindOutcome, TransportError> {
        let bound = bind_udp(remote, policy, &everssh::Limits::default())?;
        let route = bound.route_identity();
        let current = *self.route.lock().map_err(|_| TransportError::Connection)?;
        if !force && route == current {
            return Ok(RebindOutcome {
                local_addr: self.local_addr()?,
                route,
                rebound: false,
            });
        }
        let socket = bound.into_socket();
        let local_addr = self.rebind(socket)?;
        *self.route.lock().map_err(|_| TransportError::Connection)? = route;
        Ok(RebindOutcome {
            local_addr,
            route,
            rebound: true,
        })
    }
}

pub struct AdmittedConnection {
    connection: Connection,
    control_send: SendStream,
    control_recv: RecvStream,
    hello: ClientHello,
    client_spki_sha256: [u8; 32],
    take_over: bool,
    address_was_validated: bool,
}

impl AdmittedConnection {
    pub fn hello(&self) -> &ClientHello {
        &self.hello
    }

    pub fn client_spki_sha256(&self) -> [u8; 32] {
        self.client_spki_sha256
    }

    pub fn take_over(&self) -> bool {
        self.take_over
    }

    pub fn address_was_validated(&self) -> bool {
        self.address_was_validated
    }

    pub fn close(self) {
        self.connection.close(CLOSE_CODE, b"everudp test close");
    }

    pub(crate) fn reject_writer_busy(self) {
        self.connection
            .close(WRITER_BUSY_CLOSE_CODE, b"everudp writer is busy");
    }

    pub(crate) fn reject_association_capacity(self) {
        self.connection.close(
            ASSOCIATION_CAPACITY_CLOSE_CODE,
            b"everudp association capacity exhausted",
        );
    }

    pub fn into_parts(self) -> (Connection, SendStream, RecvStream, ClientHello) {
        (
            self.connection,
            self.control_send,
            self.control_recv,
            self.hello,
        )
    }
}

pub struct ClientSession {
    connection: Connection,
    control_send: SendStream,
    control_recv: RecvStream,
}

impl ClientSession {
    #[cfg(feature = "path-diagnostics")]
    pub(crate) fn diagnostic_connection(&self) -> Connection {
        self.connection.clone()
    }

    pub fn close(self) {
        self.connection.close(CLOSE_CODE, b"everudp test close");
    }

    pub fn into_parts(self) -> (Connection, SendStream, RecvStream) {
        (self.connection, self.control_send, self.control_recv)
    }
}

async fn read_client_hello(
    recv: &mut RecvStream,
    limits: &Limits,
) -> Result<ClientHello, TransportError> {
    let mut wire = [0_u8; MAX_CONTROL_WIRE];
    recv.read_exact(&mut wire[..HEADER_LEN])
        .await
        .map_err(|_| TransportError::Stream)?;
    let payload_len = u32::from_be_bytes(
        wire[10..14]
            .try_into()
            .map_err(|_| TransportError::Stream)?,
    ) as usize;
    if payload_len > limits.control_frame_max {
        return Err(TransportError::Protocol(WireError::PayloadTooLarge {
            kind: Kind::ClientHello,
            length: payload_len,
            maximum: limits.control_frame_max,
        }));
    }
    let total = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(TransportError::Stream)?;
    recv.read_exact(&mut wire[HEADER_LEN..total])
        .await
        .map_err(|_| TransportError::Stream)?;
    let (record, consumed) = decode_record(StreamRole::Control, &wire[..total], limits)?;
    if consumed != total || record.header.kind != Kind::ClientHello || record.header.sequence != 0 {
        return Err(TransportError::Handshake(HandshakeError::InvalidLength));
    }
    ClientHello::decode_exact(record.payload).map_err(TransportError::Handshake)
}

async fn write_client_hello(
    send: &mut SendStream,
    hello: &ClientHello,
    limits: &Limits,
) -> Result<(), TransportError> {
    let mut payload = [0_u8; ClientHello::MAX_ENCODED_LEN];
    let payload_len = hello.encode_into(&mut payload)?;
    let mut wire = [0_u8; HEADER_LEN + ClientHello::MAX_ENCODED_LEN];
    let used = encode_record(
        StreamRole::Control,
        Kind::ClientHello,
        0,
        &payload[..payload_len],
        limits,
        &mut wire,
    )?;
    send.write_all(&wire[..used])
        .await
        .map_err(|_| TransportError::Stream)?;
    Ok(())
}

fn client_spki_from_connection(connection: &Connection) -> Result<[u8; 32], TransportError> {
    let identity = connection
        .peer_identity()
        .ok_or(TransportError::PeerIdentity)?;
    spki_from_peer_identity(identity.as_ref())
}

fn spki_from_peer_identity(identity: &dyn std::any::Any) -> Result<[u8; 32], TransportError> {
    let certificates = identity
        .downcast_ref::<Vec<CertificateDer<'_>>>()
        .ok_or(TransportError::PeerIdentity)?;
    let [certificate] = certificates.as_slice() else {
        return Err(TransportError::PeerIdentity);
    };
    let spki = extract_spki(certificate).ok_or(TransportError::PeerIdentity)?;
    Ok(sha256(spki))
}

/// Claim a floor invitation using the certificate authenticated by TLS, never
/// a client-supplied fingerprint. The caller must close on failure and must not
/// enable application delivery before success. This does not parse streams.
#[cfg(any(feature = "floor-single-owner", feature = "stream-floor"))]
#[doc(hidden)]
pub fn floor_authorize_initial(
    connection: &noq_proto::Connection,
    hello: &ClientHello,
    invitations: &mut InvitationStore,
    now_ms: u64,
) -> Result<bool, TransportError> {
    if connection.crypto_session().is_handshaking() {
        return Err(TransportError::PeerIdentity);
    }
    let ClientHello::Initial { .. } = hello else {
        return Err(TransportError::Admission(AdmissionError::TokenRejected));
    };
    let identity = connection
        .crypto_session()
        .peer_identity()
        .ok_or(TransportError::PeerIdentity)?;
    let spki = spki_from_peer_identity(identity.as_ref())?;
    claim_initial_invitation(hello, invitations, spki, now_ms)
}

#[cfg(any(feature = "floor-single-owner", feature = "stream-floor"))]
fn claim_initial_invitation(
    hello: &ClientHello,
    invitations: &mut InvitationStore,
    client_spki_sha256: [u8; 32],
    now_ms: u64,
) -> Result<bool, TransportError> {
    let ClientHello::Initial { token, .. } = hello else {
        return Err(TransportError::Admission(AdmissionError::TokenRejected));
    };
    let session = invitations.session().to_owned();
    invitations
        .claim(
            token.as_bytes(),
            hello.association_id(),
            &session,
            hello.generation(),
            hello.role(),
            client_spki_sha256,
            now_ms,
        )
        .map_err(TransportError::Admission)
}

/// Authorize the stream-floor's ordinary noQ connection using the SPKI
/// authenticated by its completed TLS session. The invitation is one-use and
/// remains bound to association, generation, role, session, and that SPKI.
/// No caller-supplied fingerprint participates in this decision.
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub fn stream_floor_authorize_initial(
    connection: &Connection,
    hello: &ClientHello,
    invitations: &mut InvitationStore,
    now_ms: u64,
) -> Result<bool, TransportError> {
    let client_spki_sha256 = client_spki_from_connection(connection)?;
    claim_initial_invitation(hello, invitations, client_spki_sha256, now_ms)
}

fn require_runtime() -> Result<(), TransportError> {
    tokio::runtime::Handle::try_current()
        .map(|_| ())
        .map_err(|_| TransportError::RuntimeUnavailable)
}

fn ring_provider() -> Arc<CryptoProvider> {
    Arc::new(noq::rustls::crypto::ring::default_provider())
}

#[derive(Clone)]
struct SingleServerCert(Arc<CertifiedKey>);

impl fmt::Debug for SingleServerCert {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SingleServerCert(<REDACTED>)")
    }
}

impl ResolvesServerCert for SingleServerCert {
    fn resolve(&self, _client_hello: RustlsClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[derive(Clone)]
struct SingleClientCert(Arc<CertifiedKey>);

impl fmt::Debug for SingleClientCert {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SingleClientCert(<REDACTED>)")
    }
}

impl ResolvesClientCert for SingleClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[noq::rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// Build the disposable floor's protocol configuration without spawning drivers.
/// This shares the exact TLS and transport builders used by the safe floor.
/// Invitation/SPKI association admission must still run after TLS completes.
#[cfg(feature = "floor-single-owner")]
#[doc(hidden)]
pub fn floor_server_config(
    identity: &GatewayIdentity,
    limits: &Limits,
) -> Result<ServerConfig, TransportError> {
    let profile = LockedTransportProfile::for_datagram_floor(limits)?;
    let tls = locked_server_tls(identity, ring_provider(), profile.alpn)?;
    locked_server_config(tls, limits, &profile)
}

/// Build the disposable floor client with the safe floor's tracked SPKI verifier.
#[cfg(feature = "floor-single-owner")]
#[doc(hidden)]
pub fn floor_client_config(
    identity: &ClientIdentity,
    server_spki_sha256: [u8; 32],
    limits: &Limits,
) -> Result<(ClientConfig, PinMismatchState), TransportError> {
    let profile = LockedTransportProfile::for_datagram_floor(limits)?;
    let (tls, mismatch) =
        locked_client_tls(server_spki_sha256, ring_provider(), identity, profile.alpn)?;
    Ok((locked_client_config(tls, limits, &profile)?, mismatch))
}

/// Shared stream experiment configuration for both ordinary noQ endpoints and
/// the native protocol driver. Neither builder starts a runtime or admits data.
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub fn stream_floor_server_config(
    identity: &GatewayIdentity,
    limits: &Limits,
) -> Result<ServerConfig, TransportError> {
    let profile = LockedTransportProfile::for_stream_floor(limits)?;
    let tls = locked_server_tls(identity, ring_provider(), profile.alpn)?;
    locked_server_config(tls, limits, &profile)
}

/// Tracked pinned client configuration shared by both stream experiment drivers.
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub fn stream_floor_client_config(
    identity: &ClientIdentity,
    server_spki_sha256: [u8; 32],
    limits: &Limits,
) -> Result<(ClientConfig, PinMismatchState), TransportError> {
    let profile = LockedTransportProfile::for_stream_floor(limits)?;
    let (tls, mismatch) =
        locked_client_tls(server_spki_sha256, ring_provider(), identity, profile.alpn)?;
    Ok((locked_client_config(tls, limits, &profile)?, mismatch))
}

fn locked_server_tls(
    identity: &GatewayIdentity,
    provider: Arc<CryptoProvider>,
    alpn: &[u8],
) -> Result<Arc<RustlsServerConfig>, TransportError> {
    let mut config = RustlsServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&noq::rustls::version::TLS13])
        .map_err(|_| TransportError::TlsConfiguration)?
        .with_client_cert_verifier(Arc::new(
            everssh::association::BootstrapClientCertVerifier::new(provider),
        ))
        .with_cert_resolver(Arc::new(SingleServerCert(identity.certified_key())));
    config.alpn_protocols = vec![alpn.to_vec()];
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    config.send_tls13_tickets = 0;
    config.max_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(Arc::new(config))
}

#[cfg(all(test, feature = "floor-single-owner"))]
mod floor_config_tests {
    use super::*;

    #[test]
    fn protocol_configs_reuse_locked_tls_without_a_runtime() {
        let server = GatewayIdentity::generate().expect("floor test fixture succeeds");
        let client = ClientIdentity::generate().expect("floor test fixture succeeds");
        let limits = Limits::default();
        // These assignments also enforce that no second protocol version was
        // introduced beside the high-level noQ configuration types.
        let _: noq_proto::ServerConfig =
            floor_server_config(&server, &limits).expect("floor test fixture succeeds");
        let (config, mismatch) = floor_client_config(&client, server.spki_sha256(), &limits)
            .expect("floor test fixture succeeds");
        let _: noq_proto::ClientConfig = config;
        assert!(!mismatch.observed());

        let profile = LockedTransportProfile::for_datagram_floor(&limits)
            .expect("floor test fixture succeeds");
        let tls = locked_server_tls(&server, ring_provider(), profile.alpn)
            .expect("floor test fixture succeeds");
        assert_eq!(tls.alpn_protocols, [crate::reliable_datagram::ALPN]);
        assert_eq!(tls.max_early_data_size, 0);
        assert!(!tls.send_half_rtt_data);
        assert_eq!(tls.send_tls13_tickets, 0);
        assert_eq!(tls.max_tls13_tickets, 0);
        let (tls, _) =
            locked_client_tls(server.spki_sha256(), ring_provider(), &client, profile.alpn)
                .expect("floor test fixture succeeds");
        assert_eq!(tls.alpn_protocols, [crate::reliable_datagram::ALPN]);
        assert!(!tls.enable_early_data);
    }
}

#[cfg(all(test, feature = "stream-floor"))]
mod stream_floor_config_tests {
    use super::*;

    #[test]
    fn stream_configs_share_pinned_protocol_types_without_starting_drivers() {
        let server = GatewayIdentity::generate().expect("server identity");
        let client = ClientIdentity::generate().expect("client identity");
        let limits = Limits::default();
        let _: noq_proto::ServerConfig =
            stream_floor_server_config(&server, &limits).expect("server config");
        let (config, mismatch) = stream_floor_client_config(&client, server.spki_sha256(), &limits)
            .expect("client config");
        let _: noq_proto::ClientConfig = config;
        assert!(!mismatch.observed());
        let tls =
            locked_server_tls(&server, ring_provider(), STREAM_FLOOR_ALPN).expect("server TLS");
        assert_eq!(tls.alpn_protocols, [STREAM_FLOOR_ALPN]);
        assert_eq!(tls.max_early_data_size, 0);
        assert!(!tls.send_half_rtt_data);
        assert_eq!(tls.send_tls13_tickets, 0);
        let (tls, _) = locked_client_tls(
            server.spki_sha256(),
            ring_provider(),
            &client,
            STREAM_FLOOR_ALPN,
        )
        .expect("client TLS");
        assert_eq!(tls.alpn_protocols, [STREAM_FLOOR_ALPN]);
        assert!(!tls.enable_early_data);
    }

    #[test]
    fn locked_transport_debug_receipt_has_no_datagram_buffers_even_all_features() {
        let limits = Limits::default();
        let profile = LockedTransportProfile::for_stream_floor(&limits).expect("profile");
        let config = locked_transport(Side::Server, &limits, &profile).expect("transport");
        let debug = format!("{config:?}");
        assert!(
            debug.contains("datagram_receive_buffer_size: None"),
            "{debug}"
        );
        assert!(debug.contains("datagram_send_buffer_size: 0"), "{debug}");
        assert!(debug.contains("ack_frequency_config: Some"), "{debug}");
        assert!(debug.contains("max_concurrent_bidi_streams: 1"), "{debug}");
        assert!(debug.contains("max_concurrent_uni_streams: 1"), "{debug}");
        assert!(debug.contains("stream_receive_window: 4194304"), "{debug}");
        assert!(debug.contains("receive_window: 8388608"), "{debug}");
        assert!(debug.contains("send_window: 4194304"), "{debug}");
        assert!(
            debug.contains("enable_segmentation_offload: true"),
            "{debug}"
        );

        let client = locked_transport(Side::Client, &limits, &profile).expect("transport");
        let client_debug = format!("{client:?}");
        assert!(
            client_debug.contains("max_concurrent_bidi_streams: 0"),
            "{client_debug}"
        );
        assert!(
            client_debug.contains("max_concurrent_uni_streams: 1"),
            "{client_debug}"
        );
    }
}

fn locked_client_tls(
    server_spki_sha256: [u8; 32],
    provider: Arc<CryptoProvider>,
    identity: &ClientIdentity,
    alpn: &[u8],
) -> Result<(Arc<RustlsClientConfig>, PinMismatchState), TransportError> {
    let (verifier, pin_mismatch) = SpkiPinVerifier::tracked(server_spki_sha256, provider.clone());
    let mut config = RustlsClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&noq::rustls::version::TLS13])
        .map_err(|_| TransportError::TlsConfiguration)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(Arc::new(SingleClientCert(identity.certified_key())));
    config.alpn_protocols = vec![alpn.to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok((Arc::new(config), pin_mismatch))
}

fn map_client_connection_error(
    error: &ConnectionError,
    pin_mismatch: &PinMismatchState,
) -> TransportError {
    if pin_mismatch.observed() {
        return TransportError::PinMismatch;
    }
    match error {
        ConnectionError::ApplicationClosed(close) if close.error_code == CLOSE_CODE => {
            TransportError::Rejected
        }
        ConnectionError::VersionMismatch | ConnectionError::ConnectionClosed(_) => {
            TransportError::Rejected
        }
        ConnectionError::TransportError(_)
        | ConnectionError::Reset
        | ConnectionError::TimedOut
        | ConnectionError::LocallyClosed
        | ConnectionError::CidsExhausted
        | ConnectionError::ApplicationClosed(_) => TransportError::Connection,
    }
}

fn locked_server_config(
    rustls: Arc<RustlsServerConfig>,
    limits: &Limits,
    profile: &LockedTransportProfile,
) -> Result<ServerConfig, TransportError> {
    let crypto =
        QuicServerConfig::try_from(rustls).map_err(|_| TransportError::TlsConfiguration)?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(locked_transport(Side::Server, limits, profile)?);
    config.max_incoming(MAX_INCOMING);
    config.incoming_buffer_size(INCOMING_BUFFER_SIZE);
    config.incoming_buffer_size_total(INCOMING_BUFFER_TOTAL);
    config.migration(true);
    config.preferred_address_v4(None);
    config.preferred_address_v6(None);
    config.retry_token_lifetime(limits.invitation_lifetime());
    let mut validation = noq::ValidationTokenConfig::default();
    validation.sent(0);
    validation.log(Arc::new(NoneTokenLog));
    config.validation_token_config(validation);
    Ok(config)
}

fn locked_client_config(
    rustls: Arc<RustlsClientConfig>,
    limits: &Limits,
    profile: &LockedTransportProfile,
) -> Result<ClientConfig, TransportError> {
    let crypto =
        QuicClientConfig::try_from(rustls).map_err(|_| TransportError::TlsConfiguration)?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(locked_transport(Side::Client, limits, profile)?);
    config.token_store(Arc::new(NoneTokenStore));
    Ok(config)
}

#[derive(Clone, Copy)]
enum Side {
    Server,
    Client,
}

/// Which peer's incoming stream limits are being described by a transport
/// configuration receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportConfigSide {
    Server,
    Client,
}

/// Stable, non-secret description of the requested QUIC transport settings.
/// This is intentionally separate from noq's private `TransportConfig` fields
/// so benchmark artifacts can record the settings without exposing internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfigReceipt {
    pub alpn: &'static [u8],
    pub incoming_bidi: u32,
    pub incoming_uni: u32,
    pub datagrams: bool,
    pub datagram_receive_buffer: Option<usize>,
    pub datagram_send_buffer: usize,
    pub stream_receive_window: u64,
    pub receive_window: u64,
    pub send_window: u64,
    pub ack_policy: QuicAckPolicy,
    pub segmentation_offload: bool,
}

/// Describe builder inputs before building a noq config. This is not evidence
/// of negotiated settings or native/ordinary runtime parity; callers must also
/// verify the built configuration and the established connection.
/// In particular, this remains stream-only when `--all-features` also enables
/// the unrelated datagram spike.
pub fn effective_transport_config_receipt(
    side: TransportConfigSide,
    limits: &Limits,
    profile: &LockedTransportProfile,
) -> Result<TransportConfigReceipt, TransportError> {
    limits.validate()?;
    let (incoming_bidi, incoming_uni) = match side {
        TransportConfigSide::Server => (profile.server_incoming_bidi, profile.server_incoming_uni),
        TransportConfigSide::Client => (profile.client_incoming_bidi, profile.client_incoming_uni),
    };
    Ok(TransportConfigReceipt {
        alpn: profile.alpn,
        incoming_bidi,
        incoming_uni,
        datagrams: profile.datagrams,
        datagram_receive_buffer: profile.datagrams.then_some(FAST_DATAGRAM_BUFFER_BYTES),
        datagram_send_buffer: if profile.datagrams {
            FAST_DATAGRAM_BUFFER_BYTES
        } else {
            0
        },
        stream_receive_window: limits.queue_bytes_per_direction as u64,
        receive_window: (limits.queue_bytes_per_direction as u64) * 2,
        send_window: limits.queue_bytes_per_direction as u64,
        ack_policy: profile.ack_policy,
        segmentation_offload: profile.segmentation_offload,
    })
}

#[cfg(all(test, not(feature = "datagram-spike")))]
mod ack_policy_tests {
    use super::*;

    #[test]
    fn actual_client_and_server_ack_configuration_matches_selected_policy() {
        let limits = Limits::default();
        let profile = LockedTransportProfile::for_limits(&limits).expect("profile");
        let (threshold, delay) = if cfg!(feature = "quic-ack-threshold-spike") {
            ("ack_eliciting_threshold: 1", "max_ack_delay: Some(1ms)")
        } else if cfg!(feature = "quic-ack-coalescing-spike") {
            ("ack_eliciting_threshold: 1", "max_ack_delay: Some(5ms)")
        } else {
            ("ack_eliciting_threshold: 0", "max_ack_delay: Some(1ms)")
        };
        for side in [Side::Client, Side::Server] {
            let config = locked_transport(side, &limits, &profile).expect("transport");
            let debug = format!("{config:?}");
            assert!(debug.contains(threshold), "{debug}");
            assert!(debug.contains(delay), "{debug}");
            assert!(
                debug.contains("datagram_receive_buffer_size: None"),
                "{debug}"
            );
            assert!(debug.contains("datagram_send_buffer_size: 0"), "{debug}");
        }
    }
}

fn locked_transport(
    side: Side,
    limits: &Limits,
    profile: &LockedTransportProfile,
) -> Result<Arc<TransportConfig>, TransportError> {
    limits.validate()?;
    let idle = IdleTimeout::try_from(limits.idle_timeout())
        .map_err(|_| TransportError::InvalidLimits(LimitViolation::IdleTimeout))?;
    let stream_window = VarInt::from_u64(limits.queue_bytes_per_direction as u64)
        .map_err(|_| TransportError::InvalidLimits(LimitViolation::QueueBytesPerDirection))?;
    let receive_window = VarInt::from_u64((limits.queue_bytes_per_direction as u64) * 2)
        .map_err(|_| TransportError::InvalidLimits(LimitViolation::QueueBytesPerDirection))?;
    let (incoming_bidi, incoming_uni) = match side {
        Side::Server => (
            VarInt::from_u32(profile.server_incoming_bidi),
            VarInt::from_u32(profile.server_incoming_uni),
        ),
        Side::Client => (
            VarInt::from_u32(profile.client_incoming_bidi),
            VarInt::from_u32(profile.client_incoming_uni),
        ),
    };
    let mut config = TransportConfig::default();
    config.max_concurrent_bidi_streams(incoming_bidi);
    config.max_concurrent_uni_streams(incoming_uni);
    config.stream_receive_window(stream_window);
    config.receive_window(receive_window);
    config.send_window(limits.queue_bytes_per_direction as u64);
    config.max_idle_timeout(Some(idle));
    config.keep_alive_interval(Some(limits.keepalive()));
    #[cfg(not(everudp_quinn_evaluation))]
    {
        config.default_path_max_idle_timeout(Some(limits.idle_timeout()));
        config.default_path_keep_alive_interval(Some(limits.keepalive()));
    }
    // Quinn has one active path and uses the connection idle/keepalive settings
    // above. It has no independent NoQ multipath timeout configuration.
    config.initial_rtt(Duration::from_millis(profile.initial_rtt_ms));
    let ack_frequency = match profile.ack_policy {
        QuicAckPolicy::Disabled => None,
        QuicAckPolicy::EveryPacket1ms => {
            let mut ack = AckFrequencyConfig::default();
            ack.ack_eliciting_threshold(VarInt::from_u32(0));
            ack.max_ack_delay(Some(Duration::from_millis(1)));
            Some(ack)
        }
        QuicAckPolicy::EveryOtherPacket5ms => {
            let mut ack = AckFrequencyConfig::default();
            ack.ack_eliciting_threshold(VarInt::from_u32(1));
            ack.max_ack_delay(Some(Duration::from_millis(5)));
            Some(ack)
        }
        QuicAckPolicy::EveryOtherPacket1ms => {
            let mut ack = AckFrequencyConfig::default();
            ack.ack_eliciting_threshold(VarInt::from_u32(1));
            ack.max_ack_delay(Some(Duration::from_millis(1)));
            Some(ack)
        }
    };
    config.ack_frequency_config(ack_frequency);
    config.initial_mtu(limits.safe_initial_mtu);
    config.min_mtu(limits.safe_initial_mtu);
    config.mtu_discovery_config(Some(noq::MtuDiscoveryConfig::default()));
    config.enable_segmentation_offload(profile.segmentation_offload);
    if profile.datagrams {
        config.datagram_receive_buffer_size(Some(FAST_DATAGRAM_BUFFER_BYTES));
        config.datagram_send_buffer_size(FAST_DATAGRAM_BUFFER_BYTES);
    } else {
        config.datagram_receive_buffer_size(None);
        config.datagram_send_buffer_size(0);
    }
    #[cfg(not(everudp_quinn_evaluation))]
    {
        config.send_observed_address_reports(false);
        config.receive_observed_address_reports(false);
        config.max_concurrent_multipath_paths(0);
        config.max_remote_nat_traversal_addresses(0);
        config.server_handshake_migration(false);
    }
    // Quinn does not implement these NoQ draft extensions. Its handshake
    // rejects packets from a different remote address; standard post-handshake
    // client migration remains enabled through ServerConfig::migration.
    Ok(Arc::new(config))
}
