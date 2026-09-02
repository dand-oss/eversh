//! Typed, diagnostics-safe failures for everssh.

/// The endpoint invariant rejected at the authenticated boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointViolation {
    ZeroPort,
    FamilyMismatch,
    UnspecifiedAddress,
    MulticastAddress,
    BroadcastAddress,
    MissingIpv6Scope,
}

/// The finite UDP binding policy invariant that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpPolicyViolation {
    PeerLoopbackRequiresExplicit,
    ExplicitFamilyMismatch,
    ExplicitPortZero,
    RangeStartsAtZero,
    RangeInverted,
    RangeTooWide,
    SelectedAddressUnusable,
    ExactBindMismatch,
}

/// A named finite limit that cannot be represented safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitViolation {
    ContractValue,
    ZeroValue,
    WindowTooLarge,
    IncomingTotalOverflow,
    RetryBudgetTooSmall,
    PortSpanTooLarge,
    SameRouteReplacementBudget,
    RouteObservationExceedsPoll,
    DeadlineOverflow,
}

/// The absolute deadline that expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlinePhase {
    ServerLease,
    Handshake,
    Authentication,
    ClientConnect,
    TargetConnect,
    Finalize,
}

#[derive(Debug)]
pub enum Error {
    BootstrapMalformed,
    SshConnectionMalformed,
    ServerStartMalformed,
    ReleaseRejected,
    InvalidSshArgument,
    SshPolicyRejected,
    SshProcessFailed,
    BootstrapTimedOut,
    BridgeIncomplete,
    AuthRejected,
    PinMismatch,
    VersionUnsupported,
    TokenReuse,
    TargetUnauthorized,
    LeaseExpired,
    IdentityRandomness,
    IdentityKeyGeneration,
    IdentityCertificateGeneration,
    IdentityCertificateMalformed,
    IdentitySigningKey,
    IdentityUnavailable,
    RuntimeUnavailable,
    TlsConfiguration,
    InvalidEndpoint(EndpointViolation),
    InvalidUdpPolicy(UdpPolicyViolation),
    InvalidLimits(LimitViolation),
    RouteSelection(std::io::Error),
    UdpBind(std::io::Error),
    PortRangeExhausted,
    EndpointClosed,
    RetryFailed,
    RetryLimitExceeded,
    AddressNotValidated,
    QuicConnect,
    QuicConnection,
    StreamOpen,
    StreamRead,
    StreamWrite,
    BridgeAllocation,
    BridgeAdmissionClosed,
    DeadlineExpired(DeadlinePhase),
    TokenStateUnavailable,
    TargetConnect(std::io::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for EndpointViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ZeroPort => "endpoint port is zero",
            Self::FamilyMismatch => "endpoint address families differ",
            Self::UnspecifiedAddress => "endpoint address is unspecified",
            Self::MulticastAddress => "endpoint address is multicast",
            Self::BroadcastAddress => "endpoint address is broadcast",
            Self::MissingIpv6Scope => "link-local IPv6 endpoint has no scope identifier",
        };
        f.write_str(message)
    }
}

impl std::fmt::Display for UdpPolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::PeerLoopbackRequiresExplicit => {
                "route-selected UDP policy rejects a loopback peer"
            }
            Self::ExplicitFamilyMismatch => "explicit UDP endpoint family differs from its peer",
            Self::ExplicitPortZero => "explicit UDP endpoint port is zero",
            Self::RangeStartsAtZero => "UDP port range starts at zero",
            Self::RangeInverted => "UDP port range is inverted",
            Self::RangeTooWide => "UDP port range exceeds the configured finite span",
            Self::SelectedAddressUnusable => "kernel-selected UDP source address is unusable",
            Self::ExactBindMismatch => "bound UDP endpoint differs from the requested endpoint",
        };
        f.write_str(message)
    }
}

impl std::fmt::Display for LimitViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ContractValue => "a frozen protocol limit was changed",
            Self::ZeroValue => "a required finite limit is zero",
            Self::WindowTooLarge => "a transport window exceeds QUIC's representable range",
            Self::IncomingTotalOverflow => "the aggregate incoming buffer cap overflows",
            Self::RetryBudgetTooSmall => "the Retry attempt budget cannot complete validation",
            Self::PortSpanTooLarge => "the UDP port-range span is invalid",
            Self::SameRouteReplacementBudget => "same-route replacement budget must be exactly one",
            Self::RouteObservationExceedsPoll => {
                "route observation bound exceeds the fallback-poll interval"
            }
            Self::DeadlineOverflow => "an absolute deadline cannot be represented",
        };
        f.write_str(message)
    }
}

impl std::fmt::Display for DeadlinePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ServerLease => "server lease",
            Self::Handshake => "QUIC handshake",
            Self::Authentication => "stream authentication",
            Self::ClientConnect => "client connect/authentication",
            Self::TargetConnect => "authorized target connect",
            Self::Finalize => "endpoint finalization",
        };
        f.write_str(message)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BootstrapMalformed => f.write_str("malformed bootstrap record"),
            Self::SshConnectionMalformed => f.write_str("malformed SSH_CONNECTION"),
            Self::ServerStartMalformed => f.write_str("malformed private server-start record"),
            Self::ReleaseRejected => f.write_str("private server release was not authorized"),
            Self::InvalidSshArgument => f.write_str("SSH argument rejected by bootstrap policy"),
            Self::SshPolicyRejected => {
                f.write_str("effective SSH proxy configuration is not permitted")
            }
            Self::SshProcessFailed => f.write_str("owned OpenSSH bootstrap process failed"),
            Self::BootstrapTimedOut => f.write_str("absolute bootstrap deadline expired"),
            Self::BridgeIncomplete => f.write_str("byte bridge did not drain and finalize cleanly"),
            Self::AuthRejected => f.write_str("authentication rejected"),
            Self::PinMismatch => {
                f.write_str("server SPKI does not match the authenticated bootstrap pin")
            }
            Self::VersionUnsupported => f.write_str("unsupported protocol version"),
            Self::TokenReuse => f.write_str("one-use token already consumed"),
            Self::TargetUnauthorized => f.write_str("target not authorized by bootstrap"),
            Self::LeaseExpired => f.write_str("one-shot server lease expired"),
            Self::IdentityRandomness => f.write_str("ephemeral identity randomness unavailable"),
            Self::IdentityKeyGeneration => f.write_str("ephemeral signing-key generation failed"),
            Self::IdentityCertificateGeneration => {
                f.write_str("ephemeral certificate generation failed")
            }
            Self::IdentityCertificateMalformed => {
                f.write_str("generated certificate has malformed SubjectPublicKeyInfo")
            }
            Self::IdentitySigningKey => f.write_str("ephemeral signing key was rejected"),
            Self::IdentityUnavailable => f.write_str("ephemeral identity secret is unavailable"),
            Self::RuntimeUnavailable => f.write_str("Tokio runtime is unavailable"),
            Self::TlsConfiguration => f.write_str("locked TLS configuration failed"),
            Self::InvalidEndpoint(reason) => write!(f, "invalid authenticated endpoint: {reason}"),
            Self::InvalidUdpPolicy(reason) => write!(f, "invalid UDP policy: {reason}"),
            Self::InvalidLimits(reason) => write!(f, "invalid finite limits: {reason}"),
            Self::RouteSelection(source) => {
                write!(f, "kernel UDP route selection failed: {source}")
            }
            Self::UdpBind(source) => write!(f, "UDP bind failed: {source}"),
            Self::PortRangeExhausted => f.write_str("bounded UDP port range exhausted"),
            Self::EndpointClosed => f.write_str("QUIC endpoint closed"),
            Self::RetryFailed => f.write_str("QUIC Retry could not be issued"),
            Self::RetryLimitExceeded => f.write_str("finite QUIC Retry attempt budget exhausted"),
            Self::AddressNotValidated => {
                f.write_str("client address was not validated by server Retry")
            }
            Self::QuicConnect => f.write_str("QUIC connection setup failed"),
            Self::QuicConnection => f.write_str("QUIC connection failed"),
            Self::StreamOpen => f.write_str("required QUIC bidirectional stream unavailable"),
            Self::StreamRead => f.write_str("QUIC authentication stream read failed"),
            Self::StreamWrite => f.write_str("QUIC authentication stream write failed"),
            Self::BridgeAllocation => f.write_str("fixed bridge buffer allocation failed"),
            Self::BridgeAdmissionClosed => f.write_str("bridge admission is no longer running"),
            Self::DeadlineExpired(phase) => write!(f, "absolute {phase} deadline expired"),
            Self::TokenStateUnavailable => f.write_str("one-use token state unavailable"),
            Self::TargetConnect(source) => {
                write!(f, "authorized loopback target connect failed: {source}")
            }
            Self::Io(source) => write!(f, "io: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RouteSelection(source)
            | Self::UdpBind(source)
            | Self::TargetConnect(source)
            | Self::Io(source) => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}
