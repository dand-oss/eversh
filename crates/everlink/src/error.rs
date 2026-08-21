//! Typed errors for everlink.

#[derive(Debug)]
pub enum Error {
    BootstrapMalformed,
    AuthRejected,
    PinMismatch,
    VersionUnsupported,
    TokenReuse,
    TargetUnauthorized,
    LeaseExpired,
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BootstrapMalformed => write!(f, "malformed bootstrap record"),
            Self::AuthRejected => write!(f, "authentication rejected"),
            Self::PinMismatch => write!(f, "server SPKI does not match the bootstrap pin"),
            Self::VersionUnsupported => write!(f, "unsupported protocol version"),
            Self::TokenReuse => write!(f, "one-use token already consumed"),
            Self::TargetUnauthorized => write!(f, "target not authorized by bootstrap"),
            Self::LeaseExpired => write!(f, "one-shot server lease expired"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
