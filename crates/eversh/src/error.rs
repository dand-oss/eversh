//! Typed errors for eversh.

#[derive(Debug)]
pub enum Error {
    NameInvalid,
    RequestTooLarge,
    ArgCountExceeded,
    NullInArg,
    VersionUnsupported,
    PathTooLong,
    RoleUnknown,
    NotImplementedInM1,
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameInvalid => write!(f, "invalid session name"),
            Self::RequestTooLarge => write!(f, "remote-control request exceeds its cap"),
            Self::ArgCountExceeded => write!(f, "remote-control request has too many arguments"),
            Self::NullInArg => write!(f, "NUL byte in argument"),
            Self::VersionUnsupported => write!(f, "unsupported protocol version"),
            Self::PathTooLong => write!(f, "socket path exceeds the Unix pathname limit"),
            Self::RoleUnknown => write!(f, "unknown role"),
            Self::NotImplementedInM1 => write!(f, "not implemented in M1"),
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
