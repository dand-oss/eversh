//! Typed errors for everpty. No panics on protocol input; sources are kept.

#[derive(Debug)]
pub enum Error {
    AlreadyExists,
    NotLive,
    Busy { current_writer_id: u32 },
    NameInvalid,
    SocketStale,
    StartupDeadline,
    PathTooLong,
    MetadataInvalid,
    MetadataTooLarge,
    StateRootUnavailable,
    StatePathUnsafe,
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists => write!(f, "session already exists"),
            Self::NotLive => write!(f, "session is not live"),
            Self::Busy { current_writer_id } => {
                write!(f, "writer busy (current writer {current_writer_id})")
            }
            Self::NameInvalid => write!(f, "invalid session name"),
            Self::SocketStale => write!(f, "stale session socket"),
            Self::StartupDeadline => write!(f, "startup deadline expired"),
            Self::PathTooLong => write!(f, "socket path exceeds the Unix pathname limit"),
            Self::MetadataInvalid => write!(f, "invalid session metadata record"),
            Self::MetadataTooLarge => write!(f, "session metadata record exceeds the size cap"),
            Self::StateRootUnavailable => write!(f, "no usable state directory candidate"),
            Self::StatePathUnsafe => write!(f, "state path has unsafe type, owner, or mode"),
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
