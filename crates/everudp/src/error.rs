use crate::wire::{Kind, StreamRole};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitViolation {
    BootstrapRecordMax,
    ControlFrameMax,
    TerminalFrameMax,
    QueueBytesPerDirection,
    QueueOperationsPerDirection,
    GlobalQueueBytes,
    CopyBufferBytes,
    InitialUdpBudget,
    InvitationBytes,
    InvitationLifetime,
    MaxPendingInvitations,
    MaxObservers,
    Keepalive,
    IdleTimeout,
    FirstSshRecovery,
    SshRecoveryInterval,
    SafeInitialMtu,
    StreamCounts,
}

impl fmt::Display for LimitViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "locked everudp limit changed: {self:?}")
    }
}

impl std::error::Error for LimitViolation {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    InvalidLimits(LimitViolation),
    Incomplete {
        needed: usize,
        available: usize,
    },
    OutputTooSmall {
        needed: usize,
        available: usize,
    },
    VersionUnsupported(u8),
    DatagramDirection(u8),
    UnknownKind(u8),
    KindNotAllowed {
        kind: Kind,
        stream: StreamRole,
    },
    PayloadTooLarge {
        kind: Kind,
        length: usize,
        maximum: usize,
    },
    LengthInvalid {
        kind: Kind,
        length: usize,
    },
    LengthOverflow,
    DuplicateStream(StreamRole),
    ObserverInputStream,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(error) => write!(formatter, "{error}"),
            Self::Incomplete { .. } => formatter.write_str("incomplete everudp record"),
            Self::OutputTooSmall { .. } => {
                formatter.write_str("everudp record output buffer is too small")
            }
            Self::VersionUnsupported(_) => {
                formatter.write_str("everudp wire version is unsupported")
            }
            Self::DatagramDirection(_) => {
                formatter.write_str("everudp fast datagram direction is invalid")
            }
            Self::UnknownKind(_) => formatter.write_str("unknown everudp record kind"),
            Self::KindNotAllowed { .. } => {
                formatter.write_str("everudp record kind is invalid for its stream")
            }
            Self::PayloadTooLarge { .. } => {
                formatter.write_str("everudp record exceeds its payload cap")
            }
            Self::LengthInvalid { .. } => {
                formatter.write_str("everudp record has a non-canonical payload length")
            }
            Self::LengthOverflow => formatter.write_str("everudp record length overflow"),
            Self::DuplicateStream(_) => formatter.write_str("duplicate everudp stream"),
            Self::ObserverInputStream => {
                formatter.write_str("an everudp observer cannot open an input stream")
            }
        }
    }
}

impl std::error::Error for WireError {}

impl From<LimitViolation> for WireError {
    fn from(value: LimitViolation) -> Self {
        Self::InvalidLimits(value)
    }
}

#[derive(Debug)]
pub enum Error {
    Limits(LimitViolation),
    Wire(WireError),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => write!(formatter, "{error}"),
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Limits(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<LimitViolation> for Error {
    fn from(value: LimitViolation) -> Self {
        Self::Limits(value)
    }
}

impl From<WireError> for Error {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
