//! Typed errors for eversh. Display output never contains secrets, tokens,
//! payload bytes, or raw environment values.

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
    /// SSH destination token failed conservative validation.
    HostInvalid,
    /// An origin label failed validation or exceeded its bounds.
    OriginInvalid,
    /// Unpadded base64url input was malformed or non-canonical.
    Base64Malformed,
    /// A control request carried unknown flag bits.
    FlagsInvalid,
    /// The current executable path cannot be quoted as a safe shell word.
    SelfExeUnsafe,
    /// The local link-status file path cannot be quoted as a safe
    /// ProxyCommand argument word.
    StatusPathUnsafe,
    /// A remote binary word failed conservative validation.
    RemoteWordInvalid,
    /// A user-supplied SSH option failed the audited allowlist.
    SshOptionRejected,
    /// Remote-role argument grammar violation (private protocol).
    RoleProtocol(&'static str),
    /// The remote-role protocol version word is unsupported.
    RoleVersionUnsupported,
    /// A non-interactive remote command exited with a failure code.
    RemoteCommandFailed(u8),
    /// A non-interactive remote command was terminated by a signal.
    RemoteCommandSignaled(i32),
    /// Captured remote list output exceeded its configured cap.
    ListOutputTooLarge,
    /// Captured remote list output was not parseable discovery data.
    ListOutputInvalid,
    /// Supervisor limits failed validation.
    LimitsInvalid,
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
            Self::HostInvalid => write!(f, "invalid SSH destination"),
            Self::OriginInvalid => write!(f, "invalid origin label"),
            Self::Base64Malformed => write!(f, "malformed base64url request token"),
            Self::FlagsInvalid => write!(f, "unknown control-request flags"),
            Self::SelfExeUnsafe => {
                write!(f, "the eversh executable path is not a safe shell word")
            }
            Self::StatusPathUnsafe => {
                write!(f, "the link-status file path is not a safe shell word")
            }
            Self::RemoteWordInvalid => write!(f, "invalid remote command word"),
            Self::SshOptionRejected => {
                write!(f, "SSH option rejected by the audited allowlist")
            }
            Self::RoleProtocol(detail) => write!(f, "everpty role protocol: {detail}"),
            Self::RoleVersionUnsupported => write!(
                f,
                "eversh everpty-role remote protocol version is unsupported (expected v1)"
            ),
            Self::RemoteCommandFailed(code) => {
                write!(f, "remote command failed with exit code {code}")
            }
            Self::RemoteCommandSignaled(signal) => {
                write!(f, "remote command terminated by signal {signal}")
            }
            Self::ListOutputTooLarge => write!(f, "remote list output exceeds its cap"),
            Self::ListOutputInvalid => write!(f, "remote list output is not valid discovery data"),
            Self::LimitsInvalid => write!(f, "supervisor limits failed validation"),
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
