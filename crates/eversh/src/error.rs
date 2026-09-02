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
    /// The current executable path cannot be quoted as a safe ProxyCommand
    /// word (not absolute, non-UTF-8, quotes, control bytes, or a percent
    /// token OpenSSH would expand inside the quoted word).
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
    /// The private per-spawn everssh link-status channel could not be
    /// allocated for a classification-carrying spawn (design 3, 7): the
    /// operation fails closed with this local error BEFORE any ssh child
    /// exists, because an uninstrumented spawn's missing record would
    /// classify an ordinary 255 (an auth or policy failure) as a transport
    /// failure and wrongly enter the reconnect path.
    LinkStatusChannel {
        /// The state root allocation was attempted under, when one
        /// resolved at all.
        root: Option<std::path::PathBuf>,
        /// Why allocation failed.
        fault: LinkStatusFault,
    },
    Io(std::io::Error),
}

/// Why the private per-spawn link-status channel could not be allocated
/// (design 3, 7).
#[derive(Debug)]
pub enum LinkStatusFault {
    /// No state-root candidate resolved at all: there is no private root
    /// to allocate the per-spawn file under.
    NoRoot,
    /// The private `link-status` directory under the state root could not
    /// be created — an unwritable or otherwise unallocatable root.
    RootUnusable(std::io::Error),
    /// The resolved path cannot be embedded as the single-quoted
    /// `--status-file` ProxyCommand word: OpenSSH expands percent tokens
    /// inside quoted ProxyCommand words before the local shell sees the
    /// quotes, so a state root carrying `%` (like quotes, control bytes,
    /// or non-UTF-8) is rejected outright, never escaped.
    UnsafePath,
    /// Exclusive creation of the per-spawn `0600` file failed.
    FileCreate(std::io::Error),
}

impl std::fmt::Display for LinkStatusFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRoot => write!(
                f,
                "no state root resolved (set EVERSH_STATE_DIR, XDG_RUNTIME_DIR, XDG_STATE_HOME, or HOME)"
            ),
            Self::RootUnusable(error) => {
                write!(f, "cannot create the private link-status directory ({error})")
            }
            Self::UnsafePath => write!(
                f,
                "state root path is not a safe ProxyCommand word (percent tokens rejected)"
            ),
            Self::FileCreate(error) => {
                write!(f, "cannot create the per-spawn status file ({error})")
            }
        }
    }
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
                write!(
                    f,
                    "the eversh executable path is not a safe ProxyCommand word"
                )
            }
            Self::StatusPathUnsafe => {
                write!(
                    f,
                    "the link-status file path is not a safe ProxyCommand word"
                )
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
            Self::LinkStatusChannel { root, fault } => match root {
                Some(root) => write!(
                    f,
                    "cannot allocate the private link-status channel under {}: {fault}",
                    root.display()
                ),
                None => write!(
                    f,
                    "cannot allocate the private link-status channel: {fault}"
                ),
            },
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
