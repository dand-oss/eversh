//! Private, payload-free `everudp-status-v1` transition journal.

use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

const PREFIX: &str = "everudp-status-v1";
const PRIVATE_MODE: u32 = 0o600;
const HEARTBEAT_INTERVAL_MS: u64 = 60_000;

#[derive(Debug)]
pub enum StatusError {
    Io(io::Error),
    UnsafeFile,
    ClockWentBackwards,
}

impl fmt::Display for StatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::UnsafeFile => formatter.write_str("unsafe everudp status file"),
            Self::ClockWentBackwards => formatter.write_str("everudp status clock went backwards"),
        }
    }
}

impl std::error::Error for StatusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for StatusError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Connecting,
    Connected,
    Carrying,
    Migrating,
    Disconnected { ambiguous_input: usize },
    Reconnecting { ambiguous_input: usize },
    RecoveringOverSsh { ambiguous_input: usize },
    Gapped,
}

impl LinkState {
    fn disconnected_input(self) -> Option<usize> {
        match self {
            Self::Disconnected { ambiguous_input }
            | Self::Reconnecting { ambiguous_input }
            | Self::RecoveringOverSsh { ambiguous_input } => Some(ambiguous_input),
            Self::Connecting
            | Self::Connected
            | Self::Carrying
            | Self::Migrating
            | Self::Gapped => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalCause {
    CleanClose,
    Authentication,
    Protocol,
    PtyExit,
    Killed,
    LocalCancel,
    Transport,
}

impl TerminalCause {
    fn word(self) -> &'static str {
        match self {
            Self::CleanClose => "clean-close",
            Self::Authentication => "authentication",
            Self::Protocol => "protocol",
            Self::PtyExit => "pty-exit",
            Self::Killed => "killed",
            Self::LocalCancel => "local-cancel",
            Self::Transport => "transport",
        }
    }

    fn parse(word: &str) -> Option<Self> {
        match word {
            "clean-close" => Some(Self::CleanClose),
            "authentication" => Some(Self::Authentication),
            "protocol" => Some(Self::Protocol),
            "pty-exit" => Some(Self::PtyExit),
            "killed" => Some(Self::Killed),
            "local-cancel" => Some(Self::LocalCancel),
            "transport" => Some(Self::Transport),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusRecord {
    Transition(LinkState),
    DisconnectedHeartbeat {
        elapsed_ms: u64,
        ambiguous_input: usize,
    },
    Terminal {
        cause: TerminalCause,
        carried: bool,
        ambiguous_input: usize,
    },
}

/// An exclusively created 0600 journal. The open descriptor, rather than a
/// repeatedly resolved path, is retained for the process lifetime.
pub struct StatusFile {
    file: File,
    state: Option<LinkState>,
    disconnected_since_ms: Option<u64>,
    last_heartbeat_ms: Option<u64>,
}

impl StatusFile {
    pub fn create_private(path: &Path) -> Result<Self, StatusError> {
        let descriptor = everpty::sys::create_exclusive_private(path)?;
        let file = File::from(descriptor);
        file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_MODE))?;
        validate_private(&file)?;
        Ok(Self {
            file,
            state: None,
            disconnected_since_ms: None,
            last_heartbeat_ms: None,
        })
    }

    pub fn transition(&mut self, state: LinkState, now_ms: u64) -> Result<bool, StatusError> {
        if self.state == Some(state) {
            return Ok(false);
        }
        let line = match state {
            LinkState::Connecting => format!("{PREFIX} state connecting\n"),
            LinkState::Connected => format!("{PREFIX} state connected\n"),
            LinkState::Carrying => format!("{PREFIX} state carrying\n"),
            LinkState::Migrating => format!("{PREFIX} state migrating\n"),
            LinkState::Disconnected { ambiguous_input } => {
                format!("{PREFIX} state disconnected ambiguous-input={ambiguous_input}\n")
            }
            LinkState::Reconnecting { ambiguous_input } => {
                format!("{PREFIX} state reconnecting ambiguous-input={ambiguous_input}\n")
            }
            LinkState::RecoveringOverSsh { ambiguous_input } => {
                format!("{PREFIX} state recovering-over-ssh ambiguous-input={ambiguous_input}\n")
            }
            LinkState::Gapped => format!("{PREFIX} state gapped\n"),
        };
        self.append(&line)?;
        let was_disconnected = self.state.and_then(LinkState::disconnected_input).is_some();
        let is_disconnected = state.disconnected_input().is_some();
        self.state = Some(state);
        if is_disconnected && !was_disconnected {
            self.disconnected_since_ms = Some(now_ms);
            self.last_heartbeat_ms = Some(now_ms);
        } else if !is_disconnected {
            self.disconnected_since_ms = None;
            self.last_heartbeat_ms = None;
        }
        Ok(true)
    }

    /// Emits at most one disconnected heartbeat per full minute. Calling this
    /// while connected is a no-op.
    pub fn heartbeat(&mut self, now_ms: u64) -> Result<bool, StatusError> {
        let Some(ambiguous_input) = self.state.and_then(LinkState::disconnected_input) else {
            return Ok(false);
        };
        let since = self
            .disconnected_since_ms
            .ok_or(StatusError::ClockWentBackwards)?;
        let last = self
            .last_heartbeat_ms
            .ok_or(StatusError::ClockWentBackwards)?;
        if now_ms < since || now_ms < last {
            return Err(StatusError::ClockWentBackwards);
        }
        if now_ms - last < HEARTBEAT_INTERVAL_MS {
            return Ok(false);
        }
        self.append(&format!(
            "{PREFIX} heartbeat disconnected elapsed-ms={} ambiguous-input={ambiguous_input}\n",
            now_ms - since
        ))?;
        self.last_heartbeat_ms = Some(now_ms);
        Ok(true)
    }

    pub fn terminal(
        &mut self,
        cause: TerminalCause,
        carried: bool,
        ambiguous_input: usize,
    ) -> Result<(), StatusError> {
        self.append(&format!(
            "{PREFIX} cause {} carried={} ambiguous-input={ambiguous_input}\n",
            cause.word(),
            u8::from(carried)
        ))
    }

    fn append(&mut self, line: &str) -> Result<(), StatusError> {
        validate_private(&self.file)?;
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        Ok(())
    }
}

impl fmt::Debug for StatusFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatusFile")
            .field("state", &self.state)
            .field("disconnected_since_ms", &self.disconnected_since_ms)
            .field("last_heartbeat_ms", &self.last_heartbeat_ms)
            .finish_non_exhaustive()
    }
}

pub fn parse_line(line: &str) -> Option<StatusRecord> {
    let rest = line.strip_prefix(PREFIX)?.strip_prefix(' ')?;
    match rest {
        "state connecting" => return Some(StatusRecord::Transition(LinkState::Connecting)),
        "state connected" => return Some(StatusRecord::Transition(LinkState::Connected)),
        "state carrying" => return Some(StatusRecord::Transition(LinkState::Carrying)),
        "state migrating" => return Some(StatusRecord::Transition(LinkState::Migrating)),
        "state gapped" => return Some(StatusRecord::Transition(LinkState::Gapped)),
        _ => {}
    }
    if let Some(value) = rest.strip_prefix("state disconnected ambiguous-input=") {
        return Some(StatusRecord::Transition(LinkState::Disconnected {
            ambiguous_input: value.parse().ok()?,
        }));
    }
    if let Some(value) = rest.strip_prefix("state reconnecting ambiguous-input=") {
        return Some(StatusRecord::Transition(LinkState::Reconnecting {
            ambiguous_input: value.parse().ok()?,
        }));
    }
    if let Some(value) = rest.strip_prefix("state recovering-over-ssh ambiguous-input=") {
        return Some(StatusRecord::Transition(LinkState::RecoveringOverSsh {
            ambiguous_input: value.parse().ok()?,
        }));
    }
    if let Some(rest) = rest.strip_prefix("heartbeat disconnected elapsed-ms=") {
        let (elapsed, ambiguous) = rest.split_once(" ambiguous-input=")?;
        return Some(StatusRecord::DisconnectedHeartbeat {
            elapsed_ms: elapsed.parse().ok()?,
            ambiguous_input: ambiguous.parse().ok()?,
        });
    }
    let rest = rest.strip_prefix("cause ")?;
    let (cause, rest) = rest.split_once(" carried=")?;
    let (carried, ambiguous) = rest.split_once(" ambiguous-input=")?;
    Some(StatusRecord::Terminal {
        cause: TerminalCause::parse(cause)?,
        carried: match carried {
            "0" => false,
            "1" => true,
            _ => return None,
        },
        ambiguous_input: ambiguous.parse().ok()?,
    })
}

fn validate_private(file: &File) -> Result<(), StatusError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != everpty::sys::effective_uid()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != PRIVATE_MODE
    {
        return Err(StatusError::UnsafeFile);
    }
    // Keep the descriptor in the validation surface so a future refactor
    // cannot silently replace descriptor validation with path validation.
    everpty::sys::validate_fd(file.as_fd())?;
    Ok(())
}
