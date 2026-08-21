//! Pure lifecycle and writer-ownership state machines (design 5.1-5.3).
//!
//! M1 delivers the transitions as pure functions with exhaustive tests;
//! M2 wires them to real PTYs, sockets, and timers. First-cause-wins
//! terminal semantics mirror the M0 shutdown design.

/// Broker application lifecycle. `Failed` is terminal for startup failures;
/// `Exited` is terminal for a finished child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Starting,
    WaitingForWriter,
    Running,
    Exited,
    Failed,
}

/// Writer ownership, independent of the lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    NoWriter,
    Writer(u32),
}

/// A terminal cause; the first recorded cause wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalCause {
    ChildExit { signal: bool, value: u32 },
    KillRequested,
    StartupDeadline,
    InternalError,
}

/// Pure state machine: `(lifecycle, ownership, cause)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerState {
    pub lifecycle: Lifecycle,
    pub ownership: Ownership,
    pub terminal: Option<TerminalCause>,
}

#[derive(Debug)]
pub struct InvalidTransition(pub &'static str);

impl std::fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid transition: {}", self.0)
    }
}
impl std::error::Error for InvalidTransition {}

impl BrokerState {
    /// A broker binds its socket and becomes ready before any child exists.
    pub fn new() -> Self {
        Self {
            lifecycle: Lifecycle::Starting,
            ownership: Ownership::NoWriter,
            terminal: None,
        }
    }

    /// Socket bound and readiness signaled; now waiting for the initial
    /// writer before spawning the child.
    pub fn ready(&self) -> Result<Self, InvalidTransition> {
        match self.lifecycle {
            Lifecycle::Starting => Ok(Self {
                lifecycle: Lifecycle::WaitingForWriter,
                ..*self
            }),
            _ => Err(InvalidTransition("ready() from non-Starting")),
        }
    }

    /// The initial writer arrived (with real dimensions) before the startup
    /// deadline; the child may be spawned and Running begins.
    pub fn initial_writer(&self, client_id: u32) -> Result<Self, InvalidTransition> {
        match (self.lifecycle, self.ownership) {
            (Lifecycle::WaitingForWriter, Ownership::NoWriter) => Ok(Self {
                lifecycle: Lifecycle::Running,
                ownership: Ownership::Writer(client_id),
                terminal: None,
            }),
            _ => Err(InvalidTransition(
                "initial_writer() requires WaitingForWriter with no writer",
            )),
        }
    }

    /// The initial writer never arrived: terminal failure, no child spawned.
    pub fn startup_deadline(&self) -> Result<Self, InvalidTransition> {
        match self.lifecycle {
            Lifecycle::WaitingForWriter => Ok(Self {
                lifecycle: Lifecycle::Failed,
                terminal: self.terminal.or(Some(TerminalCause::StartupDeadline)),
                ..*self
            }),
            _ => Err(InvalidTransition("startup_deadline() from non-Waiting")),
        }
    }

    /// Writer attach while Running. A second writer without takeover is
    /// `Busy` and changes nothing; with takeover the old writer is revoked
    /// atomically (design 5.2: Revoked-then-Granted at an output boundary).
    pub fn writer_request(
        &self,
        client_id: u32,
        take_over: bool,
    ) -> Result<(Self, WriterRequestOutcome), InvalidTransition> {
        match self.lifecycle {
            Lifecycle::Running => match self.ownership {
                Ownership::NoWriter => Ok((
                    Self {
                        ownership: Ownership::Writer(client_id),
                        ..*self
                    },
                    WriterRequestOutcome::Granted,
                )),
                Ownership::Writer(current) if !take_over => Ok((
                    Self { ..*self },
                    WriterRequestOutcome::Busy {
                        current_writer_id: current,
                    },
                )),
                Ownership::Writer(current) => Ok((
                    Self {
                        ownership: Ownership::Writer(client_id),
                        ..*self
                    },
                    WriterRequestOutcome::TakeOver {
                        old_writer_id: current,
                    },
                )),
            },
            _ => Err(InvalidTransition("writer_request() requires Running")),
        }
    }

    /// Writer disconnect, stall deadline, or explicit detach: ownership
    /// becomes empty; future output drains to observers or is discarded;
    /// never replayed.
    pub fn revoke_writer(&self) -> Result<Self, InvalidTransition> {
        match self.lifecycle {
            Lifecycle::Running => Ok(Self {
                ownership: Ownership::NoWriter,
                ..*self
            }),
            _ => Err(InvalidTransition("revoke_writer() requires Running")),
        }
    }

    /// Terminal: child exit or completed kill. Records the first cause only.
    pub fn terminal(&self, cause: TerminalCause, exited: bool) -> Result<Self, InvalidTransition> {
        if self.terminal.is_some() {
            return Ok(*self); // first cause wins; idempotent
        }
        let lifecycle = if exited
            || matches!(
                cause,
                TerminalCause::ChildExit { .. } | TerminalCause::KillRequested
            ) {
            Lifecycle::Exited
        } else {
            Lifecycle::Failed
        };
        Ok(Self {
            lifecycle,
            terminal: Some(cause),
            ownership: Ownership::NoWriter,
        })
    }
}

impl Default for BrokerState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterRequestOutcome {
    Granted,
    Busy {
        current_writer_id: u32,
    },
    /// Old writer revoked; queued input/resize from it are rejected; the old
    /// writer may continue as an observer and receives Revoked before any
    /// subsequent output.
    TakeOver {
        old_writer_id: u32,
    },
}
