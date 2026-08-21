//! Pure role selection for the combined binary (design 2).
//!
//! `select_role` chooses exactly one logical role from the argument vector
//! BEFORE any runtime initialization. It is pure and total: no I/O, no
//! environment, no process exit. Only the everlink role may construct the
//! single Tokio runtime; the runtime-construction counter in
//! `everlink::runtime` stays at zero for every other role.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// User-facing supervisor commands (connect/attach/observe/list/...).
    Supervisor,
    /// Private dispatch to the everpty broker/attach edge.
    Everpty,
    /// Private dispatch to the everlink QUIC edge (the only role that may
    /// build the single Tokio runtime).
    Everlink,
}

/// Select exactly one role from the process arguments (argv without argv[0]
/// or the full argv — both accepted). A role marker is recognized ONLY as
/// the first argument; anything else is a supervisor invocation.
pub fn select_role<T: AsRef<str>>(args: &[T]) -> Role {
    match args.first().map(|a| a.as_ref()) {
        Some("__everpty") => Role::Everpty,
        Some("__everlink") => Role::Everlink,
        _ => Role::Supervisor,
    }
}
