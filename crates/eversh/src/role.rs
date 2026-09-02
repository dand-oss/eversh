//! Pure role selection for the combined binary (design 2).
//!
//! `select_role` chooses exactly one logical role from the argument vector
//! BEFORE any runtime initialization. It is pure and total: no I/O, no
//! environment, no process exit. Only the everlink role may construct the
//! single Tokio runtime; the runtime-construction counter in
//! `everlink::runtime` stays at zero for every other role.

use crate::error::Error;
use crate::limits::Limits;
use crate::remote::{base64url_decode, validate_name, ControlRequest};

/// Combined-binary role marker for the everpty role.
pub const EVERPTY_ROLE: &str = "__everpty";
/// Combined-binary role marker for the everlink role. Must equal
/// `everlink::ssh_policy::COMBINED_EVERLINK_ROLE` (cross-crate test).
pub const EVERLINK_ROLE: &str = "__everlink";
/// Version word of the private everpty-role remote grammar. Unknown versions
/// fail closed with a diagnostic naming the component and version (design 8).
pub const EVERPTY_ROLE_VERSION: &str = "v1";

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
        Some(EVERPTY_ROLE) => Role::Everpty,
        Some(EVERLINK_ROLE) => Role::Everlink,
        _ => Role::Supervisor,
    }
}

/// One parsed everpty-role remote operation (the words after `__everpty`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EverptyRoleCommand {
    AttachOrCreate {
        name: String,
        request: ControlRequest,
    },
    Attach {
        name: String,
        request: ControlRequest,
    },
    Observe {
        name: String,
    },
    List {
        json: bool,
        filter_origin: Option<String>,
    },
    Probe {
        name: String,
    },
    Detach {
        name: String,
    },
    Kill {
        name: String,
    },
}

fn parsed_name(word: Option<&String>, limits: &Limits) -> Result<String, Error> {
    let name = word.ok_or(Error::RoleProtocol("missing session name"))?;
    if !validate_name(name, limits) {
        return Err(Error::NameInvalid);
    }
    Ok(name.clone())
}

fn parsed_request(word: Option<&String>, limits: &Limits) -> Result<ControlRequest, Error> {
    let token = word.ok_or(Error::RoleProtocol("missing request token"))?;
    let bytes = base64url_decode(token, limits.remote_control_max)?;
    ControlRequest::decode(&bytes, limits)
}

fn exactly(args: &[String], count: usize) -> Result<(), Error> {
    if args.len() == count {
        Ok(())
    } else {
        Err(Error::RoleProtocol("wrong argument count"))
    }
}

/// Parse the private everpty-role grammar. Pure and strict: the version word
/// is checked first, every operation has an exact argument count, names are
/// validated before use, and the single base64url token is decoded through
/// the bounded control-request codec.
pub fn parse_everpty_role(args: &[String], limits: &Limits) -> Result<EverptyRoleCommand, Error> {
    match args.first().map(String::as_str) {
        Some(EVERPTY_ROLE_VERSION) => {}
        Some(_) | None => return Err(Error::RoleVersionUnsupported),
    }
    let rest = &args[1..];
    match rest.first().map(String::as_str) {
        Some("attach-or-create") => {
            exactly(rest, 3)?;
            Ok(EverptyRoleCommand::AttachOrCreate {
                name: parsed_name(rest.get(1), limits)?,
                request: parsed_request(rest.get(2), limits)?,
            })
        }
        Some("attach") => {
            exactly(rest, 3)?;
            Ok(EverptyRoleCommand::Attach {
                name: parsed_name(rest.get(1), limits)?,
                request: parsed_request(rest.get(2), limits)?,
            })
        }
        Some("observe") => {
            exactly(rest, 2)?;
            Ok(EverptyRoleCommand::Observe {
                name: parsed_name(rest.get(1), limits)?,
            })
        }
        Some("list") => {
            if rest.len() != 2 && rest.len() != 3 {
                return Err(Error::RoleProtocol("wrong argument count"));
            }
            let json = match rest.get(1).map(String::as_str) {
                Some("json") => true,
                Some("text") => false,
                _ => return Err(Error::RoleProtocol("unknown list format")),
            };
            let filter_origin = match rest.get(2) {
                None => None,
                Some(token) => {
                    let bytes = base64url_decode(token, limits.origin_label_max)?;
                    let label = String::from_utf8(bytes).map_err(|_| Error::OriginInvalid)?;
                    crate::remote::validate_origin_label(&label, limits)?;
                    Some(label)
                }
            };
            Ok(EverptyRoleCommand::List {
                json,
                filter_origin,
            })
        }
        Some("probe") => {
            exactly(rest, 2)?;
            Ok(EverptyRoleCommand::Probe {
                name: parsed_name(rest.get(1), limits)?,
            })
        }
        Some("detach") => {
            exactly(rest, 2)?;
            Ok(EverptyRoleCommand::Detach {
                name: parsed_name(rest.get(1), limits)?,
            })
        }
        Some("kill") => {
            exactly(rest, 2)?;
            Ok(EverptyRoleCommand::Kill {
                name: parsed_name(rest.get(1), limits)?,
            })
        }
        Some(_) => Err(Error::RoleProtocol("unknown operation")),
        None => Err(Error::RoleProtocol("missing operation")),
    }
}
