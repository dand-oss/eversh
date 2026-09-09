//! Typed orchestration for SSH bootstrap and persistent gateway process roles.

use crate::admission::{AdmissionError, GatewayGeneration, InvitationStore};
use crate::bootstrap::{BootstrapError, BootstrapRecord};
use crate::gateway::{
    acquire_gateway_state, GatewayBootstrapContext, GatewayControlRequest, GatewayError,
    GatewayState,
};
use crate::gateway_runner::{run_gateway, GatewayRunError};
use crate::identity::{GatewayIdentity, IdentityError};
use crate::request::{BootstrapOperation, BootstrapRequest, RequestError};
use crate::transport::{GatewayEndpoint, SharedInvitationStore, TransportError};
use crate::Limits;
use everpty::run::{Context, EnsureSessionOutcome, EnsureSessionRequest};
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

pub const COMBINED_EVERUDP_ROLE: &str = "__everudp";
pub const BOOTSTRAP_PARENT_ROLE: &str = "__bootstrap-parent-v1";
pub const GATEWAY_ROLE: &str = "__gateway-v1";

#[derive(Debug)]
pub enum RoleError {
    Everpty(everpty::Error),
    Everssh(everssh::Error),
    Request(RequestError),
    Bootstrap(BootstrapError),
    Admission(AdmissionError),
    Identity(IdentityError),
    Transport(TransportError),
    Gateway(GatewayError),
    GatewayRun(GatewayRunError),
    ClientRun(crate::ClientRunError),
    Io(io::Error),
    Child,
    AssociationMismatch,
}

impl fmt::Display for RoleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Everpty(error) => write!(formatter, "{error}"),
            Self::Everssh(error) => write!(formatter, "{error}"),
            Self::Request(error) => write!(formatter, "{error}"),
            Self::Bootstrap(error) => write!(formatter, "{error}"),
            Self::Admission(error) => write!(formatter, "{error}"),
            Self::Identity(error) => write!(formatter, "{error}"),
            Self::Transport(error) => write!(formatter, "{error}"),
            Self::Gateway(error) => write!(formatter, "{error}"),
            Self::GatewayRun(error) => write!(formatter, "{error}"),
            Self::ClientRun(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Child => formatter.write_str("everudp gateway child failed"),
            Self::AssociationMismatch => {
                formatter.write_str("everudp bootstrap association does not match")
            }
        }
    }
}

impl std::error::Error for RoleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Everpty(error) => Some(error),
            Self::Everssh(error) => Some(error),
            Self::Request(error) => Some(error),
            Self::Bootstrap(error) => Some(error),
            Self::Admission(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Gateway(error) => Some(error),
            Self::GatewayRun(error) => Some(error),
            Self::ClientRun(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Child | Self::AssociationMismatch => None,
        }
    }
}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for RoleError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}

from_error!(everpty::Error, Everpty);
from_error!(everssh::Error, Everssh);
from_error!(RequestError, Request);
from_error!(BootstrapError, Bootstrap);
from_error!(AdmissionError, Admission);
from_error!(IdentityError, Identity);
from_error!(TransportError, Transport);
from_error!(GatewayError, Gateway);
from_error!(GatewayRunError, GatewayRun);
from_error!(crate::ClientRunError, ClientRun);
from_error!(io::Error, Io);

#[derive(Debug)]
pub enum BootstrapPreparation {
    Ready {
        request: BootstrapRequest,
        state_root: PathBuf,
    },
    Broker(everpty::broker::BrokerExit),
}

/// Resolves or creates the requested PTY before any Tokio runtime exists.
/// The daemon-fork child remains the broker; only the parent continues to the
/// SSH bootstrap and gateway process.
pub fn prepare_bootstrap_parent(
    request: BootstrapRequest,
    context: Context,
    environment: Vec<OsString>,
    default_shell: Option<OsString>,
    path: Option<OsString>,
) -> Result<BootstrapPreparation, RoleError> {
    if request.operation() == BootstrapOperation::Connect {
        let command = request
            .command()
            .iter()
            .cloned()
            .map(OsString::from_vec)
            .collect();
        let outcome = everpty::run::ensure_session(EnsureSessionRequest {
            context: context.clone(),
            name: request.session().to_owned(),
            command,
            default_shell,
            environment,
            path,
            origins: vec![OsString::from(request.origin())],
            rows: request.rows(),
            columns: request.columns(),
        })?;
        if let EnsureSessionOutcome::Broker(exit) = outcome {
            return Ok(BootstrapPreparation::Broker(exit));
        }
    } else {
        let live = everpty::run::list(&context)?
            .iter()
            .any(|session| session.name() == request.session());
        if !live {
            return Err(everpty::Error::NotLive.into());
        }
    }

    let root = everpty::session::resolve_state_root_existing_from(&context.state_candidates)?;
    root.open_session(request.session(), &context.limits)?;
    Ok(BootstrapPreparation::Ready {
        request,
        state_root: root.path().to_owned(),
    })
}

/// Starts a detached gateway candidate and relays exactly one canonical
/// bootstrap line back across the authenticated SSH stdout channel.
pub async fn run_bootstrap_parent<W>(
    self_exe: PathBuf,
    gateway_role_prefix: &[&str],
    state_root: PathBuf,
    bind_ip: IpAddr,
    request: BootstrapRequest,
    mut output: W,
    limits: Limits,
) -> Result<(), RoleError>
where
    W: Write,
{
    let token = request.encode_token()?;
    let mut command = Command::new(self_exe);
    command
        .args(gateway_role_prefix)
        .arg(GATEWAY_ROLE)
        .arg("--state-root")
        .arg(state_root)
        .arg("--bind-ip")
        .arg(bind_ip.to_string())
        .arg("--request")
        .arg(token)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(false);
    // Only named diagnostic options may cross the sanitized re-exec.
    // Normal builds continue inheriting no environment variables here.
    #[cfg(feature = "path-diagnostics")]
    if let Some(path) = std::env::var_os("EVERUDP_EXIT_TRACE") {
        command.env("EVERUDP_EXIT_TRACE", path);
    }
    #[cfg(feature = "path-diagnostics")]
    if let Some(path) = std::env::var_os("EVERUDP_GATEWAY_PATH_TRACE") {
        command.env("EVERUDP_GATEWAY_PATH_TRACE", path);
    }
    #[cfg(feature = "path-io-diagnostics")]
    if let Some(value) = std::env::var_os("EVERUDP_PATH_IO_TRACE") {
        command.env("EVERUDP_PATH_IO_TRACE", value);
    }
    unsafe {
        command.pre_exec(|| everpty::sys::child_setsid().map_err(io::Error::from_raw_os_error));
    }
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().ok_or(RoleError::Child)?;
    let mut wire = Vec::with_capacity(limits.bootstrap_record_max.min(512));
    let read = tokio::time::timeout(limits.initial_udp_budget(), async {
        stdout
            .take((limits.bootstrap_record_max + 1) as u64)
            .read_to_end(&mut wire)
            .await
    })
    .await;
    let operation = match read {
        Ok(Ok(_)) if wire.len() <= limits.bootstrap_record_max => {
            let line = std::str::from_utf8(&wire)
                .map_err(|_| BootstrapError::Malformed)
                .and_then(|line| BootstrapRecord::parse_line(line, &limits))?;
            if line.association_id() != request.association_id() {
                Err(RoleError::AssociationMismatch)
            } else {
                output.write_all(&wire)?;
                output.flush()?;
                Ok(())
            }
        }
        Ok(Ok(_)) => Err(BootstrapError::Malformed.into()),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(GatewayError::Timeout.into()),
    };
    if operation.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    operation
}

/// Runs either the singleton gateway owner or the race-losing candidate that
/// requests an invitation from the already-live owner and exits.
pub async fn run_gateway_role<W>(
    pty_state_root: &Path,
    bind_ip: IpAddr,
    request: BootstrapRequest,
    mut output: W,
    limits: Limits,
) -> Result<(), RoleError>
where
    W: Write,
{
    let gateway_root_path = pty_state_root.join("everudp");
    #[cfg(feature = "path-diagnostics")]
    crate::exit_trace::install_panic_location_hook();
    let gateway_root =
        everpty::session::resolve_state_root_from(std::slice::from_ref(&gateway_root_path))?;
    let request_wire = GatewayControlRequest::with_takeover(
        request.association_id(),
        request.role(),
        request.client_spki_sha256(),
        request.take_over(),
    );
    match acquire_gateway_state(
        &gateway_root,
        request.session(),
        limits.initial_udp_budget_ms,
    )? {
        GatewayState::Connected(mut control) => {
            let record = control.request_invitation(request_wire, &limits)?;
            verify_record_binding(&record, &request)?;
            write_bootstrap(&mut output, &record)?;
            Ok(())
        }
        GatewayState::Owner(listener) => {
            let generation = GatewayGeneration::generate()?;
            let invitations: SharedInvitationStore = Arc::new(Mutex::new(InvitationStore::new(
                request.session(),
                generation,
                &limits,
            )?));
            let identity = GatewayIdentity::generate()?;
            let server_spki_sha256 = identity.spki_sha256();
            let endpoint = GatewayEndpoint::bind(
                SocketAddr::new(bind_ip, 0),
                &identity,
                Arc::clone(&invitations),
                limits,
            )?;
            let context = GatewayBootstrapContext::new(
                endpoint.local_addr(),
                server_spki_sha256,
                generation,
                std::process::id(),
            )?;
            let record = issue_record(&invitations, context, request_wire)?;
            verify_record_binding(&record, &request)?;
            write_bootstrap(&mut output, &record)?;
            drop(output);

            let control_store = Arc::clone(&invitations);
            std::thread::Builder::new()
                .name("everudp-control".to_owned())
                .spawn(move || {
                    while let Ok(())
                    | Err(
                        GatewayError::Timeout
                        | GatewayError::ControlMalformed
                        | GatewayError::PeerIo(_),
                    ) = listener.serve_invitation(&control_store, context, &limits)
                    {
                    }
                })?;

            let pty_root = everpty::session::resolve_state_root_existing_from(
                std::slice::from_ref(&pty_state_root.to_owned()),
            )?;
            let session = pty_root.open_session(request.session(), &everpty::Limits::default())?;
            run_gateway(
                endpoint,
                &session,
                request.session(),
                request.rows(),
                request.columns(),
                limits,
            )
            .await
            .inspect_err(|error| {
                crate::exit_trace::record(match error {
                    GatewayRunError::Transport(_) => "gateway-role-transport-error",
                    GatewayRunError::Link(_) => "gateway-role-link-error",
                    GatewayRunError::Pty(_) => "gateway-role-pty-error",
                    GatewayRunError::Queue(_) => "gateway-role-queue-error",
                });
            })?;
            Ok(())
        }
    }
}

fn issue_record(
    invitations: &SharedInvitationStore,
    context: GatewayBootstrapContext,
    request: GatewayControlRequest,
) -> Result<BootstrapRecord, RoleError> {
    let now_ms = everpty::sys::clock_monotonic_ms()?;
    let ticket = invitations
        .lock()
        .map_err(|_| GatewayError::InvitationStoreUnavailable)?
        .issue_with_takeover(
            request.association_id(),
            request.role(),
            request.client_spki_sha256(),
            request.take_over(),
            now_ms,
        )?;
    Ok(BootstrapRecord::new(
        context.endpoint(),
        context.server_spki_sha256(),
        ticket.token().clone(),
        ticket.association_id(),
        context.generation(),
        std::process::id(),
    )?)
}

fn verify_record_binding(
    record: &BootstrapRecord,
    request: &BootstrapRequest,
) -> Result<(), RoleError> {
    if record.association_id() != request.association_id() {
        return Err(RoleError::AssociationMismatch);
    }
    Ok(())
}

fn write_bootstrap(output: &mut impl Write, record: &BootstrapRecord) -> Result<(), RoleError> {
    let line = record.encode();
    output.write_all(line.as_str().as_bytes())?;
    output.flush()?;
    Ok(())
}
