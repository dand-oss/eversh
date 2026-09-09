//! Direct QUIC terminal delivery above a persistent `everpty` session.
//!
//! `everudp` carries opaque terminal operations and output after an
//! authenticated SSH bootstrap. It owns no terminal model and changes
//! neither the `everpty` nor `everssh` data path.

#[cfg(feature = "input-ack-hold-spike")]
mod ack_hold;
pub mod actor;
pub mod admission;
pub mod association;
pub mod bootstrap;
pub mod client;
pub mod client_driver;
pub mod client_link;
pub mod client_runner;
#[cfg(feature = "cli")]
pub mod edge;
pub mod error;
mod exit_trace;
#[cfg(feature = "floor-single-owner")]
#[doc(hidden)]
pub mod floor_admission;
#[cfg(feature = "floor-single-owner")]
#[doc(hidden)]
pub mod floor_client_admission;
#[cfg(any(feature = "floor-single-owner", feature = "stream-floor"))]
#[doc(hidden)]
pub mod floor_control;
#[cfg(any(feature = "floor-single-owner", feature = "stream-floor"))]
#[doc(hidden)]
pub mod floor_control_writer;
#[cfg(any(feature = "floor-single-owner", feature = "stream-floor"))]
#[doc(hidden)]
pub mod floor_pump;
#[cfg(any(feature = "floor-single-owner", feature = "stream-floor"))]
#[doc(hidden)]
pub mod floor_reactor;
#[cfg(any(feature = "floor-single-owner", feature = "stream-floor"))]
#[doc(hidden)]
pub mod floor_socket;
pub mod gateway;
pub mod gateway_runner;
pub mod handshake;
pub mod identity;
#[cfg(feature = "path-io-diagnostics")]
pub(crate) mod io_trace;
pub mod limits;
#[cfg(feature = "path-packet-diagnostics")]
pub(crate) mod packet_offsets;
#[cfg(feature = "path-packet-diagnostics")]
pub(crate) mod packet_trace;
#[cfg(feature = "path-diagnostics")]
pub mod path_trace;
pub mod pty;
pub mod queues;
pub mod reconnect;
#[cfg(feature = "reliable-datagram-spike")]
pub mod reliable_datagram;
pub mod request;
pub mod roles;
pub mod route;
pub mod status;
pub mod terminal;
pub mod transport;
pub mod wire;

pub use actor::{
    ControlReceipt, GatewayLink, GatewayResumeFailure, InboundApply, InputReceipt, LinkError,
    LinkInbound, OutputFlush, PreparedInput, PreparedInputToken,
};
pub use admission::{AdmissionError, GatewayGeneration, InvitationStore, InvitationTicket};
pub use association::{
    AssociationAuthorization, AssociationError, ControlDisposition, GatewayAssociation,
    InputDisposition, InputOperation,
};
pub use bootstrap::{BootstrapError, BootstrapLine, BootstrapRecord};
pub use client::{
    ClientAssociation, ClientError, OutputDisposition as ClientOutputDisposition, OutputOperation,
    OutputStage, PendingOutputView,
};
pub use client_driver::{ClientDriver, ClientDriverError, ClientRunOutcome};
pub use client_link::{
    ClientControlReceipt, ClientInboundReceipt, ClientInputFlush, ClientLink, ClientLinkError,
    ClientOutputReceipt, ClientOutputStageReceipt, ResumeLinkFailure,
};
pub use client_runner::{
    run_client, ClientConfig, ClientExit, ClientRunError, UDP_UNREACHABLE_EXIT,
};
pub use error::{Error, LimitViolation, WireError};
pub use everssh::transport::{RouteIdentity, UdpBindPolicy};
pub use gateway::{
    acquire_gateway_state, GatewayAction, GatewayBootstrapContext, GatewayControlClient,
    GatewayControlListener, GatewayControlRequest, GatewayError, GatewayLifecycle, GatewayState,
};
pub use gateway_runner::{run_gateway, GatewayRunError};
pub use handshake::{ClientHello, HandshakeError, ResumePosition, ServerHello};
pub use identity::{ClientIdentity, GatewayIdentity, IdentityError};
pub use limits::Limits;
pub use pty::{PtyError, PtyEvent, PtySession};
pub use queues::{
    DeliveryDecision, DeliveryGate, FanoutReport, FrameCopy, GatewayReplaySlabs, OutputPush,
    OutputReplay, QueueError, ReplayRing,
};
pub use reconnect::{
    reconnect_until, GatewayReplacement, ReconnectBackoff, ReconnectError, ReconnectEvent,
    ReconnectState, ReconnectSuccess, RecoveryAction, RecoveryFailure, RecoveryRequest,
};
pub use request::{BootstrapOperation, BootstrapRequest, RequestError};
pub use roles::{
    prepare_bootstrap_parent, run_bootstrap_parent, run_gateway_role, BootstrapPreparation,
    RoleError, BOOTSTRAP_PARENT_ROLE, COMBINED_EVERUDP_ROLE, GATEWAY_ROLE,
};
pub use route::{RouteError, RouteSnapshot, RouteSupervisor, RouteTrigger};
pub use status::{
    parse_line as parse_status_line, LinkState, StatusError, StatusFile, StatusRecord,
    TerminalCause as StatusTerminalCause,
};
pub use terminal::{
    LocalEvent, TerminalEdge, TerminalError, TerminalEvent, TerminalWriteEvent, GAP_NOTICE,
};
#[cfg(feature = "tuning")]
pub use transport::DevelopmentTransportTuning;
#[cfg(feature = "stream-floor")]
pub use transport::STREAM_FLOOR_ALPN;
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub mod stream_floor_app;
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub mod stream_floor_fd;
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub mod stream_floor_handshake;
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub mod stream_floor_io;
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub mod stream_floor_native;
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub mod stream_floor_native_client;
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub mod stream_floor_native_echo;
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub mod stream_floor_native_run;
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub mod stream_floor_ordinary;
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub mod stream_floor_ordinary_client;
#[cfg(feature = "stream-floor")]
#[doc(hidden)]
pub mod stream_floor_protocol;
pub use transport::{
    effective_transport_config_receipt, AdmittedConnection, ClientEndpoint, ClientSession,
    GatewayEndpoint, InitialConnectError, LockedTransportProfile, QuicAckPolicy, RebindOutcome,
    SharedInvitationStore, TransportConfigReceipt, TransportConfigSide, TransportError,
};
