//! Persistent gateway loop joining authenticated QUIC associations to one
//! terminal-free `everpty` attachment.

use crate::actor::{GatewayLink, InboundApply, LinkError, LinkInbound};
use crate::association::GatewayAssociation;
use crate::gateway::GatewayLifecycle;
use crate::handshake::ClientHello;
use crate::pty::{PtyError, PtyEvent, PtySession};
use crate::queues::{GatewayReplaySlabs, QueueError};
use crate::transport::{GatewayEndpoint, TransportError};
use crate::wire::{ConnectionRole, Kind};
use crate::Limits;
use everpty::session::SessionDir;
use everssh::association::AssociationId;
use std::fmt;
use std::future::{poll_fn, Future};
use std::task::Poll;
use tokio::sync::{mpsc, watch};

const ASSOCIATION_CAPACITY: usize = 9;

#[cfg(test)]
#[path = "gateway_fairness_tests.rs"]
mod fairness_tests;

#[derive(Debug)]
pub enum GatewayRunError {
    Transport(TransportError),
    Link(LinkError),
    Pty(PtyError),
    Queue(QueueError),
}

impl fmt::Display for GatewayRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "{error}"),
            Self::Link(error) => write!(formatter, "{error}"),
            Self::Pty(error) => write!(formatter, "{error}"),
            Self::Queue(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for GatewayRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Link(error) => Some(error),
            Self::Pty(error) => Some(error),
            Self::Queue(error) => Some(error),
        }
    }
}

impl From<TransportError> for GatewayRunError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<LinkError> for GatewayRunError {
    fn from(value: LinkError) -> Self {
        Self::Link(value)
    }
}

impl From<PtyError> for GatewayRunError {
    fn from(value: PtyError) -> Self {
        Self::Pty(value)
    }
}

impl From<QueueError> for GatewayRunError {
    fn from(value: QueueError) -> Self {
        Self::Queue(value)
    }
}

enum AssociationState {
    Connected(Box<GatewayLink>),
    Disconnected(GatewayAssociation),
}

struct ManagedAssociation {
    state: AssociationState,
    pending: Option<Result<LinkInbound, LinkError>>,
}

impl ManagedAssociation {
    fn new(state: AssociationState) -> Self {
        Self {
            state,
            pending: None,
        }
    }
}

impl AssociationState {
    fn association(&self) -> &GatewayAssociation {
        match self {
            Self::Connected(link) => link.association(),
            Self::Disconnected(association) => association,
        }
    }

    fn association_id(&self) -> AssociationId {
        self.association().association_id()
    }

    fn role(&self) -> ConnectionRole {
        self.association().role()
    }

    fn authorization(&self) -> crate::AssociationAuthorization {
        self.association().authorization()
    }

    fn is_connected(&self) -> bool {
        matches!(self, Self::Connected(_))
    }
}

struct Associations {
    slots: Box<[Option<ManagedAssociation>]>,
    next_slot: usize,
    outbound_turn: [bool; ASSOCIATION_CAPACITY],
}

enum LinkReady {
    Event(usize),
    OutboundProgress,
}

enum Ready<I, A, P> {
    Inbound(I),
    Admission(A),
    Pty(P),
}

async fn select_ready<I: Future, A: Future, P: Future>(
    next: &mut usize,
    inbound: I,
    admission: A,
    pty: P,
) -> Ready<I::Output, A::Output, P::Output> {
    // Rotate only after selecting work. A canceled all-pending poll retains
    // the preference and still registers readiness for every source.
    let ready = match *next {
        0 => tokio::select! {
            biased;
            value = inbound => Ready::Inbound(value),
            value = admission => Ready::Admission(value),
            value = pty => Ready::Pty(value),
        },
        1 => tokio::select! {
            biased;
            value = admission => Ready::Admission(value),
            value = pty => Ready::Pty(value),
            value = inbound => Ready::Inbound(value),
        },
        _ => tokio::select! {
            biased;
            value = pty => Ready::Pty(value),
            value = inbound => Ready::Inbound(value),
            value = admission => Ready::Admission(value),
        },
    };
    *next = match &ready {
        Ready::Inbound(_) => 1,
        Ready::Admission(_) => 2,
        Ready::Pty(_) => 0,
    };
    ready
}

type AuthorizationSet = [Option<crate::AssociationAuthorization>; ASSOCIATION_CAPACITY];

enum TerminalReady<I, A> {
    Inbound(I),
    Admission(A),
}

async fn select_terminal_ready<I: Future, A: Future>(
    next: &mut usize,
    inbound: I,
    admission: A,
) -> TerminalReady<I::Output, A::Output> {
    match select_ready(
        next,
        inbound,
        admission,
        std::future::pending::<std::convert::Infallible>(),
    )
    .await
    {
        Ready::Inbound(value) => TerminalReady::Inbound(value),
        Ready::Admission(value) => TerminalReady::Admission(value),
        Ready::Pty(impossible) => match impossible {},
    }
}

/// Owns the one persistent endpoint-accept future. QUIC accept/auth futures
/// are not treated as cancellation-safe, so terminal or PTY activity must
/// never drop one after it has consumed an incoming connection or token.
struct AdmissionDriver {
    authorizations: watch::Sender<AuthorizationSet>,
    incoming: mpsc::Receiver<Result<crate::AdmittedConnection, TransportError>>,
    task: tokio::task::JoinHandle<()>,
}

impl AdmissionDriver {
    fn spawn(endpoint: GatewayEndpoint, initial: AuthorizationSet) -> Self {
        let (authorizations, mut updates) = watch::channel(initial);
        let (sender, incoming) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            loop {
                let current = *updates.borrow_and_update();
                crate::exit_trace::record("gateway-admission-wait");
                let admitted = endpoint.accept_any(&current).await;
                crate::exit_trace::record(if admitted.is_ok() {
                    "gateway-admission-ready"
                } else {
                    "gateway-admission-error"
                });
                if sender.send(admitted).await.is_err() {
                    return;
                }
                crate::exit_trace::record("gateway-admission-enqueued");
            }
        });
        Self {
            authorizations,
            incoming,
            task,
        }
    }

    fn update(&self, authorizations: AuthorizationSet) {
        self.authorizations.send_replace(authorizations);
    }

    async fn next(&mut self) -> Result<crate::AdmittedConnection, TransportError> {
        self.incoming
            .recv()
            .await
            .unwrap_or(Err(TransportError::EndpointClosed))
    }

    fn stop(&mut self) {
        self.task.abort();
    }
}

impl Drop for AdmissionDriver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Associations {
    fn new() -> Result<Self, QueueError> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(ASSOCIATION_CAPACITY)
            .map_err(|_| QueueError::Allocation)?;
        slots.resize_with(ASSOCIATION_CAPACITY, || None);
        Ok(Self {
            slots: slots.into_boxed_slice(),
            next_slot: 0,
            outbound_turn: [false; ASSOCIATION_CAPACITY],
        })
    }

    fn insert(&mut self, state: AssociationState) -> Result<usize, QueueError> {
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
            .ok_or(QueueError::ObserverCapacity)?;
        *slot = Some(ManagedAssociation::new(state));
        self.outbound_turn[index] = false;
        Ok(index)
    }

    fn has_capacity(&self) -> bool {
        self.slots.iter().any(Option::is_none)
    }

    fn put(&mut self, index: usize, state: AssociationState) {
        debug_assert!(self.slots[index].is_none());
        self.slots[index] = Some(ManagedAssociation::new(state));
    }

    fn take(&mut self, index: usize) -> Option<AssociationState> {
        let managed = self.slots.get_mut(index)?.take()?;
        debug_assert!(managed.pending.is_none());
        Some(managed.state)
    }

    fn find(&self, association_id: AssociationId) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|managed| managed.state.association_id() == association_id)
        })
    }

    fn writer(&self) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|managed| managed.state.role() == ConnectionRole::Writer)
        })
    }

    fn disconnected_observer(&self) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_ref().is_some_and(|managed| {
                managed.state.role() == ConnectionRole::Observer && !managed.state.is_connected()
            })
        })
    }

    fn authorizations(&self) -> AuthorizationSet {
        let mut authorizations = [None; ASSOCIATION_CAPACITY];
        for (output, managed) in authorizations.iter_mut().zip(self.slots.iter()) {
            *output = managed
                .as_ref()
                .map(|managed| managed.state.authorization());
        }
        authorizations
    }

    fn first_pending(&self) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|managed| managed.pending.is_some())
        })
    }

    fn take_pending(&mut self, index: usize) -> Option<Result<LinkInbound, LinkError>> {
        self.slots.get_mut(index)?.as_mut()?.pending.take()
    }

    fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }
}

/// Runs one persistent gateway across concurrent writer/observer associations
/// and every sequential resume. The single broker attachment outlives every
/// network connection and remains the only PTY data-plane edge.
pub async fn run_gateway(
    endpoint: GatewayEndpoint,
    session: &SessionDir,
    name: &str,
    initial_rows: u16,
    initial_columns: u16,
    limits: Limits,
) -> Result<(), GatewayRunError> {
    let mut lifecycle = GatewayLifecycle::new(&limits).map_err(|error| {
        GatewayRunError::Link(LinkError::Association(crate::AssociationError::Gateway(
            error,
        )))
    })?;
    let mut slabs = GatewayReplaySlabs::new(&limits)?;
    #[cfg(feature = "path-diagnostics")]
    if let Some(path) = std::env::var_os("EVERUDP_GATEWAY_PATH_TRACE") {
        slabs
            .enable_path_trace(std::path::Path::new(&path))
            .map_err(PtyError::from)?;
    }
    let admitted = accept_first(&endpoint).await?;
    let take_over = admitted.take_over();
    let (link, _) =
        GatewayLink::prepare_initial(admitted, &mut lifecycle, &mut slabs, limits).await?;

    // Every network role shares this one persistent broker writer. In
    // particular, an observer that creates a replacement gateway must not
    // strand that gateway on an observer-only broker socket which can never
    // later carry a writer's input. `(0,0)` preserves an existing session's
    // dimensions; a writer creating the session supplies its real size.
    let (rows, columns) = if initial_rows == 0 && initial_columns == 0 {
        (0, 0)
    } else {
        (initial_rows, initial_columns)
    };
    let pty = PtySession::connect_gateway(
        session,
        name,
        take_over,
        rows,
        columns,
        everpty::Limits::default(),
        *endpoint.generation().as_bytes(),
    )
    .await;
    let mut pty = match pty {
        Ok(pty) => pty,
        Err(PtyError::Busy { .. }) => {
            link.reject_prepared_writer_busy(&mut lifecycle, &mut slabs)?;
            endpoint.wait_idle().await;
            return Ok(());
        }
        Err(error) => {
            link.abort_prepared_initial(&mut lifecycle, &mut slabs)?;
            endpoint.wait_idle().await;
            return Err(error.into());
        }
    };
    let link = link
        .commit_prepared_initial(&mut lifecycle, &mut slabs)
        .await?;
    let mut associations = Associations::new()?;
    associations.insert(AssociationState::Connected(Box::new(link)))?;
    let mut admission = AdmissionDriver::spawn(endpoint.clone(), associations.authorizations());
    let mut pending_pty = None;
    let mut prefer_pty_once = false;
    let mut next_ready = 0;
    let mut pty_output = Vec::new();
    pty_output
        .try_reserve_exact(limits.copy_buffer_bytes)
        .map_err(|_| QueueError::Allocation)?;

    loop {
        if let Some(index) = associations.first_pending() {
            let event = associations
                .take_pending(index)
                .expect("pending association event");
            prefer_pty_once = process_link_event(
                index,
                event,
                &mut associations,
                &mut pty,
                &mut lifecycle,
                &mut slabs,
            )
            .await?;
            continue;
        }
        if prefer_pty_once {
            prefer_pty_once = false;
            if let Some(event) = poll_pty_now(&mut pty).await {
                if let Some(status) = queue_ready_pty_event(
                    event,
                    &mut pty,
                    &mut pending_pty,
                    &mut pty_output,
                    &mut associations,
                    &mut slabs,
                    limits.copy_buffer_bytes,
                )
                .await?
                {
                    return finish_terminal_delivery(
                        &endpoint,
                        associations,
                        status,
                        &mut lifecycle,
                        &mut slabs,
                        limits,
                        &mut admission,
                    )
                    .await;
                }
                continue;
            }
        }
        if let Some(event) = pending_pty.take() {
            if let Some(status) = queue_ready_pty_event(
                event,
                &mut pty,
                &mut pending_pty,
                &mut pty_output,
                &mut associations,
                &mut slabs,
                limits.copy_buffer_bytes,
            )
            .await?
            {
                return finish_terminal_delivery(
                    &endpoint,
                    associations,
                    status,
                    &mut lifecycle,
                    &mut slabs,
                    limits,
                    &mut admission,
                )
                .await;
            }
            continue;
        }
        let authorizations = associations.authorizations();
        admission.update(authorizations);
        let ready = select_ready(
            &mut next_ready,
            next_link_ready(&mut associations, &mut slabs),
            admission.next(),
            pty.next_event(),
        )
        .await;
        match ready {
            Ready::Admission(Ok(admitted)) => {
                handle_admitted(
                    admitted,
                    &mut associations,
                    &mut lifecycle,
                    &mut slabs,
                    limits,
                )
                .await?;
            }
            Ready::Admission(Err(
                error @ (TransportError::EndpointClosed
                | TransportError::InvitationStoreUnavailable),
            )) => return Err(error.into()),
            Ready::Admission(Err(_)) => {}
            Ready::Inbound(LinkReady::Event(index)) => {
                let event = associations
                    .take_pending(index)
                    .expect("ready association event");
                prefer_pty_once = process_link_event(
                    index,
                    event,
                    &mut associations,
                    &mut pty,
                    &mut lifecycle,
                    &mut slabs,
                )
                .await?;
            }
            Ready::Inbound(LinkReady::OutboundProgress) => {}
            Ready::Pty(event) => {
                if let Some(status) = queue_ready_pty_event(
                    event,
                    &mut pty,
                    &mut pending_pty,
                    &mut pty_output,
                    &mut associations,
                    &mut slabs,
                    limits.copy_buffer_bytes,
                )
                .await?
                {
                    return finish_terminal_delivery(
                        &endpoint,
                        associations,
                        status,
                        &mut lifecycle,
                        &mut slabs,
                        limits,
                        &mut admission,
                    )
                    .await;
                }
            }
        }
    }
}

async fn accept_first(
    endpoint: &GatewayEndpoint,
) -> Result<crate::AdmittedConnection, GatewayRunError> {
    loop {
        match endpoint.accept_initial().await {
            Ok(admitted) => return Ok(admitted),
            Err(
                error @ (TransportError::EndpointClosed
                | TransportError::InvitationStoreUnavailable),
            ) => return Err(error.into()),
            Err(_) => {}
        }
    }
}

async fn next_link_ready(
    associations: &mut Associations,
    slabs: &mut GatewayReplaySlabs,
) -> LinkReady {
    poll_fn(|context| {
        let start = associations.next_slot;
        for offset in 0..associations.slots.len() {
            let index = (start + offset) % associations.slots.len();
            let Some(managed) = associations.slots[index].as_mut() else {
                continue;
            };
            // Every ready return rotates priority. Pending-only scans still
            // poll every connection, preserving all readiness registrations.
            associations.next_slot = (index + 1) % ASSOCIATION_CAPACITY;
            if managed.pending.is_some() {
                return Poll::Ready(LinkReady::Event(index));
            }
            let AssociationState::Connected(link) = &mut managed.state else {
                continue;
            };
            match link.output_resume_required(slabs) {
                Ok(true) => {
                    managed.pending = Some(Err(LinkError::OutputResumeRequired));
                    return Poll::Ready(LinkReady::Event(index));
                }
                Ok(false) => {}
                Err(error) => {
                    managed.pending = Some(Err(error));
                    return Poll::Ready(LinkReady::Event(index));
                }
            }
            // After one delivered inbound event, offer one bounded outbound
            // turn. Keep this preference outside ManagedAssociation because
            // applying an event takes/reinserts its state. Neither a paste nor
            // an endless output queue may monopolize a connected association.
            let outbound_first = associations.outbound_turn[index];
            associations.outbound_turn[index] = false;
            if outbound_first {
                match link.poll_outbound(slabs, context) {
                    Poll::Ready(Ok(true)) => return Poll::Ready(LinkReady::OutboundProgress),
                    Poll::Ready(Err(error)) => {
                        managed.pending = Some(Err(error));
                        return Poll::Ready(LinkReady::Event(index));
                    }
                    Poll::Ready(Ok(false)) | Poll::Pending => {}
                }
            }
            // Always give ACKs a turn between successful outbound steps to
            // avoid manufacturing an overrun from unread cumulative ACKs.
            let event = {
                let mut future = std::pin::pin!(link.next_inbound());
                match Future::poll(future.as_mut(), context) {
                    Poll::Ready(event) => Some(event),
                    Poll::Pending => None,
                }
            };
            if let Some(event) = event {
                managed.pending = Some(event);
                associations.outbound_turn[index] = true;
                return Poll::Ready(LinkReady::Event(index));
            }
            if outbound_first {
                continue;
            }
            match link.poll_outbound(slabs, context) {
                Poll::Ready(Ok(true)) => return Poll::Ready(LinkReady::OutboundProgress),
                Poll::Ready(Err(error)) => {
                    managed.pending = Some(Err(error));
                    return Poll::Ready(LinkReady::Event(index));
                }
                Poll::Ready(Ok(false)) | Poll::Pending => {}
            }
        }
        Poll::Pending
    })
    .await
}

async fn handle_admitted(
    admitted: crate::AdmittedConnection,
    associations: &mut Associations,
    lifecycle: &mut GatewayLifecycle,
    slabs: &mut GatewayReplaySlabs,
    limits: Limits,
) -> Result<(), GatewayRunError> {
    match admitted.hello() {
        ClientHello::Initial { .. } => {
            handle_initial(admitted, associations, lifecycle, slabs, limits).await
        }
        ClientHello::Resume { .. } => {
            handle_resume(admitted, associations, lifecycle, slabs, limits).await
        }
    }
}

async fn handle_initial(
    admitted: crate::AdmittedConnection,
    associations: &mut Associations,
    lifecycle: &mut GatewayLifecycle,
    slabs: &mut GatewayReplaySlabs,
    limits: Limits,
) -> Result<(), GatewayRunError> {
    let association_id = admitted.hello().association_id();
    if associations.find(association_id).is_some() {
        admitted.close();
        return Ok(());
    }
    if admitted.hello().role() == ConnectionRole::Writer {
        if let Some(previous) = associations.writer() {
            let connected = associations.slots[previous]
                .as_ref()
                .is_some_and(|managed| managed.state.is_connected());
            if connected && !admitted.take_over() {
                admitted.reject_writer_busy();
                return Ok(());
            }
            crate::exit_trace::record("gateway-prepare-retire-writer");
            retire_writer(previous, connected, associations, lifecycle, slabs, limits).await?;
            crate::exit_trace::record("gateway-prepare-writer-retired");
        }
    } else if !associations.has_capacity() {
        // Disconnected observers remain resumable until capacity pressure.
        // At that boundary, retire one stale observer so locally cancelled
        // or permanently lost clients cannot exhaust the PTY-lifetime cap.
        if let Some(stale) = associations.disconnected_observer() {
            retire_association(stale, associations, lifecycle, slabs)?;
        }
    }
    if !associations.has_capacity() {
        admitted.reject_association_capacity();
        return Ok(());
    }
    crate::exit_trace::record("gateway-prepare-accept-initial");
    match GatewayLink::accept_initial(admitted, lifecycle, slabs, limits).await {
        Ok((link, _)) => {
            crate::exit_trace::record("gateway-prepare-initial-accepted");
            associations.insert(AssociationState::Connected(Box::new(link)))?;
            Ok(())
        }
        Err(_) => Ok(()),
    }
}

async fn handle_resume(
    admitted: crate::AdmittedConnection,
    associations: &mut Associations,
    lifecycle: &mut GatewayLifecycle,
    slabs: &mut GatewayReplaySlabs,
    limits: Limits,
) -> Result<(), GatewayRunError> {
    let association_id = admitted.hello().association_id();
    let Some(index) = associations.find(association_id) else {
        admitted.close();
        return Ok(());
    };
    let association = match associations.take(index).expect("located association") {
        AssociationState::Connected(link) => (*link).into_resumable_association(),
        AssociationState::Disconnected(association) => association,
    };
    match GatewayLink::try_accept_resume(admitted, association, lifecycle, slabs, limits).await {
        Ok((link, _)) => {
            associations.put(index, AssociationState::Connected(Box::new(link)));
            Ok(())
        }
        Err(failure) => {
            let (_error, association) = failure.into_parts();
            associations.put(index, AssociationState::Disconnected(association));
            Ok(())
        }
    }
}

async fn retire_writer(
    index: usize,
    notify: bool,
    associations: &mut Associations,
    lifecycle: &mut GatewayLifecycle,
    slabs: &mut GatewayReplaySlabs,
    limits: Limits,
) -> Result<(), GatewayRunError> {
    let state = associations.take(index).expect("located writer");
    let association_id = state.association_id();
    if let AssociationState::Connected(mut link) = state {
        if notify {
            let _ = slabs.push_writer_output(Kind::Ownership, &[2])?;
            let _ = tokio::time::timeout(
                limits.initial_udp_budget(),
                drain_revoked_writer(&mut link, slabs),
            )
            .await;
        }
        (*link).close();
    }
    let released = lifecycle.release(association_id);
    debug_assert_eq!(released, Some(ConnectionRole::Writer));
    slabs.replace_writer_generation()?;
    Ok(())
}

async fn drain_revoked_writer(
    link: &mut GatewayLink,
    slabs: &mut GatewayReplaySlabs,
) -> Result<(), GatewayRunError> {
    loop {
        link.flush_control(slabs).await?;
        link.flush_output(slabs).await?;
        let pending = link
            .association()
            .output(slabs)
            .map_err(LinkError::from)?
            .unacknowledged_operations();
        match link.next_inbound().await {
            Ok(LinkInbound::ControlFinished) if pending == 0 => return Ok(()),
            Ok(LinkInbound::ControlFinished) => return Ok(()),
            Ok(event) => {
                let rejected = match link.prepare_inbound(event, slabs)? {
                    InboundApply::Deliver(input) => Some(input.token()),
                    InboundApply::None | InboundApply::Detach | InboundApply::Receipt(_) => None,
                };
                if let Some(token) = rejected {
                    link.abort_prepared_input(token)?;
                }
            }
            Err(_) => return Ok(()),
        }
    }
}

async fn process_link_event(
    index: usize,
    event: Result<LinkInbound, LinkError>,
    associations: &mut Associations,
    pty: &mut PtySession,
    lifecycle: &mut GatewayLifecycle,
    slabs: &mut GatewayReplaySlabs,
) -> Result<bool, GatewayRunError> {
    let Some(state) = associations.take(index) else {
        return Ok(false);
    };
    let AssociationState::Connected(mut link) = state else {
        associations.put(index, state);
        return Ok(false);
    };
    let mut prefer_pty = false;
    match event {
        Ok(LinkInbound::ControlFinished) => {
            associations.put(
                index,
                AssociationState::Disconnected((*link).into_resumable_association()),
            );
        }
        Ok(event) => {
            let fast_stream_duplicate = link.is_fast_stream_duplicate(&event);
            let prepared = match link.prepare_inbound(event, slabs) {
                Ok(prepared) => prepared,
                Err(error) => {
                    crate::exit_trace::record("active-prepare-error");
                    trace_link_error(&error);
                    associations.put(index, AssociationState::Connected(link));
                    retire_association(index, associations, lifecycle, slabs)?;
                    return Ok(false);
                }
            };
            match prepared {
                InboundApply::Detach => {
                    crate::exit_trace::record("active-detach");
                    #[cfg(feature = "path-diagnostics")]
                    if link.association().role() == ConnectionRole::Writer {
                        slabs.finish_path_trace();
                    }
                    associations.put(index, AssociationState::Connected(link));
                    retire_association(index, associations, lifecycle, slabs)?;
                    return Ok(false);
                }
                InboundApply::Deliver(input) => {
                    let token = input.token();
                    let probe_pty = prefer_pty_after_commit(input.operation());
                    if let Err(error) = pty.send_operation(input.operation()).await {
                        link.abort_prepared_input(token)?;
                        associations.put(index, AssociationState::Connected(link));
                        return Err(error.into());
                    }
                    link.commit_prepared_input(token, slabs)?;
                    // Only accepted input earns one nonblocking PTY turn. Pending
                    // output falls straight through to normal ACK/link service.
                    prefer_pty = probe_pty;
                }
                InboundApply::Receipt(crate::InputReceipt::Duplicate { .. }) => {
                    prefer_pty = fast_stream_duplicate;
                }
                InboundApply::None | InboundApply::Receipt(_) => {}
            }
            associations.put(index, AssociationState::Connected(link));
        }
        Err(error) if link_error_is_temporary(&error) => {
            associations.put(
                index,
                AssociationState::Disconnected((*link).into_resumable_association()),
            );
        }
        Err(error) => {
            crate::exit_trace::record("active-permanent-error");
            trace_link_error(&error);
            associations.put(index, AssociationState::Connected(link));
            retire_association(index, associations, lifecycle, slabs)?;
        }
    }
    Ok(prefer_pty)
}

fn trace_link_error(error: &LinkError) {
    crate::exit_trace::record(match error {
        LinkError::Association(crate::association::AssociationError::Queue(error)) => match error {
            QueueError::AckAhead => "error-queue-ack-ahead",
            QueueError::AckBehind => "error-queue-ack-behind",
            QueueError::SequenceGap => "error-queue-sequence-gap",
            QueueError::EpochMismatch => "error-queue-epoch",
            QueueError::DeliveryPending => "error-queue-delivery-pending",
            QueueError::DeliveryNotPending => "error-queue-delivery-not-pending",
            _ => "error-queue-other",
        },
        LinkError::Association(_) => "error-association",
        LinkError::Protocol(_) => "error-protocol",
        LinkError::StreamEndedMidRecord => "error-mid-record",
        LinkError::InputCloseMissing => "error-input-close-missing",
        LinkError::InputAfterClose => "error-input-after-close",
        LinkError::ControlBackpressure => "error-control-backpressure",
        _ => "error-other",
    });
}

async fn finish_terminal_delivery(
    endpoint: &GatewayEndpoint,
    mut associations: Associations,
    status: i32,
    lifecycle: &mut GatewayLifecycle,
    slabs: &mut GatewayReplaySlabs,
    limits: Limits,
    admission: &mut AdmissionDriver,
) -> Result<(), GatewayRunError> {
    release_disconnected(&mut associations, lifecycle, slabs)?;
    let mut next_ready = 0;
    loop {
        if let Some(index) = associations.first_pending() {
            let event = associations
                .take_pending(index)
                .expect("pending terminal association event");
            process_terminal_event(index, event, &mut associations, lifecycle, slabs)?;
            continue;
        }
        if associations.is_empty() {
            crate::exit_trace::record("gateway-terminal-empty");
            lifecycle.pty_exited(status);
            admission.stop();
            endpoint.wait_idle().await;
            return Ok(());
        }
        let authorizations = associations.authorizations();
        admission.update(authorizations);
        let ready = select_terminal_ready(
            &mut next_ready,
            next_link_ready(&mut associations, slabs),
            admission.next(),
        )
        .await;
        match ready {
            TerminalReady::Admission(admitted) => match admitted {
                Ok(admitted) => {
                    if matches!(admitted.hello(), ClientHello::Resume { .. }) {
                        handle_resume(admitted, &mut associations, lifecycle, slabs, limits)
                            .await?;
                    } else {
                        admitted.close();
                    }
                }
                Err(
                    error @ (TransportError::EndpointClosed
                    | TransportError::InvitationStoreUnavailable),
                ) => return Err(error.into()),
                Err(_) => {}
            },
            TerminalReady::Inbound(LinkReady::Event(index)) => {
                let event = associations
                    .take_pending(index)
                    .expect("ready terminal association event");
                process_terminal_event(index, event, &mut associations, lifecycle, slabs)?;
            }
            TerminalReady::Inbound(LinkReady::OutboundProgress) => {}
        }
    }
}

fn process_terminal_event(
    index: usize,
    event: Result<LinkInbound, LinkError>,
    associations: &mut Associations,
    lifecycle: &mut GatewayLifecycle,
    slabs: &mut GatewayReplaySlabs,
) -> Result<(), GatewayRunError> {
    let Some(state) = associations.take(index) else {
        return Ok(());
    };
    let AssociationState::Connected(mut link) = state else {
        associations.put(index, state);
        return Ok(());
    };
    match event {
        Ok(LinkInbound::ControlFinished) => {
            let pending = link
                .association()
                .output(slabs)
                .map_err(LinkError::from)?
                .unacknowledged_operations();
            if pending == 0 {
                crate::exit_trace::record("terminal-fin-acked");
                let association_id = link.association().association_id();
                let role = link.association().role();
                (*link).close();
                let _ = lifecycle.release(association_id);
                if role == ConnectionRole::Observer {
                    slabs.remove_observer(association_id)?;
                }
            } else {
                crate::exit_trace::record("terminal-fin-unacked");
                associations.put(
                    index,
                    AssociationState::Disconnected((*link).into_resumable_association()),
                );
            }
        }
        Ok(event) => {
            let rejected = match link.prepare_inbound(event, slabs) {
                Ok(InboundApply::Deliver(input)) => Some(input.token()),
                Ok(InboundApply::Detach) => {
                    crate::exit_trace::record("terminal-detach");
                    associations.put(index, AssociationState::Connected(link));
                    retire_association(index, associations, lifecycle, slabs)?;
                    return Ok(());
                }
                Ok(InboundApply::None | InboundApply::Receipt(_)) => None,
                Err(_) => {
                    crate::exit_trace::record("terminal-prepare-error");
                    associations.put(index, AssociationState::Connected(link));
                    retire_association(index, associations, lifecycle, slabs)?;
                    return Ok(());
                }
            };
            if let Some(token) = rejected {
                link.abort_prepared_input(token)?;
            }
            associations.put(index, AssociationState::Connected(link));
        }
        Err(error) if link_error_is_temporary(&error) => {
            crate::exit_trace::record("terminal-temporary-error");
            associations.put(
                index,
                AssociationState::Disconnected((*link).into_resumable_association()),
            );
        }
        Err(_) => {
            crate::exit_trace::record("terminal-permanent-error");
            associations.put(index, AssociationState::Connected(link));
            retire_association(index, associations, lifecycle, slabs)?;
        }
    }
    Ok(())
}

fn retire_association(
    index: usize,
    associations: &mut Associations,
    lifecycle: &mut GatewayLifecycle,
    slabs: &mut GatewayReplaySlabs,
) -> Result<(), QueueError> {
    let Some(state) = associations.take(index) else {
        return Ok(());
    };
    let association_id = state.association_id();
    let role = state.role();
    if let AssociationState::Connected(link) = state {
        (*link).close();
    }
    let _ = lifecycle.release(association_id);
    match role {
        ConnectionRole::Writer => {
            slabs.replace_writer_generation()?;
        }
        ConnectionRole::Observer => slabs.remove_observer(association_id)?,
    }
    Ok(())
}

fn release_disconnected(
    associations: &mut Associations,
    lifecycle: &mut GatewayLifecycle,
    slabs: &mut GatewayReplaySlabs,
) -> Result<(), QueueError> {
    for index in 0..associations.slots.len() {
        if associations.slots[index]
            .as_ref()
            .is_some_and(|managed| matches!(managed.state, AssociationState::Disconnected(_)))
        {
            crate::exit_trace::record("terminal-discard-disconnected");
            retire_association(index, associations, lifecycle, slabs)?;
        }
    }
    Ok(())
}

async fn queue_pty_event(
    event: PtyEvent,
    pty: &mut PtySession,
    associations: &mut Associations,
    slabs: &mut GatewayReplaySlabs,
) -> Result<Option<i32>, GatewayRunError> {
    match event {
        PtyEvent::Output(bytes) => {
            debug_assert_eq!(pty.output_bytes().len(), bytes);
            if bytes != 0 {
                slabs.push_output(Kind::Output, pty.output_bytes())?;
                send_fast_output_to_connected(associations, slabs, pty.output_bytes()).await;
            }
            pty.consume_event()?;
            Ok(None)
        }
        PtyEvent::Ownership(event) => {
            slabs.push_output(Kind::Ownership, &[event])?;
            pty.consume_event()?;
            Ok(None)
        }
        PtyEvent::Exit(status) => {
            crate::exit_trace::record("gateway-queue-exit");
            slabs.push_output(Kind::Exit, &status.to_be_bytes())?;
            pty.consume_event()?;
            Ok(Some(status))
        }
        PtyEvent::DirectLeaseEnded => Err(PtyError::Protocol.into()),
    }
}

/// Coalesces only output frames that are already readable in the same poll
/// turn. This bounds replay-operation amplification without adding a timer or
/// delaying the first byte of an interactive response.
async fn queue_ready_pty_event(
    event: Result<PtyEvent, PtyError>,
    pty: &mut PtySession,
    pending: &mut Option<Result<PtyEvent, PtyError>>,
    output: &mut Vec<u8>,
    associations: &mut Associations,
    slabs: &mut GatewayReplaySlabs,
    coalesce_cap: usize,
) -> Result<Option<i32>, GatewayRunError> {
    let event = event?;
    if event == PtyEvent::DirectLeaseEnded {
        // `PtySession::next_event` participates in cancellable selects (and
        // in the zero-wait coalescing poll below). Keep the stateful release
        // handshake here, after the readiness result has been committed.
        pty.finish_direct_release().await?;
        return Ok(None);
    }
    let PtyEvent::Output(bytes) = event else {
        return queue_pty_event(event, pty, associations, slabs).await;
    };
    if bytes >= coalesce_cap {
        return queue_pty_event(PtyEvent::Output(bytes), pty, associations, slabs).await;
    }

    output.clear();
    debug_assert_eq!(pty.output_bytes().len(), bytes);
    output.extend_from_slice(pty.output_bytes());
    pty.consume_event()?;
    while output.len() < coalesce_cap {
        let Some(next) = poll_pty_now(pty).await else {
            break;
        };
        match next {
            Ok(PtyEvent::Output(bytes)) if bytes <= coalesce_cap - output.len() => {
                debug_assert_eq!(pty.output_bytes().len(), bytes);
                output.extend_from_slice(pty.output_bytes());
                pty.consume_event()?;
            }
            other => {
                *pending = Some(other);
                break;
            }
        }
    }
    if !output.is_empty() {
        slabs.push_output(Kind::Output, output)?;
        send_fast_output_to_connected(associations, slabs, output).await;
    }
    Ok(None)
}

#[cfg(feature = "datagram-spike")]
async fn send_fast_output_to_connected(
    associations: &mut Associations,
    slabs: &GatewayReplaySlabs,
    payload: &[u8],
) {
    for managed in associations.slots.iter_mut().flatten() {
        if let AssociationState::Connected(link) = &mut managed.state {
            link.send_fresh_output_fast(slabs, payload).await;
        }
    }
}

#[cfg(not(feature = "datagram-spike"))]
async fn send_fast_output_to_connected(
    _associations: &mut Associations,
    _slabs: &GatewayReplaySlabs,
    _payload: &[u8],
) {
}

/// Polls one cancellation-safe broker read exactly once and reports `None`
/// instead of waiting. `FrameReader` retains any partial frame consumed by the
/// poll, so the next normal read resumes at the same byte boundary.
async fn poll_pty_now(pty: &mut PtySession) -> Option<Result<PtyEvent, PtyError>> {
    poll_once_now(pty.next_event()).await
}

async fn poll_once_now<T>(future: impl Future<Output = T>) -> Option<T> {
    let mut future = std::pin::pin!(future);
    poll_fn(|context| {
        let event = match Future::poll(future.as_mut(), context) {
            Poll::Ready(event) => Some(event),
            Poll::Pending => None,
        };
        Poll::Ready(event)
    })
    .await
}

fn prefer_pty_after_commit(operation: crate::InputOperation<'_>) -> bool {
    cfg!(feature = "pty-ready-spike") && matches!(operation, crate::InputOperation::Bytes(_))
}

fn link_error_is_temporary(error: &LinkError) -> bool {
    matches!(
        error,
        LinkError::StreamOpen
            | LinkError::StreamRead
            | LinkError::StreamWrite
            | LinkError::OutputResumeRequired
    )
}
