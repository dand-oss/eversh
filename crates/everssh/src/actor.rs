//! Persistent client/server owners for a resumable everssh association.

use crate::association::{AssociationAuthorization, ClientHello};
use crate::bootstrap::BootstrapRecord;
use crate::error::{DeadlinePhase, Error, LimitViolation};
use crate::identity::EphemeralClientIdentity;
use crate::limits::Limits;
use crate::resume::{
    AssociationBoundary, AssociationCompletion, AssociationCore, AssociationRunError,
    ResumeAssociationConfig,
};
use crate::transport::{ClientEndpoint, ServerEndpoint, UdpBindPolicy};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::Instant;

const CLOSE_CODE: noq::VarInt = noq::VarInt::from_u32(0x4556);
const RECONNECT_BACKOFF: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub enum ActorError {
    Terminal(Error),
    Run(AssociationRunError),
}

impl From<Error> for ActorError {
    fn from(source: Error) -> Self {
        Self::Terminal(source)
    }
}

impl From<AssociationRunError> for ActorError {
    fn from(source: AssociationRunError) -> Self {
        Self::Run(source)
    }
}

struct RemoteConnection {
    connection: noq::Connection,
    send: noq::SendStream,
    recv: noq::RecvStream,
}

async fn close_remote(remote: RemoteConnection) {
    remote
        .connection
        .close(CLOSE_CODE, b"association connection ended");
    drop(remote.send);
    drop(remote.recv);
    let _ = tokio::time::timeout(Duration::from_secs(5), remote.connection.closed()).await;
}

/// Reports whether the peer deliberately ended this association with our
/// terminal application close code. Must run before `close_remote`, whose local
/// close would replace the connection's close evidence.
async fn peer_sent_terminal_close(remote: &RemoteConnection) -> bool {
    match tokio::time::timeout(Duration::from_secs(1), remote.connection.closed()).await {
        Ok(noq::ConnectionError::ApplicationClosed(close)) => close.error_code == CLOSE_CODE,
        _ => false,
    }
}

fn reconnect_is_retryable(error: &Error) -> bool {
    matches!(
        error,
        Error::DeadlineExpired(DeadlinePhase::ClientConnect) | Error::QuicConnect
    )
}

pub struct ServerAssociation {
    endpoint: ServerEndpoint,
    core: AssociationCore,
    authorization: AssociationAuthorization,
    target_read: OwnedReadHalf,
    target_write: OwnedWriteHalf,
    remote: RemoteConnection,
}

impl ServerAssociation {
    pub async fn accept(
        endpoint: ServerEndpoint,
        config: ResumeAssociationConfig,
    ) -> Result<Self, Error> {
        let initial = endpoint.accept_v2_initial().await?;
        let authorization = initial.connection().authorization();
        let (connection, target) = initial.into_parts();
        let (connection, send, recv, _) = connection.into_remote_parts();
        let (target_read, target_write) = target.into_split();
        Ok(Self {
            endpoint,
            core: AssociationCore::new(config)?,
            authorization,
            target_read,
            target_write,
            remote: RemoteConnection {
                connection,
                send,
                recv,
            },
        })
    }

    pub fn authorization(&self) -> AssociationAuthorization {
        self.authorization
    }

    pub async fn run(mut self) -> Result<AssociationCompletion, ActorError> {
        loop {
            let mut remote = self.remote;
            let result = self
                .core
                .run_connection(
                    &mut self.target_read,
                    &mut self.target_write,
                    &mut remote.recv,
                    &mut remote.send,
                )
                .await;
            let peer_terminal = matches!(&result, Err(error) if error.boundary == AssociationBoundary::Remote)
                && peer_sent_terminal_close(&remote).await;
            close_remote(remote).await;

            match result {
                Ok(completion) => {
                    let _ = self.endpoint.close().await;
                    return Ok(completion);
                }
                Err(error) if error.boundary == AssociationBoundary::Remote => {
                    if self.core.is_clean() {
                        let _ = self.endpoint.close().await;
                        return Ok(AssociationCompletion::Clean);
                    }
                    if peer_terminal
                        || matches!(
                            &error.source,
                            Error::Io(source) if source.kind() == std::io::ErrorKind::UnexpectedEof
                        )
                    {
                        let _ = self.endpoint.close().await;
                        return Err(ActorError::Run(error));
                    }
                    let (connection, peer_ack) = self
                        .endpoint
                        .accept_v2_resume(
                            self.authorization,
                            self.core.delivered_ack(),
                            self.core.outbound_last_assigned(),
                        )
                        .await
                        .map_err(ActorError::Terminal)?;
                    self.core
                        .apply_peer_ack(peer_ack)
                        .map_err(ActorError::Terminal)?;
                    let (connection, send, recv, _) = connection.into_remote_parts();
                    self.remote = RemoteConnection {
                        connection,
                        send,
                        recv,
                    };
                }
                Err(error) => {
                    let _ = self.endpoint.close().await;
                    return Err(ActorError::Run(error));
                }
            }
        }
    }
}

pub struct ClientAssociation<R, W> {
    server: SocketAddr,
    spki_sha256: [u8; 32],
    association_id: crate::association::AssociationId,
    initial_hello: Option<ClientHello>,
    identity: EphemeralClientIdentity,
    core: AssociationCore,
    limits: Limits,
    local_read: R,
    local_write: W,
}

impl<R, W> ClientAssociation<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(
        record: &BootstrapRecord,
        target_port: u16,
        identity: EphemeralClientIdentity,
        config: ResumeAssociationConfig,
        limits: Limits,
        local_read: R,
        local_write: W,
    ) -> Result<Self, Error> {
        let initial_hello = ClientHello::initial(
            record.association_id(),
            0,
            record.token().clone(),
            target_port,
        )?;
        Ok(Self {
            server: SocketAddr::new(record.udp_endpoint, record.udp_port),
            spki_sha256: record.spki_sha256,
            association_id: record.association_id(),
            initial_hello: Some(initial_hello),
            identity,
            core: AssociationCore::new(config)?,
            limits,
            local_read,
            local_write,
        })
    }

    pub async fn run(mut self) -> Result<AssociationCompletion, ActorError> {
        let mut initial = true;
        let mut reconnect_deadline: Option<Instant> = None;
        loop {
            let endpoint = ClientEndpoint::bind(
                self.server,
                UdpBindPolicy::RouteSelected,
                self.spki_sha256,
                &self.identity,
                self.limits,
            )
            .map_err(ActorError::Terminal)?;
            let hello = if initial {
                self.initial_hello.take().ok_or(Error::TokenReuse)?
            } else {
                ClientHello::resume(self.association_id, self.core.delivered_ack())?
            };
            if !initial {
                if reconnect_deadline.is_none() {
                    reconnect_deadline = Some(
                        Instant::now()
                            .checked_add(self.reconnect_budget())
                            .ok_or(Error::InvalidLimits(LimitViolation::DeadlineOverflow))?,
                    );
                }
                let deadline = reconnect_deadline
                    .expect("reconnect deadline was just initialized when absent");
                let attempt_ends = Instant::now()
                    .checked_add(self.limits.handshake_timeout())
                    .ok_or(Error::InvalidLimits(LimitViolation::DeadlineOverflow))?;
                if attempt_ends > deadline {
                    return Err(ActorError::Terminal(Error::DeadlineExpired(
                        DeadlinePhase::Reconnect,
                    )));
                }
            }
            let (session, server_hello) = match endpoint.connect_v2_association(hello).await {
                Ok(session) => session,
                // A live association survives transient path loss: reconnect
                // attempts stay inside the bounded association budget below.
                // Authentication and protocol rejections stay terminal.
                Err(error) if !initial && reconnect_is_retryable(&error) => {
                    tokio::time::sleep(RECONNECT_BACKOFF).await;
                    continue;
                }
                Err(error) => return Err(ActorError::Terminal(error)),
            };
            initial = false;
            self.core
                .apply_peer_ack(server_hello.delivered_ack())
                .map_err(ActorError::Terminal)?;

            // Keep the route supervisor alive for this connection: it owns
            // production source-address rebinds while the association runs.
            let parts = session.into_parts();
            let endpoint = parts.endpoint;
            let supervisor = parts.supervisor;
            let mut remote = RemoteConnection {
                connection: parts.connection,
                send: parts.send,
                recv: parts.recv,
            };
            let result = self
                .core
                .run_connection(
                    &mut self.local_read,
                    &mut self.local_write,
                    &mut remote.recv,
                    &mut remote.send,
                )
                .await;
            let peer_terminal = matches!(&result, Err(error) if error.boundary == AssociationBoundary::Remote)
                && peer_sent_terminal_close(&remote).await;
            close_remote(remote).await;
            drop(supervisor);
            drop(endpoint);

            match result {
                Ok(completion) => return Ok(completion),
                Err(error) if error.boundary == AssociationBoundary::Remote => {
                    if self.core.is_clean() {
                        return Ok(AssociationCompletion::Clean);
                    }
                    if peer_terminal
                        || matches!(
                            &error.source,
                            Error::Io(source) if source.kind() == std::io::ErrorKind::UnexpectedEof
                        )
                    {
                        return Err(ActorError::Run(error));
                    }
                    continue;
                }
                Err(error) => return Err(ActorError::Run(error)),
            }
        }
    }

    /// The client stops one full handshake before the server's renewed
    /// association lease, so it can never outlive the accepting endpoint.
    fn reconnect_budget(&self) -> Duration {
        self.limits
            .server_lease()
            .saturating_sub(self.limits.handshake_timeout())
    }
}
