//! Persistent client/server owners for a resumable everssh association.

use crate::association::{AssociationAuthorization, ClientHello};
use crate::bootstrap::BootstrapRecord;
use crate::error::Error;
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

const CLOSE_CODE: noq::VarInt = noq::VarInt::from_u32(0x4556);

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
            let (session, server_hello) = endpoint
                .connect_v2_association(hello)
                .await
                .map_err(ActorError::Terminal)?;
            initial = false;
            self.core
                .apply_peer_ack(server_hello.delivered_ack())
                .map_err(ActorError::Terminal)?;

            let (endpoint, connection, send, recv) = session.into_remote_parts();
            let mut remote = RemoteConnection {
                connection,
                send,
                recv,
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
}
