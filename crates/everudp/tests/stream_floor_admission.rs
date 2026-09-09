#![cfg(feature = "stream-floor")]

use everssh::association::AssociationId;
use everudp::transport::{
    stream_floor_authorize_initial, stream_floor_client_config, stream_floor_server_config,
};
use everudp::wire::ConnectionRole;
use everudp::{
    ClientHello, ClientIdentity, GatewayGeneration, GatewayIdentity, InvitationStore, Limits,
    ResumePosition, TransportError,
};

async fn connected_pair(
    server_identity: &GatewayIdentity,
    client_identity: &ClientIdentity,
) -> (
    noq::Endpoint,
    noq::Endpoint,
    noq::Connection,
    noq::Connection,
) {
    let limits = Limits::default();
    let server = noq::Endpoint::server(
        stream_floor_server_config(server_identity, &limits).expect("server config"),
        "127.0.0.1:0".parse().expect("server address"),
    )
    .expect("server endpoint");
    let client = noq::Endpoint::client("127.0.0.1:0".parse().expect("client address"))
        .expect("client endpoint");
    let (config, mismatch) =
        stream_floor_client_config(client_identity, server_identity.spki_sha256(), &limits)
            .expect("client config");
    client.set_default_client_config(config);
    let connecting = client
        .connect(server.local_addr().expect("server address"), "localhost")
        .expect("connect");
    let accepting = async {
        loop {
            let incoming = server.accept().await.expect("incoming");
            if !incoming.remote_address_validated() {
                incoming.retry().expect("retry");
                continue;
            }
            break incoming.await.expect("server TLS");
        }
    };
    let (client_connection, server_connection) = tokio::join!(connecting, accepting);
    let client_connection = client_connection.expect("client TLS");
    assert!(!mismatch.observed());
    assert_eq!(client_connection.max_datagram_size(), None);
    assert_eq!(server_connection.max_datagram_size(), None);
    (server, client, client_connection, server_connection)
}

fn hello(
    association_id: AssociationId,
    generation: GatewayGeneration,
    role: ConnectionRole,
    token: everssh::bootstrap::SecretToken,
) -> ClientHello {
    ClientHello::initial(
        association_id,
        generation,
        role,
        ResumePosition {
            input_epoch: 0,
            next_input: 0,
            output_epoch: 0,
            next_output: 0,
            delivered_output_ack: 0,
        },
        token,
    )
    .expect("initial hello")
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_stream_admission_uses_tls_spki_and_one_use_bindings() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let limits = Limits::default();
        let association = AssociationId::from_bytes([1; 16]).expect("association");
        let generation = GatewayGeneration::from_bytes([2; 16]).expect("generation");

        for mismatch in [
            "valid",
            "reuse",
            "spki",
            "association",
            "generation",
            "role",
            "expiry",
        ] {
            let server_identity = GatewayIdentity::generate().expect("server identity");
            let client_identity = ClientIdentity::generate().expect("client identity");
            let (server, client, _client_connection, connection) =
                connected_pair(&server_identity, &client_identity).await;
            let bound_spki = if mismatch == "spki" {
                [0; 32]
            } else {
                client_identity.spki_sha256()
            };
            let mut store =
                InvitationStore::new("stream-floor", generation, &limits).expect("store");
            let ticket = store
                .issue(association, ConnectionRole::Writer, bound_spki, 0)
                .expect("ticket");
            let hello = hello(
                if mismatch == "association" {
                    AssociationId::from_bytes([3; 16]).expect("other association")
                } else {
                    association
                },
                if mismatch == "generation" {
                    GatewayGeneration::from_bytes([3; 16]).expect("other generation")
                } else {
                    generation
                },
                if mismatch == "role" {
                    ConnectionRole::Observer
                } else {
                    ConnectionRole::Writer
                },
                ticket.token().clone(),
            );
            let now = if mismatch == "expiry" {
                limits.invitation_lifetime_ms
            } else {
                1
            };
            let result = stream_floor_authorize_initial(&connection, &hello, &mut store, now);
            match mismatch {
                "valid" => assert!(matches!(result, Ok(false))),
                "reuse" => {
                    assert!(matches!(result, Ok(false)));
                    assert!(matches!(
                        stream_floor_authorize_initial(&connection, &hello, &mut store, now),
                        Err(TransportError::Admission(
                            everudp::AdmissionError::TokenReuse
                        ))
                    ));
                }
                "expiry" => assert!(matches!(
                    result,
                    Err(TransportError::Admission(
                        everudp::AdmissionError::InvitationExpired
                    ))
                )),
                _ => assert!(matches!(
                    result,
                    Err(TransportError::Admission(
                        everudp::AdmissionError::BindingMismatch
                    ))
                )),
            }
            connection.close(noq::VarInt::from_u32(0), b"admission test");
            server.wait_idle().await;
            client.wait_idle().await;
        }
    })
    .await
    .expect("bounded stream admission test");
}
