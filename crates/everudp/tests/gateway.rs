use everssh::association::AssociationId;
use everudp::wire::ConnectionRole;
use everudp::{
    acquire_gateway_state, GatewayBootstrapContext, GatewayControlRequest, GatewayError,
    GatewayGeneration, GatewayState, InvitationStore, Limits, SharedInvitationStore,
};
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempState {
    base: PathBuf,
    root: PathBuf,
}

impl TempState {
    fn new() -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "everudp-gateway-test-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&base).expect("base");
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).expect("base mode");
        let root = base.join("gateway");
        Self { base, root }
    }

    fn resolve(&self) -> everpty::session::StateRoot {
        everpty::session::resolve_state_root_from(std::slice::from_ref(&self.root))
            .expect("state root")
    }
}

impl Drop for TempState {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.root);
        let _ = fs::remove_dir(&self.base);
    }
}

fn association(byte: u8) -> AssociationId {
    AssociationId::from_bytes([byte; 16]).expect("association")
}

fn generation() -> GatewayGeneration {
    GatewayGeneration::from_bytes([7; 16]).expect("generation")
}

#[test]
fn gateway_state_is_singleton_race_safe_and_exactly_private() {
    let temp = Arc::new(TempState::new());
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let temp = Arc::clone(&temp);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let root = temp.resolve();
            barrier.wait();
            acquire_gateway_state(&root, "work", 1_000).expect("acquire")
        }));
    }
    let mut states: Vec<GatewayState> = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect();
    assert_eq!(
        states
            .iter()
            .filter(|state| matches!(state, GatewayState::Owner(_)))
            .count(),
        1
    );
    assert_eq!(
        states
            .iter()
            .filter(|state| matches!(state, GatewayState::Connected(_)))
            .count(),
        1
    );

    let owner_index = states
        .iter()
        .position(|state| matches!(state, GatewayState::Owner(_)))
        .expect("owner");
    let connected_index = 1 - owner_index;
    let connected = match states.swap_remove(connected_index) {
        GatewayState::Connected(client) => client,
        GatewayState::Owner(_) => panic!("connected state"),
    };
    let mut owner = match states.pop().expect("owner state") {
        GatewayState::Owner(owner) => owner,
        GatewayState::Connected(_) => panic!("owner state"),
    };
    let accepted = owner.accept_peer(1_000).expect("same-UID peer");
    drop(accepted);
    drop(connected);

    assert_eq!(
        fs::metadata(owner.state_path())
            .expect("state metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(
        fs::symlink_metadata(owner.socket_path())
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    owner.retire().expect("retire");
}

#[test]
fn same_uid_control_socket_issues_a_bound_canonical_invitation() {
    let temp = TempState::new();
    let root = temp.resolve();
    let mut owner = match acquire_gateway_state(&root, "work", 1_000).expect("owner") {
        GatewayState::Owner(owner) => owner,
        GatewayState::Connected(_) => panic!("fresh root has no gateway"),
    };
    let mut client = match acquire_gateway_state(&root, "work", 1_000).expect("client") {
        GatewayState::Connected(client) => client,
        GatewayState::Owner(_) => panic!("gateway must be singleton"),
    };
    let limits = Limits::default();
    let store: SharedInvitationStore = Arc::new(Mutex::new(
        InvitationStore::new("work", generation(), &limits).expect("store"),
    ));
    let context = GatewayBootstrapContext::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 4444)),
        [8; 32],
        generation(),
        1234,
    )
    .expect("context");
    let request =
        GatewayControlRequest::with_takeover(association(1), ConnectionRole::Writer, [9; 32], true);

    std::thread::scope(|scope| {
        let requester = scope.spawn(|| client.request_invitation(request, &limits));
        owner
            .serve_invitation(&store, context, &limits)
            .expect("serve invitation");
        let record = requester.join().expect("request thread").expect("record");
        assert_eq!(record.endpoint(), context.endpoint());
        assert_eq!(record.server_spki_sha256(), [8; 32]);
        assert_eq!(record.association_id(), association(1));
        assert_eq!(record.generation(), generation());
        assert!(store
            .lock()
            .expect("store lock")
            .claim(
                record.token().as_bytes(),
                association(1),
                "work",
                generation(),
                ConnectionRole::Writer,
                [9; 32],
                everpty::sys::clock_monotonic_ms().expect("clock"),
            )
            .expect("fully bound claim"));
    });
    owner.retire().expect("retire");
}

#[test]
fn failed_control_peers_do_not_disable_later_invitations() {
    let temp = TempState::new();
    let root = temp.resolve();
    let mut owner = match acquire_gateway_state(&root, "work", 1_000).expect("owner") {
        GatewayState::Owner(owner) => owner,
        GatewayState::Connected(_) => panic!("fresh root has no gateway"),
    };
    let limits = Limits::default();
    let store: SharedInvitationStore = Arc::new(Mutex::new(
        InvitationStore::new("work", generation(), &limits).expect("store"),
    ));
    let context = GatewayBootstrapContext::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 4444)),
        [8; 32],
        generation(),
        1234,
    )
    .expect("context");

    let eof = UnixStream::connect(owner.socket_path()).expect("EOF peer");
    drop(eof);
    assert!(matches!(
        owner.serve_invitation(&store, context, &limits),
        Err(GatewayError::PeerIo(_))
    ));

    let mut partial = UnixStream::connect(owner.socket_path()).expect("partial peer");
    partial.write_all(b"E").expect("partial request");
    assert!(matches!(
        owner.serve_invitation(&store, context, &limits),
        Err(GatewayError::Timeout)
    ));
    drop(partial);

    let mut client = match acquire_gateway_state(&root, "work", 1_000).expect("client") {
        GatewayState::Connected(client) => client,
        GatewayState::Owner(_) => panic!("gateway must remain singleton"),
    };
    let request = GatewayControlRequest::new(association(2), ConnectionRole::Observer, [10; 32]);
    std::thread::scope(|scope| {
        let requester = scope.spawn(|| client.request_invitation(request, &limits));
        owner
            .serve_invitation(&store, context, &limits)
            .expect("listener survives failed peers");
        requester.join().expect("request thread").expect("record");
    });
    owner.retire().expect("retire");
}
