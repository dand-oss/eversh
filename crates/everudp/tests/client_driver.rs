use everpty::sys;
use everssh::association::AssociationId;
use everudp::wire::{ConnectionRole, EpochGap, Kind};
use everudp::{
    parse_status_line, ClientAssociation, ClientDriver, ClientEndpoint, ClientHello,
    ClientIdentity, ClientInboundReceipt, ClientLink, ClientOutputStageReceipt, ClientRunOutcome,
    GatewayAction, GatewayEndpoint, GatewayGeneration, GatewayIdentity, GatewayLifecycle,
    GatewayLink, GatewayReplaySlabs, InputOperation, InvitationStore, Limits, LinkState,
    ResumePosition, StatusFile, StatusRecord, StatusTerminalCause, TerminalEdge,
};
use std::fs;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn association() -> AssociationId {
    AssociationId::from_bytes([9; 16]).expect("association")
}

fn generation() -> GatewayGeneration {
    GatewayGeneration::from_bytes([10; 16]).expect("generation")
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_driver_moves_real_stdio_and_acks_exit_before_restoring() {
    let limits = Limits::default();
    let store = Arc::new(Mutex::new(
        InvitationStore::new("work", generation(), &limits).expect("store"),
    ));
    let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
    let gateway = GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
        .expect("gateway");
    let client_identity = ClientIdentity::generate().expect("client identity");
    let ticket = store
        .lock()
        .expect("store lock")
        .issue(
            association(),
            ConnectionRole::Writer,
            client_identity.spki_sha256(),
            sys::clock_monotonic_ms().expect("clock"),
        )
        .expect("ticket");
    let hello = ClientHello::initial(
        association(),
        generation(),
        ConnectionRole::Writer,
        ResumePosition {
            input_epoch: 0,
            next_input: 0,
            output_epoch: 0,
            next_output: 0,
            delivered_output_ack: 0,
        },
        ticket.token().clone(),
    )
    .expect("hello");
    let endpoint = ClientEndpoint::bind(
        loopback(),
        &client_identity,
        gateway_identity.spki_sha256(),
        limits,
    )
    .expect("client endpoint");
    let (admitted, session) = tokio::join!(
        gateway.accept_initial(),
        endpoint.connect_initial(gateway.local_addr(), &hello)
    );
    let admitted = admitted.expect("admitted");
    let session = session.expect("session");
    let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
    let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");

    let (stdin_read, stdin_write) = sys::pipe_cloexec().expect("stdin pipe");
    let (stdout_read, stdout_write) = sys::pipe_cloexec().expect("stdout pipe");
    let (stderr_read, stderr_write) = sys::pipe_cloexec().expect("stderr pipe");
    let status_root = std::env::temp_dir().join(format!(
        "everudp-client-driver-{}-{}",
        std::process::id(),
        sys::clock_monotonic_ms().expect("clock")
    ));
    fs::create_dir(&status_root).expect("status root");
    fs::set_permissions(&status_root, fs::Permissions::from_mode(0o700)).expect("status root mode");
    let status_path = status_root.join("status");
    let mut status = StatusFile::create_private(&status_path).expect("status file");
    status
        .transition(
            LinkState::Connecting,
            sys::clock_monotonic_ms().expect("clock"),
        )
        .expect("connecting status");
    assert_eq!(
        sys::write_fd(stdin_write.as_fd(), b"from-terminal").expect("seed stdin"),
        13
    );

    let server = async {
        let (mut link, _) =
            GatewayLink::accept_initial(admitted, &mut lifecycle, &mut slabs, limits)
                .await
                .expect("gateway link");
        let mut input = Vec::new();
        link.receive_input(&mut slabs, |operation| {
            let InputOperation::Bytes(bytes) = operation else {
                panic!("expected input bytes")
            };
            input.extend_from_slice(bytes);
            Ok(())
        })
        .await
        .expect("receive input");
        link.flush_control(&mut slabs).await.expect("input ACK");
        assert_eq!(input, b"from-terminal");

        slabs
            .push_output(Kind::Output, b"to-terminal")
            .expect("output");
        slabs
            .push_output(Kind::Exit, &23_i32.to_be_bytes())
            .expect("exit");
        link.flush_output(&slabs).await.expect("flush output");
        link.receive_control(&mut slabs).await.expect("output ACK");
        link.receive_control(&mut slabs).await.expect("exit ACK");
        assert_eq!(slabs.writer_output().unacknowledged_operations(), 0);
        link.close();
    };

    let peer = async {
        let association =
            ClientAssociation::new(association(), generation(), ConnectionRole::Writer, limits)
                .expect("association");
        let mut link = ClientLink::finish_initial(session, association, limits)
            .await
            .expect("client link");
        let terminal = TerminalEdge::stage(
            stdin_read.as_fd(),
            stdout_write.as_fd(),
            stderr_write.as_fd(),
        )
        .expect("terminal");
        let mut driver =
            ClientDriver::activate(terminal, &link, limits, Some(status)).expect("driver");
        let outcome = driver.run_link(&mut link).await.expect("run terminal");
        assert_eq!(outcome, ClientRunOutcome::PtyExited(23));
        driver.terminal_status(StatusTerminalCause::PtyExit, 0);
        drop(driver);
        drop(link);
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(server, peer);
    })
    .await
    .expect("driver deadline");
    drop(stdin_write);
    drop(stdout_write);
    drop(stderr_write);

    let mut stdout = std::fs::File::from(stdout_read);
    let mut output = Vec::new();
    stdout.read_to_end(&mut output).expect("read stdout");
    assert_eq!(output, b"to-terminal");
    let mut stderr = std::fs::File::from(stderr_read);
    let mut errors = Vec::new();
    stderr.read_to_end(&mut errors).expect("read stderr");
    assert!(errors.is_empty());

    let records: Vec<_> = fs::read_to_string(&status_path)
        .expect("read status")
        .lines()
        .map(parse_status_line)
        .collect();
    assert_eq!(
        records,
        [
            Some(StatusRecord::Transition(LinkState::Connecting)),
            Some(StatusRecord::Transition(LinkState::Connected)),
            Some(StatusRecord::Transition(LinkState::Carrying)),
            Some(StatusRecord::Terminal {
                cause: StatusTerminalCause::PtyExit,
                carried: true,
                ambiguous_input: 0,
            }),
        ]
    );
    fs::remove_dir_all(status_root).expect("status cleanup");
}

#[tokio::test(flavor = "current_thread")]
async fn gap_during_blocked_stdout_abandons_stale_output_and_delivers_the_new_epoch() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let limits = Limits::default();
        let store = Arc::new(Mutex::new(
            InvitationStore::new("work", generation(), &limits).expect("store"),
        ));
        let gateway_identity = GatewayIdentity::generate().expect("gateway identity");
        let gateway =
            GatewayEndpoint::bind(loopback(), &gateway_identity, Arc::clone(&store), limits)
                .expect("gateway");
        let client_identity = ClientIdentity::generate().expect("client identity");
        let ticket = store
            .lock()
            .expect("store lock")
            .issue(
                association(),
                ConnectionRole::Writer,
                client_identity.spki_sha256(),
                sys::clock_monotonic_ms().expect("clock"),
            )
            .expect("ticket");
        let hello = ClientHello::initial(
            association(),
            generation(),
            ConnectionRole::Writer,
            ResumePosition {
                input_epoch: 0,
                next_input: 0,
                output_epoch: 0,
                next_output: 0,
                delivered_output_ack: 0,
            },
            ticket.token().clone(),
        )
        .expect("hello");
        let endpoint = ClientEndpoint::bind(
            loopback(),
            &client_identity,
            gateway_identity.spki_sha256(),
            limits,
        )
        .expect("client endpoint");
        let (admitted, session) = tokio::join!(
            gateway.accept_initial(),
            endpoint.connect_initial(gateway.local_addr(), &hello)
        );
        let mut lifecycle = GatewayLifecycle::new(&limits).expect("lifecycle");
        let mut slabs = GatewayReplaySlabs::new(&limits).expect("slabs");
        let client_association =
            ClientAssociation::new(association(), generation(), ConnectionRole::Writer, limits)
                .expect("association");
        let (server_link, client_link) = tokio::join!(
            GatewayLink::accept_initial(
                admitted.expect("admitted"),
                &mut lifecycle,
                &mut slabs,
                limits,
            ),
            ClientLink::finish_initial(session.expect("session"), client_association, limits)
        );
        let mut server_link = server_link.expect("server link").0;
        let mut client_link = client_link.expect("client link");

        slabs
            .push_output(Kind::Output, b"stale-output-must-not-escape")
            .expect("stale output");
        server_link
            .flush_output(&slabs)
            .await
            .expect("flush stale output");
        assert!(matches!(
            client_link.next_inbound().await.expect("open output"),
            ClientInboundReceipt::OutputStreamOpened
        ));
        assert!(matches!(
            client_link
                .next_inbound()
                .await
                .expect("stage stale output"),
            ClientInboundReceipt::Output(ClientOutputStageReceipt::Staged { .. })
        ));
        assert!(client_link.association().has_pending_output());

        let (stdin_read, stdin_write) = sys::pipe_cloexec().expect("stdin pipe");
        let (stdout_read, stdout_write) = sys::pipe_cloexec().expect("stdout pipe");
        let (stderr_read, stderr_write) = sys::pipe_cloexec().expect("stderr pipe");
        sys::set_nonblocking(stdout_write.as_fd()).expect("nonblocking stdout");
        let filler = [b'F'; 4096];
        let mut filler_bytes = 0usize;
        loop {
            match sys::write_fd(stdout_write.as_fd(), &filler) {
                Ok(0) => panic!("stdout pipe accepted a zero-byte fill"),
                Ok(written) => filler_bytes += written,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fill stdout pipe: {error}"),
            }
        }
        assert!(filler_bytes > 0);
        let terminal = TerminalEdge::stage(
            stdin_read.as_fd(),
            stdout_write.as_fd(),
            stderr_write.as_fd(),
        )
        .expect("terminal");
        let mut driver =
            ClientDriver::activate(terminal, &client_link, limits, None).expect("activate driver");
        let notice_reader = tokio::task::spawn_blocking(move || {
            let mut stderr = std::fs::File::from(stderr_read);
            let mut notice = vec![0_u8; everudp::terminal::GAP_NOTICE.len()];
            stderr.read_exact(&mut notice).expect("read gap notice");
            (stderr, notice)
        });

        // Inject the valid next control sequence while stdout is known-full.
        // This reproduces the independent-stream interleaving defensively
        // handled by the driver, then the peer closes for a normal resume.
        let gap = EpochGap::new(0, 1).expect("gap");
        slabs
            .writer_control_mut()
            .push(Kind::Gap, &gap.encode())
            .expect("queue gap");
        let server = async {
            server_link
                .flush_control(&mut slabs)
                .await
                .expect("flush gap");
            let (stderr, notice) = tokio::time::timeout(Duration::from_secs(2), notice_reader)
                .await
                .expect("gap notice deadline")
                .expect("gap notice reader");
            (server_link.into_resumable_association(), stderr, notice)
        };
        let peer = driver.run_link(&mut client_link);
        let ((server_association, mut stderr, notice), peer_outcome) = tokio::join!(server, peer);
        assert_eq!(
            peer_outcome.expect("gap must not be terminal"),
            ClientRunOutcome::NetworkLost
        );
        assert!(!client_link.association().has_pending_output());
        assert_eq!(notice, everudp::terminal::GAP_NOTICE);

        let client_association = client_link.into_resumable_association();
        assert_eq!(
            slabs.replace_writer_generation().expect("replace epoch"),
            (0, 1)
        );
        let resume_hello = client_association.resume_hello().expect("resume hello");
        let authorization = server_association.authorization();
        let (admitted, session) = tokio::join!(
            gateway.accept_resume(authorization),
            endpoint.connect_resume(gateway.local_addr(), &resume_hello)
        );
        let (server_link, client_link) = tokio::join!(
            GatewayLink::accept_resume(
                admitted.expect("resume admission"),
                server_association,
                &mut lifecycle,
                &mut slabs,
                limits,
            ),
            ClientLink::finish_resume(session.expect("resume session"), client_association, limits,)
        );
        let (mut server_link, action) = server_link.expect("resumed server link");
        assert_eq!(action, GatewayAction::WriterResumed);
        let mut client_link = client_link.expect("resumed client link");

        let mut stdout = std::fs::File::from(stdout_read);
        let mut drained_filler = vec![0_u8; filler_bytes];
        stdout
            .read_exact(&mut drained_filler)
            .expect("drain full pipe");
        assert!(drained_filler.iter().all(|byte| *byte == b'F'));

        let server = async {
            slabs
                .push_output(Kind::Output, b"future-output")
                .expect("future output");
            slabs
                .push_output(Kind::Exit, &0_i32.to_be_bytes())
                .expect("exit");
            server_link
                .flush_output(&slabs)
                .await
                .expect("flush future output");
            server_link
                .receive_control(&mut slabs)
                .await
                .expect("future output ACK");
            server_link
                .receive_control(&mut slabs)
                .await
                .expect("exit ACK");
            assert_eq!(slabs.writer_output().unacknowledged_operations(), 0);
            server_link.close();
        };
        let peer = driver.run_link(&mut client_link);
        let ((), outcome) = tokio::join!(server, peer);
        assert_eq!(
            outcome.expect("new epoch driver"),
            ClientRunOutcome::PtyExited(0)
        );
        drop(driver);
        drop(client_link);
        drop(stdin_write);
        drop(stdout_write);
        drop(stderr_write);

        let mut future = Vec::new();
        stdout.read_to_end(&mut future).expect("read future output");
        assert_eq!(future, b"future-output");
        let mut extra_notices = Vec::new();
        stderr
            .read_to_end(&mut extra_notices)
            .expect("read duplicate gap notices");
        assert!(
            extra_notices.is_empty(),
            "gap notice was emitted more than once"
        );
    })
    .await
    .expect("blocked stdout GAP regression deadline");
}
