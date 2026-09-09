use everpty::sys;
use everudp::wire::ConnectionRole;
use everudp::{LocalEvent, TerminalEdge, GAP_NOTICE};
use std::io::Read;
use std::os::fd::AsFd;

#[test]
fn staging_changes_nothing_and_drop_restores_termios_and_signal_mask() {
    let (master, slave) = sys::openpty(24, 80).expect("pty");
    let before_termios = sys::terminal_attributes(slave.as_fd()).expect("termios");
    let before_mask = sys::current_signal_mask().expect("mask");
    {
        let mut edge = TerminalEdge::stage(slave.as_fd(), slave.as_fd(), slave.as_fd())
            .expect("stage terminal");
        assert!(sys::terminal_attributes(slave.as_fd()).expect("staged termios") == before_termios);
        assert_eq!(
            sys::current_signal_mask().expect("staged mask"),
            before_mask
        );
        edge.activate(ConnectionRole::Writer).expect("activate");
        assert!(sys::terminal_attributes(slave.as_fd()).expect("raw termios") != before_termios);
        assert_ne!(
            sys::current_signal_mask().expect("active mask"),
            before_mask
        );
        assert!(edge.is_active());
    }
    assert!(sys::terminal_attributes(slave.as_fd()).expect("restored termios") == before_termios);
    assert_eq!(
        sys::current_signal_mask().expect("restored mask"),
        before_mask
    );
    drop(master);
}

#[test]
fn observer_never_places_stdin_in_raw_mode() {
    let (_master, slave) = sys::openpty(24, 80).expect("pty");
    let before = sys::terminal_attributes(slave.as_fd()).expect("termios");
    let mut edge = TerminalEdge::stage(slave.as_fd(), slave.as_fd(), slave.as_fd()).expect("stage");
    edge.activate(ConnectionRole::Observer).expect("observer");
    assert!(sys::terminal_attributes(slave.as_fd()).expect("observer termios") == before);
}

#[test]
fn gap_notice_is_one_plain_line_with_no_escape_or_repaint_instruction() {
    let (read, write) = sys::pipe_cloexec().expect("pipe");
    let input = std::fs::File::open("/dev/null").expect("stdin");
    let output = std::fs::File::create("/dev/null").expect("stdout");
    let mut edge = TerminalEdge::stage(input.as_fd(), output.as_fd(), write.as_fd()).expect("edge");
    edge.activate(ConnectionRole::Observer).expect("activate");
    edge.write_gap_notice().expect("notice");
    drop(edge);
    drop(write);
    let mut read = std::fs::File::from(read);
    let mut bytes = Vec::new();
    read.read_to_end(&mut bytes).expect("read");
    assert_eq!(bytes, GAP_NOTICE);
    assert!(!bytes.contains(&0x1b));
    assert!(!String::from_utf8(bytes).expect("UTF-8").contains("ctrl"));
}

#[tokio::test(flavor = "current_thread")]
async fn async_terminal_edge_reads_stdin_without_polling_when_queue_is_full() {
    let (read, write) = sys::pipe_cloexec().expect("stdin pipe");
    let (_output_read, output) = sys::pipe_cloexec().expect("stdout pipe");
    let (_error_read, error) = sys::pipe_cloexec().expect("stderr pipe");
    let mut edge = TerminalEdge::stage(read.as_fd(), output.as_fd(), error.as_fd()).expect("stage");
    edge.activate(ConnectionRole::Writer).expect("activate");
    edge.enable_async_io().expect("async descriptors");
    assert_eq!(
        sys::write_fd(write.as_fd(), b"abc").expect("write stdin"),
        3
    );
    let mut input = [0_u8; 16];
    assert_eq!(
        edge.next_local_event(&mut input, true)
            .await
            .expect("local event"),
        LocalEvent::Stdin { bytes: 3 }
    );
    assert_eq!(&input[..3], b"abc");

    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(20),
        edge.next_local_event(&mut input, false)
    )
    .await
    .is_err());
}
