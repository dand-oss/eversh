//! Real-Linux, real-broker arbitrary-byte transparency regressions.
#![cfg(all(target_os = "linux", feature = "cli"))]
#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use everpty::run::{self, Context};
use everpty::session::SessionMeta;
use everpty::{sys, Limits};
use nix::sys::signal::Signal;

const NAME: &str = "bytes";
static FIXTURE: AtomicU64 = AtomicU64::new(0);

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_everpty")
}

fn wait_child(child: &mut Child, deadline: Instant, label: &str) -> ExitStatus {
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{label} exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn id(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }

    fn wait(mut self, deadline: Instant, label: &str) -> ExitStatus {
        let status = wait_child(self.0.as_mut().unwrap(), deadline, label);
        self.0.take();
        status
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct SessionGuard {
    base: PathBuf,
    state: PathBuf,
    metadata: Option<SessionMeta>,
    finished: bool,
}

impl SessionGuard {
    fn new(tag: &str) -> Self {
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        let base = loop {
            let n = FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("everpty-bytes-{tag}-{}-{n}", std::process::id()));
            match builder.create(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("fixture directory: {error}"),
            }
        };
        Self {
            state: base.join("state"),
            base,
            metadata: None,
            finished: false,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(binary());
        command
            .env_clear()
            .env("EVERSH_STATE_DIR", &self.state)
            .env("PATH", "/usr/bin:/bin")
            .env("SHELL", "/bin/sh")
            .env("TERM", "xterm-256color")
            .env("LC_ALL", "C");
        command
    }

    fn context(&self) -> Context {
        Context {
            state_candidates: vec![self.state.clone()],
            limits: Limits::default(),
        }
    }

    fn discover_metadata(&self, deadline: Instant) -> SessionMeta {
        loop {
            if let Ok(sessions) = run::list(&self.context()) {
                if let Some(metadata) = sessions
                    .into_iter()
                    .find(|metadata| metadata.name() == NAME && metadata.child().is_some())
                {
                    return metadata;
                }
            }
            assert!(Instant::now() < deadline, "live metadata never appeared");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn start_detached(tag: &str) -> Self {
        let mut guard = Self::new(tag);
        let (master, slave) = sys::openpty(24, 80).unwrap();
        let mut command = guard.command();
        command
            .process_group(0)
            .stdin(Stdio::from(File::from(slave.try_clone().unwrap())))
            .stdout(Stdio::from(File::from(slave.try_clone().unwrap())))
            .stderr(Stdio::from(File::from(slave)))
            .args([
                "start",
                NAME,
                "--",
                "/bin/sh",
                "-c",
                "stty raw -echo; printf READY; exec cat",
            ]);
        let starter = command.spawn().unwrap();
        let starter = ChildGuard::new(starter);
        let mut outer = File::from(master);
        sys::set_nonblocking(outer.as_fd()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let ready = read_until_bounded(&mut outer, b"READY", deadline);
        assert_eq!(ready, b"READY", "no synthetic starter output");
        guard.metadata = Some(guard.discover_metadata(deadline));

        sys::kill(starter.id() as libc::pid_t, Signal::SIGTERM).unwrap();
        let status = starter.wait(deadline, "initial attached starter");
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "terminating the starter must detach without killing the session"
        );
        guard
    }

    fn live_identity(pid: libc::pid_t, ticks: u64) -> bool {
        sys::proc_start_ticks(pid).is_ok_and(|actual| actual == ticks)
    }

    fn run_kill_command(&self) {
        let Ok(child) = self
            .command()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .args(["kill", NAME])
            .spawn()
        else {
            return;
        };
        let mut child = ChildGuard::new(child);
        let _ = wait_child(
            child.0.as_mut().unwrap(),
            Instant::now() + Duration::from_secs(8),
            "cleanup kill command",
        );
        child.0.take();
    }

    fn processes_gone(&self) -> bool {
        let Some(metadata) = &self.metadata else {
            return true;
        };
        let broker_gone =
            !Self::live_identity(metadata.broker_pid(), metadata.broker_start_ticks());
        let child_gone = metadata
            .child()
            .is_none_or(|child| !Self::live_identity(child.pid(), child.start_ticks()));
        broker_gone && child_gone
    }

    fn direct_cleanup(&self, signal: Signal) {
        let Some(metadata) = &self.metadata else {
            return;
        };
        if let Some(child) = metadata.child() {
            if Self::live_identity(child.pid(), child.start_ticks())
                && sys::getpgid_of(child.pid()).ok() == Some(child.pgid())
            {
                let _ = sys::killpg(child.pgid(), signal);
            }
        }
        if Self::live_identity(metadata.broker_pid(), metadata.broker_start_ticks()) {
            let _ = sys::kill(metadata.broker_pid(), signal);
        }
    }

    fn cleanup(&mut self) -> bool {
        if self.metadata.is_none() {
            self.metadata = run::list(&self.context())
                .ok()
                .and_then(|sessions| sessions.into_iter().find(|meta| meta.name() == NAME));
        }
        self.run_kill_command();
        let first = Instant::now() + Duration::from_secs(2);
        while !self.processes_gone() && Instant::now() < first {
            std::thread::sleep(Duration::from_millis(5));
        }
        if !self.processes_gone() {
            self.direct_cleanup(Signal::SIGTERM);
            std::thread::sleep(Duration::from_millis(50));
            self.direct_cleanup(Signal::SIGKILL);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while !self.processes_gone() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let gone = self.processes_gone();
        let _ = std::fs::remove_dir_all(&self.base);
        gone && !self.base.exists()
    }

    fn finish(mut self) {
        assert!(self.cleanup(), "session processes and state were cleaned");
        self.finished = true;
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.cleanup();
        }
    }
}

fn write_bounded(writer: &mut impl Write, bytes: &[u8], deadline: Instant) {
    let mut offset = 0;
    while offset < bytes.len() {
        assert!(Instant::now() < deadline, "attach stdin write timed out");
        match writer.write(&bytes[offset..]) {
            Ok(0) => panic!("attach stdin made no progress"),
            Ok(written) => offset += written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("attach stdin write: {error}"),
        }
    }
}

fn read_exact_bounded(
    reader: &mut impl Read,
    len: usize,
    deadline: Instant,
    read_index: &mut usize,
) -> Vec<u8> {
    const READ_SIZES: [usize; 7] = [1, 2, 5, 17, 257, 1021, 4093];
    let mut output = Vec::with_capacity(len);
    while output.len() < len {
        assert!(Instant::now() < deadline, "attach stdout read timed out");
        let wanted = READ_SIZES[*read_index % READ_SIZES.len()].min(len - output.len());
        *read_index += 1;
        let mut chunk = vec![0; wanted];
        match reader.read(&mut chunk) {
            Ok(0) => panic!("attach stdout reached early EOF"),
            Ok(read) => output.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("attach stdout read: {error}"),
        }
    }
    output
}

fn read_until_bounded(reader: &mut impl Read, needle: &[u8], deadline: Instant) -> Vec<u8> {
    let mut output = Vec::new();
    let mut byte = [0u8; 1];
    while !output.ends_with(needle) {
        assert!(
            Instant::now() < deadline,
            "starter readiness timed out: {output:?}"
        );
        match reader.read(&mut byte) {
            Ok(0) => panic!("starter reached EOF before readiness: {output:?}"),
            Ok(_) => output.push(byte[0]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("starter readiness read: {error}"),
        }
    }
    output
}

fn assert_quiet(reader: &mut impl Read, duration: Duration) {
    let deadline = Instant::now() + duration;
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => panic!("attach exited before deliberate detach"),
            Ok(_) => panic!("synthetic byte after expected output: {byte:?}"),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("attach stdout quiet check: {error}"),
        }
    }
}

fn drain_to_eof(reader: &mut impl Read, deadline: Instant) -> Vec<u8> {
    let mut output = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        assert!(Instant::now() < deadline, "attach stdout EOF timed out");
        match reader.read(&mut chunk) {
            Ok(0) => return output,
            Ok(read) => output.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("attach stdout final drain: {error}"),
        }
    }
}

fn attach_round_trip(tag: &str, fragments: &[Vec<u8>], timeout: Duration) -> Vec<u8> {
    let session = SessionGuard::start_detached(tag);
    let mut command = session.command();
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .args(["attach", NAME, "--take-over"]);
    let mut attach = command.spawn().unwrap();
    let mut stdin = attach.stdin.take().unwrap();
    let mut stdout = attach.stdout.take().unwrap();
    sys::set_nonblocking(stdin.as_fd()).unwrap();
    sys::set_nonblocking(stdout.as_fd()).unwrap();
    let attach = ChildGuard::new(attach);
    let deadline = Instant::now() + timeout;
    assert_quiet(&mut stdout, Duration::from_millis(40));

    let mut actual = Vec::new();
    let mut read_index = 0;
    for fragment in fragments {
        write_bounded(&mut stdin, fragment, deadline);
        let echoed = read_exact_bounded(&mut stdout, fragment.len(), deadline, &mut read_index);
        assert_eq!(&echoed, fragment, "fragment changed across the real PTY");
        actual.extend_from_slice(&echoed);
    }
    assert_quiet(&mut stdout, Duration::from_millis(40));
    drop(stdin);
    let status = attach.wait(deadline, "attached client detach");
    assert_eq!(status.code(), Some(0), "stdin EOF is a clean detach");
    assert!(
        drain_to_eof(&mut stdout, deadline).is_empty(),
        "no synthetic suffix may follow the exact payload"
    );
    session.finish();
    actual
}

#[test]
fn named_terminal_byte_classes_are_exact_across_fragmented_writes_and_reads() {
    let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
        ("nul", vec![vec![0]]),
        ("ff", vec![vec![0xff]]),
        (
            "invalid utf8 split",
            vec![vec![0xf0], vec![0x28], vec![0x8c], vec![0x28]],
        ),
        ("carriage return", vec![vec![b'\r']]),
        ("line feed", vec![vec![b'\n']]),
        ("crlf", vec![vec![b'\r'], vec![b'\n']]),
        (
            "csi split",
            vec![b"\x1b".to_vec(), b"[31".to_vec(), b"mred\x1b[0m".to_vec()],
        ),
        ("osc", vec![b"\x1b]0;arbitrary-byte-title\x07".to_vec()]),
        (
            "dcs split at st",
            vec![b"\x1bP1;2|payload\x1b".to_vec(), b"\\".to_vec()],
        ),
        ("kitty keyboard", vec![b"\x1b[>1u\x1b[97;5u".to_vec()]),
        (
            "kitty graphics split at st",
            vec![b"\x1b_Gf=24,s=1,v=1;AAAA\x1b".to_vec(), b"\\".to_vec()],
        ),
        (
            "bracketed paste",
            vec![b"\x1b[200~paste\0\xff\r\n\x1b[201~".to_vec()],
        ),
        (
            "alternate screen",
            vec![b"\x1b[?1049halternate\x1b[?1049l".to_vec()],
        ),
        (
            "partial escape across reads",
            vec![
                b"\x1b".to_vec(),
                b"[".to_vec(),
                b"?25".to_vec(),
                b"l".to_vec(),
            ],
        ),
    ];
    let mut fragments = Vec::new();
    let mut expected = Vec::new();
    for (label, parts) in cases {
        assert!(!label.is_empty());
        for part in parts {
            expected.extend_from_slice(&part);
            fragments.push(part);
        }
    }
    let actual = attach_round_trip("classes", &fragments, Duration::from_secs(20));
    assert_eq!(actual, expected);
    assert!(!actual.windows(5).any(|window| window == b"READY"));
}

fn deterministic_bytes(len: usize) -> Vec<u8> {
    let mut state = 0xd1b5_4a32_d192_ed03u64;
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        bytes.push((state >> 29) as u8);
    }
    bytes
}

#[test]
fn deterministic_multi_megabyte_stream_has_no_prefix_suffix_or_loss() {
    const LEN: usize = 4 * 1024 * 1024 + 257;
    let expected = deterministic_bytes(LEN);
    let fragments: Vec<Vec<u8>> = expected.chunks(16_381).map(<[u8]>::to_vec).collect();
    let actual = attach_round_trip("multi", &fragments, Duration::from_secs(60));
    assert_eq!(actual.len(), LEN);
    assert_eq!(actual, expected);
}
