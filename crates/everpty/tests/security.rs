//! Public filesystem-behavior tests for `everpty::session`
//! (plans/m2-plan.md §8; M2 commit 3).
//!
//! Hazard inventory: these tests create files, directories, FIFOs, and
//! Unix sockets under unique fixtures in the system temp directory, and
//! one test spawns one reader thread. No test spawns or terminates a
//! process, sends a signal, or mutates the process environment (state
//! root candidates are injected). Exact-mode assertions assume the
//! ambient umask does not clear user permission bits.
#![allow(clippy::unwrap_used)]

use std::ffi::OsStr;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use everpty::error::Error;
use everpty::limits::Limits;
use everpty::session::{
    resolve_state_root_from, ChildMeta, SessionMeta, StateRoot, METADATA_MAX_BYTES,
};

static FIXTURE: AtomicUsize = AtomicUsize::new(0);

/// Ownership guard over an exclusively-created fixture base. Held for
/// the whole test; on drop it best-effort removes only the base this
/// guard itself created — never a predictable path someone else owns.
struct Fixture {
    base: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let mut private_dir = std::fs::DirBuilder::new();
        private_dir.mode(0o700);
        for _ in 0..64 {
            let n = FIXTURE.fetch_add(1, Ordering::Relaxed);
            let unique = format!("everpty-security-{}-{}", std::process::id(), n);
            let base = std::env::temp_dir().join(unique);
            match private_dir.create(&base) {
                Ok(()) => return Self { base },
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("fixture base: {e}"),
            }
        }
        panic!("fixture base: exhausted unique names");
    }

    fn base(&self) -> &Path {
        &self.base
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Sets the wrapped stop flag when dropped, so a panicking test can
/// never leave a helper thread detached and looping.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn make_root(base: &Path) -> StateRoot {
    let candidate = base.join("root");
    resolve_state_root_from(std::slice::from_ref(&candidate)).unwrap()
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn fifo(path: &Path) {
    nix::unistd::mkfifo(path, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
}

fn sample_meta(name: &str, limits: &Limits) -> SessionMeta {
    SessionMeta::new(
        name,
        limits,
        OsStr::new("/bin/sample-shell"),
        4242,
        99,
        1_000_000,
    )
    .unwrap()
    .with_origins(limits, vec!["cli-origin".to_owned()])
    .unwrap()
}

#[test]
fn state_root_first_usable_wins_and_is_0700() {
    let fx = Fixture::new();
    let first = fx.base().join("mid").join("aa");
    let second = fx.base().join("bb");
    let root = resolve_state_root_from(&[first.clone(), second.clone()]).unwrap();
    assert_eq!(root.path(), first.as_path());
    assert!(first.is_dir());
    assert_eq!(mode_of(&first), 0o700);
    // Intermediate components created by the walk are also 0700.
    assert_eq!(mode_of(&fx.base().join("mid")), 0o700);
    assert!(!second.exists(), "later candidates must not be touched");
}

#[test]
fn state_root_skips_unsafe_candidates() {
    let fx = Fixture::new();
    let base = fx.base();

    // Symlink to a perfectly safe directory: still rejected (no-follow).
    let real = base.join("real");
    std::fs::create_dir(&real).unwrap();
    chmod(&real, 0o700);
    let link = base.join("lnk");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    // Wrong type: a regular file where a directory should be.
    let file = base.join("file");
    std::fs::write(&file, b"not a dir").unwrap();

    // Wrong mode: 0777 directory.
    let open = base.join("open");
    std::fs::create_dir(&open).unwrap();
    chmod(&open, 0o777);

    let relative = PathBuf::from("everpty-relative-candidate");

    let candidates = [relative, link.clone(), file.clone(), open.clone()];
    assert!(matches!(
        resolve_state_root_from(&candidates),
        Err(Error::StateRootUnavailable)
    ));
    // Nothing was repaired into acceptance.
    assert!(std::fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(file.is_file());
    assert_eq!(mode_of(&open), 0o777, "never chmod-repaired");
}

#[test]
fn session_dir_0700_lock_meta_0600() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();
    let locked = root.session("s1", &limits).unwrap().lock().unwrap();
    let meta = sample_meta("s1", &limits);
    locked.store_metadata(&limits, &meta).unwrap();
    let dir = root.path().join("s1");
    assert_eq!(mode_of(&dir), 0o700);
    assert_eq!(mode_of(&dir.join("lock")), 0o600);
    assert_eq!(mode_of(&dir.join("meta")), 0o600);
    // Successful publication leaves no abandoned temp file behind.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n.to_string_lossy().starts_with("meta.tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn bound_session_retirement_is_dirfd_relative_and_idempotent() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();
    let locked = root.session("retire", &limits).unwrap().lock().unwrap();
    locked
        .store_metadata(&limits, &sample_meta("retire", &limits))
        .unwrap();
    let mut bound = locked.bind_broker_socket(&limits).unwrap();
    let dir = root.path().join("retire");
    assert!(dir.join("socket").exists());
    bound.retire_socket().unwrap();
    assert!(!dir.join("socket").exists());
    assert!(dir.exists(), "terminal replies may still be draining");
    bound.retire_socket().unwrap();
    bound.retire_state().unwrap();
    assert!(!dir.exists());
    bound.retire_state().unwrap();
}

#[test]
fn retirement_retains_unknown_entries_and_parent_replacements() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();

    let locked = root.session("unknown", &limits).unwrap().lock().unwrap();
    let mut bound = locked.bind_broker_socket(&limits).unwrap();
    let unknown = root.path().join("unknown").join("foreign");
    std::fs::write(&unknown, b"keep").unwrap();
    assert!(bound.retire_state().is_err());
    assert!(
        unknown.exists(),
        "unknown object must never be recursively removed"
    );

    let locked = root.session("swapped", &limits).unwrap().lock().unwrap();
    let mut swapped = locked.bind_broker_socket(&limits).unwrap();
    let original = root.path().join("swapped");
    let moved = root.path().join("moved-original");
    std::fs::rename(&original, &moved).unwrap();
    let mut replacement = std::fs::DirBuilder::new();
    replacement.mode(0o700);
    replacement.create(&original).unwrap();
    std::fs::write(original.join("sentinel"), b"replacement").unwrap();
    assert!(matches!(
        swapped.retire_socket(),
        Err(Error::StatePathUnsafe)
    ));
    assert_eq!(
        std::fs::read(original.join("sentinel")).unwrap(),
        b"replacement"
    );
    assert!(
        moved.join("socket").exists(),
        "original entry is retained safely"
    );

    let locked = root.session("meta-swap", &limits).unwrap().lock().unwrap();
    locked
        .store_metadata(&limits, &sample_meta("meta-swap", &limits))
        .unwrap();
    let mut meta_swapped = locked.bind_broker_socket(&limits).unwrap();
    let meta = root.path().join("meta-swap").join("meta");
    std::fs::rename(&meta, root.path().join("saved-owned-meta")).unwrap();
    std::fs::write(&meta, b"foreign-safe-shaped-metadata").unwrap();
    std::fs::set_permissions(&meta, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        meta_swapped.retire_state(),
        Err(Error::StatePathUnsafe)
    ));
    assert_eq!(
        std::fs::read(&meta).unwrap(),
        b"foreign-safe-shaped-metadata",
        "same-mode metadata replacement must be retained"
    );
}

#[test]
fn second_lock_opener_gets_already_exists() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();
    let held = root.session("s1", &limits).unwrap().lock().unwrap();
    let second = root.session("s1", &limits).unwrap();
    assert!(matches!(second.lock(), Err(Error::AlreadyExists)));
    drop(held);
}

#[test]
fn lock_rejects_unsafe_existing_lock_file() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();

    // Pre-made 0644 lock file: rejected before flock, never chmodded.
    let loose = root.session("s2", &limits).unwrap();
    let loose_lock = root.path().join("s2/lock");
    std::fs::write(&loose_lock, b"").unwrap();
    chmod(&loose_lock, 0o644);
    assert!(matches!(loose.lock(), Err(Error::StatePathUnsafe)));
    assert_eq!(mode_of(&loose_lock), 0o644, "never chmod-repaired");

    // FIFO planted at the lock name: the nonblocking open cannot hang
    // and the fd-stat type check rejects it.
    let planted = root.session("s3", &limits).unwrap();
    fifo(&root.path().join("s3/lock"));
    assert!(matches!(planted.lock(), Err(Error::StatePathUnsafe)));

    // Directory planted at the lock name: EISDIR before any fd-stat,
    // resolved to the typed error by no-follow stat evidence.
    let dir_lock = root.session("s4", &limits).unwrap();
    std::fs::create_dir(root.path().join("s4/lock")).unwrap();
    assert!(matches!(dir_lock.lock(), Err(Error::StatePathUnsafe)));

    // Mode-000 lock file we own: EACCES on open, typed via the same
    // no-follow stat evidence — never a generic Io error.
    let dark_lock = root.session("s5", &limits).unwrap();
    let dark_path = root.path().join("s5/lock");
    std::fs::write(&dark_path, b"").unwrap();
    chmod(&dark_path, 0o000);
    assert!(matches!(dark_lock.lock(), Err(Error::StatePathUnsafe)));
    assert_eq!(mode_of(&dark_path), 0o000, "never chmod-repaired");
}

#[test]
fn socket_path_over_limit_is_path_too_long_and_nothing_created() {
    let fx = Fixture::new();
    let long_component = "x".repeat(90);
    let candidate = fx.base().join(long_component);
    let root = resolve_state_root_from(std::slice::from_ref(&candidate)).unwrap();
    let limits = Limits::default();
    // Sanity: root + "/s1/socket" exceeds the 107-byte sun_path bound.
    assert!(root.path().as_os_str().len() + 1 + 2 + 1 + 6 > limits.unix_path_max);
    assert!(matches!(
        root.session("s1", &limits),
        Err(Error::PathTooLong)
    ));
    assert!(
        !root.path().join("s1").exists(),
        "the length gate must fire before any session state is created"
    );
}

#[test]
fn meta_unsafe_entries_rejected_without_blocking() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();

    // FIFO named `meta`: the nonblocking no-follow open returns
    // promptly and the fd-stat type check rejects it unread.
    let m1 = root.session("m1", &limits).unwrap();
    fifo(&root.path().join("m1/meta"));
    assert!(matches!(
        m1.load_metadata(&limits),
        Err(Error::StatePathUnsafe)
    ));

    // Loose-mode regular file.
    let m2 = root.session("m2", &limits).unwrap();
    let loose = root.path().join("m2/meta");
    std::fs::write(&loose, b"x").unwrap();
    chmod(&loose, 0o644);
    assert!(matches!(
        m2.load_metadata(&limits),
        Err(Error::StatePathUnsafe)
    ));
    assert_eq!(mode_of(&loose), 0o644, "never chmod-repaired");

    // Symlink, even to a safe 0600 regular file.
    let m3 = root.session("m3", &limits).unwrap();
    let target = root.path().join("m3/target");
    std::fs::write(&target, b"x").unwrap();
    chmod(&target, 0o600);
    std::os::unix::fs::symlink("target", root.path().join("m3/meta")).unwrap();
    assert!(matches!(
        m3.load_metadata(&limits),
        Err(Error::StatePathUnsafe)
    ));

    // Unix socket planted at the meta name: ENXIO before any read,
    // resolved to the typed error by no-follow stat evidence.
    let m4 = root.session("m4", &limits).unwrap();
    let _sock_holder = UnixListener::bind(root.path().join("m4/meta")).unwrap();
    assert!(matches!(
        m4.load_metadata(&limits),
        Err(Error::StatePathUnsafe)
    ));

    // Mode-000 metadata file we own: EACCES, same typed resolution.
    let m5 = root.session("m5", &limits).unwrap();
    let dark_meta = root.path().join("m5/meta");
    std::fs::write(&dark_meta, b"x").unwrap();
    chmod(&dark_meta, 0o000);
    assert!(matches!(
        m5.load_metadata(&limits),
        Err(Error::StatePathUnsafe)
    ));
}

#[test]
fn metadata_round_trip_present_and_absent_child() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();
    let locked = root.session("s4", &limits).unwrap().lock().unwrap();
    let reader = root.session("s4", &limits).unwrap();

    let absent = sample_meta("s4", &limits);
    locked.store_metadata(&limits, &absent).unwrap();
    assert_eq!(reader.load_metadata(&limits).unwrap(), absent);

    let present = absent
        .clone()
        .with_child(ChildMeta::new(777, 777, 123_456).unwrap());
    locked.store_metadata(&limits, &present).unwrap();
    assert_eq!(reader.load_metadata(&limits).unwrap(), present);
}

#[test]
fn metadata_file_over_cap_is_too_large() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();
    let sd = root.session("big", &limits).unwrap();
    let meta_path = root.path().join("big/meta");
    std::fs::write(&meta_path, vec![0u8; METADATA_MAX_BYTES + 1]).unwrap();
    chmod(&meta_path, 0o600);
    assert!(matches!(
        sd.load_metadata(&limits),
        Err(Error::MetadataTooLarge)
    ));
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let file_type = entry.file_type().unwrap();
        if file_type.is_dir() {
            collect_files(&entry.path(), out);
        } else if file_type.is_file() {
            out.push(entry.path());
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn state_dir_byte_scan_finds_no_payload_or_secrets() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();
    let locked = root.session("scan1", &limits).unwrap().lock().unwrap();
    let meta = sample_meta("scan1", &limits);
    locked.store_metadata(&limits, &meta).unwrap();

    // These sentinels exist only in this test binary: the commit-3 API
    // surface offers no channel (payload, environment, keystrokes, or
    // full argv) through which they could ever reach the state dir.
    let sentinels: [&[u8]; 3] = [
        b"PAYLOAD-SENTINEL-9427",
        b"ENV-SECRET-SENTINEL-31",
        b"KEYSTROKE-SENTINEL-77",
    ];

    let mut files = Vec::new();
    collect_files(root.path(), &mut files);
    assert!(!files.is_empty());
    for file in &files {
        let bytes = std::fs::read(file).unwrap();
        for sentinel in sentinels {
            assert!(
                !contains(&bytes, sentinel),
                "sentinel found in {}",
                file.display()
            );
        }
    }
    // Only the declared metadata fields appear on disk.
    let meta_bytes = std::fs::read(root.path().join("scan1/meta")).unwrap();
    assert!(contains(&meta_bytes, b"scan1"));
    assert!(contains(&meta_bytes, b"/bin/sample-shell"));
    assert!(contains(&meta_bytes, b"cli-origin"));
}

#[test]
fn atomic_rewrite_readers_never_see_partial_record() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();
    let locked = root.session("atom", &limits).unwrap().lock().unwrap();
    let reader_dir = root.session("atom", &limits).unwrap(); // read-only handle

    let label_a = "/A".repeat(100);
    let arg_a = OsStr::new(label_a.as_str());
    let meta_a = SessionMeta::new("atom", &limits, arg_a, 1, 0, 0).unwrap();
    let meta_b = SessionMeta::new("atom", &limits, OsStr::new("/b"), 2, 0, 0).unwrap();
    locked.store_metadata(&limits, &meta_a).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    // Panic-safe: however this test unwinds, the reader is told to stop
    // and cannot remain detached and looping.
    let _stop_guard = StopOnDrop(Arc::clone(&stop));
    let reader_stop = Arc::clone(&stop);
    // One-shot announcement flag + single-slot channel: the reader
    // sends exactly one acknowledgement, so nothing is unbounded and
    // nothing needs draining.
    let ack_armed = Arc::new(AtomicBool::new(false));
    let reader_armed = Arc::clone(&ack_armed);
    let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let expect_a = meta_a.clone();
    let expect_b = meta_b.clone();
    let reader = std::thread::spawn(move || {
        let mut acked = false;
        while !reader_stop.load(Ordering::Relaxed) {
            // Sampled BEFORE the load: an acknowledged read started
            // strictly after the announcement was armed.
            let armed_before = reader_armed.load(Ordering::SeqCst);
            let seen = reader_dir
                .load_metadata(&Limits::default())
                .expect("a concurrent load must never fail");
            assert!(
                seen == expect_a || seen == expect_b,
                "reader observed a partial or mixed record"
            );
            if armed_before && !acked {
                acked = true;
                let _ = ack_tx.try_send(());
            }
        }
    });

    // Phase 1: rewriting begins.
    for i in 0..100 {
        let next = if i % 2 == 0 { &meta_b } else { &meta_a };
        locked.store_metadata(&limits, next).unwrap();
    }
    // Deterministic concurrency proof: arm the one-shot announcement;
    // the acknowledged read starts and completes after phase 1, and
    // phase 2 keeps rewriting after it — so at least one successful
    // read happened after rewriting began and before it ended, and the
    // test can never pass vacuously.
    ack_armed.store(true, Ordering::SeqCst);
    let acked = ack_rx.recv_timeout(std::time::Duration::from_secs(2));
    if acked.is_err() {
        stop.store(true, Ordering::Relaxed);
        reader.join().expect("reader thread panicked");
        panic!("no read completed while rewriting was in progress");
    }
    // Phase 2: rewriting continues after the proven read.
    for i in 0..100 {
        let next = if i % 2 == 0 { &meta_a } else { &meta_b };
        locked.store_metadata(&limits, next).unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    reader.join().expect("reader thread panicked");
}

#[test]
fn stale_cleanup_requires_both_gates() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();
    // Gate 2 (the held exclusive lock) is enforced by the type system:
    // recovery exists only on LockedSession.

    // Live bound+listening 0600 socket: the probe connects => kept.
    let live = root.session("slive", &limits).unwrap().lock().unwrap();
    let live_path = live.dir().socket_path();
    let listener = UnixListener::bind(&live_path).unwrap();
    chmod(&live_path, 0o600);
    assert!(!live.recover_stale_socket().unwrap());
    assert!(live_path.exists(), "a live socket must never be unlinked");
    drop(listener);

    // No socket entry at all: absent => Ok(false), nothing to do.
    let none = root.session("snone", &limits).unwrap().lock().unwrap();
    assert!(!none.recover_stale_socket().unwrap());

    // Dead socket (listener closed) under the held lock: connect is
    // refused and the validated entry is unlinked.
    let dead = root.session("sdead", &limits).unwrap().lock().unwrap();
    let dead_path = dead.dir().socket_path();
    drop(UnixListener::bind(&dead_path).unwrap());
    chmod(&dead_path, 0o600);
    assert!(dead.recover_stale_socket().unwrap());
    assert!(!dead_path.exists());

    // Non-socket entry at the socket name: an error, and the entry is
    // retained — regardless of which errno the kernel reports for a
    // connect to a non-socket file.
    let planted = root.session("sfile", &limits).unwrap().lock().unwrap();
    let planted_path = planted.dir().socket_path();
    std::fs::write(&planted_path, b"not a socket").unwrap();
    assert!(planted.recover_stale_socket().is_err());
    assert!(planted_path.exists(), "non-socket entry must be retained");
}

#[test]
fn stale_probe_is_bound_to_directory_identity() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();

    // A live listener inside the LOCKED original directory.
    let live = root.session("sboth", &limits).unwrap().lock().unwrap();
    let original_socket = live.dir().socket_path();
    let _listener = UnixListener::bind(&original_socket).unwrap();
    chmod(&original_socket, 0o600);

    // Rename the displayed root away and rebuild the display path with
    // a planted DEAD 0600 socket. A path-resolved probe would get a
    // refusal from the replacement and could then authorize unlinking
    // the live socket through the still-held dirfd.
    let displayed_root = fx.base().join("root");
    let moved_root = fx.base().join("root-moved");
    std::fs::rename(&displayed_root, &moved_root).unwrap();
    let replacement_dir = displayed_root.join("sboth");
    std::fs::create_dir_all(&replacement_dir).unwrap();
    let replacement_socket = replacement_dir.join("socket");
    drop(UnixListener::bind(&replacement_socket).unwrap());
    chmod(&replacement_socket, 0o600);

    // The dirfd-identity-bound probe reaches the live socket in the
    // moved original directory: nothing is removed anywhere.
    assert!(!live.recover_stale_socket().unwrap());
    let moved_socket = moved_root.join("sboth/socket");
    assert!(moved_socket.exists(), "live original socket must survive");
    assert!(replacement_socket.exists(), "replacement must be untouched");
}

#[test]
fn discovery_skips_corrupt_mismatched_unsafe_never_fatal() {
    let fx = Fixture::new();
    let root = make_root(fx.base());
    let limits = Limits::default();

    // The one well-formed session.
    let good = root.session("good", &limits).unwrap().lock().unwrap();
    let good_meta = sample_meta("good", &limits);
    good.store_metadata(&limits, &good_meta).unwrap();

    // Corrupt metadata bytes.
    let _corrupt = root.session("corrupt", &limits).unwrap();
    let corrupt_meta = root.path().join("corrupt/meta");
    std::fs::write(&corrupt_meta, b"garbage record").unwrap();
    chmod(&corrupt_meta, 0o600);

    // Metadata name != directory name.
    let mismatch = root.session("mismatch", &limits).unwrap().lock().unwrap();
    let other_meta = sample_meta("other", &limits);
    mismatch.store_metadata(&limits, &other_meta).unwrap();

    // Valid metadata inside a directory with an unsafe mode.
    let loose = root.session("loose", &limits).unwrap().lock().unwrap();
    let loose_meta = sample_meta("loose", &limits);
    loose.store_metadata(&limits, &loose_meta).unwrap();
    chmod(&root.path().join("loose"), 0o777);

    // A session directory with no metadata at all.
    let _bare = root.session("bare", &limits).unwrap();

    // Entry-local unsafe objects: a mode-000 session directory and a
    // session whose metadata is unreadable (mode 000) are skipped, not
    // fatal — while EMFILE/ENOMEM/EIO-style failures would propagate.
    let _dark = root.session("dark", &limits).unwrap();
    chmod(&root.path().join("dark"), 0o000);
    let _darkmeta = root.session("darkmeta", &limits).unwrap();
    let dark_meta = root.path().join("darkmeta/meta");
    std::fs::write(&dark_meta, b"x").unwrap();
    chmod(&dark_meta, 0o000);

    // A stray regular file and an invalid-name directory in the root.
    std::fs::write(root.path().join("strayfile"), b"x").unwrap();
    std::fs::create_dir(root.path().join(".hidden")).unwrap();

    let sessions = root.list_sessions(&limits).unwrap();
    assert_eq!(sessions.len(), 1, "only the well-formed session is listed");
    assert_eq!(sessions[0].name(), "good");
    assert_eq!(sessions[0].exec_label(), "/bin/sample-shell");

    // Restore traversability so the fixture guard can clean up.
    chmod(&root.path().join("dark"), 0o700);
}
