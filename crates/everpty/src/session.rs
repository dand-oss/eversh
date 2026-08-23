//! On-disk session state: root discovery, 0700/0600 paths, per-session
//! locking, bounded v1 metadata, atomic publication, discovery, and
//! two-gate stale-socket recovery (plans/m2-plan.md §8).
//!
//! Capability discipline: [`StateRoot`] and [`SessionDir`] own validated
//! directory fds, and every lock, metadata, rename, discovery, and unlink
//! operates relative to those fds — path strings are display only and are
//! never trusted twice. [`LockedSession`] binds the per-session `flock`
//! to one exact directory, so one session's lock can never authorize
//! another session's mutation. Existing objects with the wrong type,
//! owner, or mode are rejected, never repaired.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::Error;
use crate::frame;
use crate::limits::Limits;
use crate::sys::{self, ProbeOutcome};

/// Complete metadata record cap in bytes (moves into `Limits` in M2
/// commit 5, with the provisional-limit inventory test).
pub const METADATA_MAX_BYTES: usize = 4096;
/// Executable display-label cap in bytes (cut on a char boundary).
pub const EXEC_LABEL_MAX_BYTES: usize = 256;
/// Per-origin label cap in bytes (over-cap is an error, never truncated).
pub const ORIGIN_LABEL_MAX_BYTES: usize = 64;
/// Maximum origin entries per record.
pub const ORIGIN_COUNT_MAX: usize = 4;

const MAGIC: &[u8; 8] = b"EVPTYM1\0";
const LOCK_FILE: &str = "lock";
const META_FILE: &str = "meta";
const SOCKET_FILE: &str = "socket";

// ---------------------------------------------------------------------------
// Pure stat policy (the only foreign-UID coverage is this matrix)
// ---------------------------------------------------------------------------

/// A directory owned by `euid` with permission bits exactly 0700.
pub(crate) fn stat_is_safe_dir(st: &nix::sys::stat::FileStat, euid: libc::uid_t) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFDIR
        && st.st_uid == euid
        && (st.st_mode & 0o7777) == 0o700
}

/// A regular file owned by `euid` with permission bits exactly 0600.
pub(crate) fn stat_is_safe_private_file(st: &nix::sys::stat::FileStat, euid: libc::uid_t) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFREG
        && st.st_uid == euid
        && (st.st_mode & 0o7777) == 0o600
}

/// A Unix socket owned by `euid` with permission bits exactly 0600.
pub(crate) fn stat_is_safe_socket(st: &nix::sys::stat::FileStat, euid: libc::uid_t) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK
        && st.st_uid == euid
        && (st.st_mode & 0o7777) == 0o600
}

/// Splits an absolute path into its raw non-empty segments. Relative
/// paths and any raw `.`/`..` segment disqualify the candidate — the
/// dirfd walk never re-interprets or escapes upward. This deliberately
/// works on raw bytes: `Path::components()` normalizes interior `.`
/// away and would silently accept `/a/./b`.
pub(crate) fn normal_components(path: &Path) -> Option<Vec<&OsStr>> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.first() != Some(&b'/') {
        return None;
    }
    let mut out = Vec::new();
    for segment in bytes.split(|&b| b == b'/') {
        match segment {
            b"" => continue, // leading, trailing, or doubled slash
            b"." | b".." => return None,
            _ => out.push(OsStr::from_bytes(segment)),
        }
    }
    Some(out)
}

/// Errnos from a no-follow open that can mean "the entry itself is the
/// wrong kind of object or has an unsafe mode" — and only those.
/// Resource failures (`EMFILE`, `ENFILE`, `ENOMEM`, `EIO`, …) are
/// deliberately absent and can never become `StatePathUnsafe`.
const OBJECT_SHAPED_ERRNOS: [i32; 6] = [
    libc::EACCES,
    libc::EISDIR,
    libc::ELOOP,
    libc::ENXIO,
    libc::ENODEV,
    libc::ENOTDIR,
];

/// After a failed no-follow open, decides from no-follow dirfd-relative
/// stat evidence whether the failure is the entry itself being unsafe
/// (wrong type, symlink, or unsafe mode) — typed
/// [`Error::StatePathUnsafe`] — or a genuine I/O failure that must
/// propagate unchanged. The entry is condemned only when the stat
/// succeeds AND the object fails the caller's safety predicate.
fn open_failure_error(
    dirfd: BorrowedFd<'_>,
    name: &OsStr,
    expected_safe: fn(&nix::sys::stat::FileStat, libc::uid_t) -> bool,
    e: std::io::Error,
) -> Error {
    let object_shaped = e.raw_os_error().is_some_and(|n| OBJECT_SHAPED_ERRNOS.contains(&n));
    if !object_shaped {
        return Error::Io(e);
    }
    match sys::fstatat_nofollow(dirfd, name) {
        Ok(st) if !expected_safe(&st, sys::effective_uid()) => Error::StatePathUnsafe,
        _ => Error::Io(e),
    }
}

/// Metadata-load failures that condemn only the enumerated entry:
/// corrupt or oversized records, unsafe path objects, or an
/// absent/raced `meta` (`ENOENT`). Everything else — `EMFILE`,
/// `ENFILE`, `ENOMEM`, `EIO`, … — propagates: discovery never silently
/// returns a partial result on unexpected I/O.
pub(crate) fn discovery_skippable(e: &Error) -> bool {
    match e {
        Error::MetadataInvalid | Error::MetadataTooLarge | Error::StatePathUnsafe => true,
        Error::Io(io) => io.raw_os_error() == Some(libc::ENOENT),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// State root
// ---------------------------------------------------------------------------

/// A validated state-root directory: the fd is the capability; the path
/// is the lexically rebuilt walked path, kept for display only.
pub struct StateRoot {
    dirfd: OwnedFd,
    path: PathBuf,
}

/// Opens `name` under `dirfd`, creating it 0700 when absent. A lost
/// `mkdirat` race (`EEXIST`) falls through to the no-follow reopen, so
/// whatever won the race is validated like any pre-existing entry.
fn open_or_create_subdir(dirfd: BorrowedFd<'_>, name: &OsStr) -> std::io::Result<OwnedFd> {
    match sys::openat_dir(dirfd, name) {
        Ok(fd) => Ok(fd),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            match sys::mkdirat_private(dirfd, name) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
                Err(e) => return Err(e),
            }
            sys::openat_dir(dirfd, name)
        }
        Err(e) => Err(e),
    }
}

/// Walks one absolute candidate component-by-component from `/`,
/// creating missing directories 0700 and refusing symlinks at every
/// step. `None` means the candidate is unusable (never repaired).
fn open_walked_dir(candidate: &Path, euid: libc::uid_t) -> Option<(OwnedFd, PathBuf)> {
    let comps = normal_components(candidate)?;
    let mut fd = sys::open_root_dir().ok()?;
    let mut walked = PathBuf::from("/");
    for name in comps {
        let next = open_or_create_subdir(fd.as_fd(), name).ok()?;
        fd = next;
        walked.push(name);
    }
    let st = sys::fstat_fd(fd.as_fd()).ok()?;
    if !stat_is_safe_dir(&st, euid) {
        return None;
    }
    Some((fd, walked))
}

/// Resolves the first usable candidate into a [`StateRoot`]. A failed
/// or unsafe candidate is skipped, never repaired; no usable candidate
/// is [`Error::StateRootUnavailable`]. Injected candidates keep tests
/// away from process environment mutation.
pub fn resolve_state_root_from(candidates: &[PathBuf]) -> Result<StateRoot, Error> {
    let euid = sys::effective_uid();
    for candidate in candidates {
        if let Some((dirfd, path)) = open_walked_dir(candidate, euid) {
            return Ok(StateRoot { dirfd, path });
        }
    }
    Err(Error::StateRootUnavailable)
}

/// Reads the documented candidate order from the environment —
/// `EVERSH_STATE_DIR`, `XDG_RUNTIME_DIR/eversh`, `XDG_STATE_HOME/eversh`,
/// `$HOME/.local/state/eversh` — skipping unset entries (relative ones
/// are rejected by the walk), then resolves the first usable candidate.
pub fn resolve_state_root() -> Result<StateRoot, Error> {
    let mut candidates = Vec::with_capacity(4);
    if let Some(d) = std::env::var_os("EVERSH_STATE_DIR") {
        candidates.push(PathBuf::from(d));
    }
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(d).join("eversh"));
    }
    if let Some(d) = std::env::var_os("XDG_STATE_HOME") {
        candidates.push(PathBuf::from(d).join("eversh"));
    }
    if let Some(d) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(d).join(".local/state/eversh"));
    }
    resolve_state_root_from(&candidates)
}

impl StateRoot {
    /// Display-only root path (lexically rebuilt during the walk).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Opens (creating if needed) the 0700 session directory for a
    /// validated name. The socket pathname is length-checked from raw
    /// bytes BEFORE anything is created.
    pub fn session(&self, name: &str, limits: &Limits) -> Result<SessionDir, Error> {
        if !frame::validate_name(name, limits) {
            return Err(Error::NameInvalid);
        }
        let socket_len =
            self.path.as_os_str().as_bytes().len() + 1 + name.len() + 1 + SOCKET_FILE.len();
        if socket_len > limits.unix_path_max {
            return Err(Error::PathTooLong);
        }
        let dirfd = match open_or_create_subdir(self.dirfd.as_fd(), OsStr::new(name)) {
            Ok(fd) => fd,
            Err(e) => {
                return Err(open_failure_error(
                    self.dirfd.as_fd(),
                    OsStr::new(name),
                    stat_is_safe_dir,
                    e,
                ))
            }
        };
        let st = sys::fstat_fd(dirfd.as_fd())?;
        if !stat_is_safe_dir(&st, sys::effective_uid()) {
            return Err(Error::StatePathUnsafe);
        }
        Ok(SessionDir {
            dirfd,
            name: name.to_owned(),
            path: self.path.join(name),
        })
    }

    /// Enumerates sessions with readable, well-formed metadata. Skips
    /// only expected entry-local conditions (invalid or non-UTF-8
    /// names, `ENOENT` races, unsafe paths, corrupt or oversized
    /// metadata, metadata name ≠ directory name); unexpected I/O such
    /// as `EMFILE`/`ENOMEM`/`EIO` propagates — never a silent partial
    /// listing. The live probe filter arrives with the CLI (commit 8).
    pub fn list_sessions(&self, limits: &Limits) -> Result<Vec<SessionMeta>, Error> {
        let entries = sys::read_dir_at(self.dirfd.as_fd())?;
        let euid = sys::effective_uid();
        let mut out = Vec::new();
        for entry in entries {
            let Some(name) = entry.to_str() else { continue };
            if !frame::validate_name(name, limits) {
                continue;
            }
            let dirfd = match sys::openat_dir(self.dirfd.as_fd(), &entry) {
                Ok(fd) => fd,
                // The entry vanished after enumeration: an ENOENT race.
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(e) => {
                    let classified =
                        open_failure_error(self.dirfd.as_fd(), &entry, stat_is_safe_dir, e);
                    match classified {
                        // Entry-local unsafe object: skipped, never fatal.
                        Error::StatePathUnsafe => continue,
                        other => return Err(other),
                    }
                }
            };
            let st = sys::fstat_fd(dirfd.as_fd())?;
            if !stat_is_safe_dir(&st, euid) {
                continue;
            }
            let dir = SessionDir {
                dirfd,
                name: name.to_owned(),
                path: self.path.join(name),
            };
            let meta = match dir.load_metadata(limits) {
                Ok(m) => m,
                Err(e) if discovery_skippable(&e) => continue,
                Err(e) => return Err(e),
            };
            if meta.name() != name {
                continue;
            }
            out.push(meta);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Session directory and lock
// ---------------------------------------------------------------------------

/// A validated 0700 session directory (fd capability + display path).
pub struct SessionDir {
    dirfd: OwnedFd,
    name: String,
    path: PathBuf,
}

impl SessionDir {
    /// The validated session name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Display-only session directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Display-only socket pathname (`<dir>/socket`).
    pub fn socket_path(&self) -> PathBuf {
        self.path.join(SOCKET_FILE)
    }

    /// Acquires the per-session `flock`, consuming the directory
    /// capability into a [`LockedSession`]. The lock file is opened
    /// without `O_EXCL` (it is reopened across owner death) and
    /// fd-stat-validated before `flock`; an unsafe existing object is
    /// [`Error::StatePathUnsafe`], never chmod-repaired. A live owner
    /// holding the lock is [`Error::AlreadyExists`].
    pub fn lock(self) -> Result<LockedSession, Error> {
        let fd = match sys::open_lock_file_at(self.dirfd.as_fd(), OsStr::new(LOCK_FILE)) {
            Ok(fd) => fd,
            Err(e) => {
                return Err(open_failure_error(
                    self.dirfd.as_fd(),
                    OsStr::new(LOCK_FILE),
                    stat_is_safe_private_file,
                    e,
                ))
            }
        };
        let st = sys::fstat_fd(fd.as_fd())?;
        if !stat_is_safe_private_file(&st, sys::effective_uid()) {
            return Err(Error::StatePathUnsafe);
        }
        match sys::acquire_session_lock(std::fs::File::from(fd))? {
            Some(lock) => Ok(LockedSession {
                dir: self,
                _lock: lock,
            }),
            None => Err(Error::AlreadyExists),
        }
    }

    /// Loads and decodes the session metadata (read-only; no lock
    /// required). The `meta` entry must fd-stat as a regular 0600
    /// euid-owned file — a FIFO or device planted there can neither
    /// block (`O_NONBLOCK` open) nor be read; a symlink fails the
    /// no-follow open. At most `METADATA_MAX_BYTES + 1` bytes are ever
    /// read; an over-cap file is [`Error::MetadataTooLarge`].
    pub fn load_metadata(&self, limits: &Limits) -> Result<SessionMeta, Error> {
        let fd = match sys::open_meta_read_at(self.dirfd.as_fd(), OsStr::new(META_FILE)) {
            Ok(fd) => fd,
            Err(e) => {
                return Err(open_failure_error(
                    self.dirfd.as_fd(),
                    OsStr::new(META_FILE),
                    stat_is_safe_private_file,
                    e,
                ))
            }
        };
        let st = sys::fstat_fd(fd.as_fd())?;
        if !stat_is_safe_private_file(&st, sys::effective_uid()) {
            return Err(Error::StatePathUnsafe);
        }
        let mut file = std::fs::File::from(fd);
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 1024];
        while buf.len() <= METADATA_MAX_BYTES {
            let want = chunk.len().min(METADATA_MAX_BYTES + 1 - buf.len());
            let n = file.read(&mut chunk[..want])?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        if buf.len() > METADATA_MAX_BYTES {
            return Err(Error::MetadataTooLarge);
        }
        SessionMeta::decode(&buf, limits)
    }
}

/// A [`SessionDir`] plus its held exclusive lock. Metadata publication
/// and stale-socket recovery exist only here, so the flock gate is
/// enforced by the type system.
pub struct LockedSession {
    dir: SessionDir,
    _lock: sys::SessionLock,
}

static META_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl LockedSession {
    /// The locked session directory.
    pub fn dir(&self) -> &SessionDir {
        &self.dir
    }

    fn create_meta_temp(&self) -> Result<(OsString, OwnedFd), Error> {
        // Bounded retry on name collision; every attempt uses a fresh
        // unique name, and only a temp created HERE is ever removed.
        const ATTEMPTS: u32 = 16;
        for _ in 0..ATTEMPTS {
            let n = META_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = format!("meta.tmp.{}.{}", std::process::id(), n);
            match sys::create_exclusive_private_at(self.dir.dirfd.as_fd(), OsStr::new(&name)) {
                Ok(fd) => return Ok((OsString::from(name), fd)),
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => continue,
                Err(e) => return Err(Error::Io(e)),
            }
        }
        Err(Error::Io(std::io::Error::from(
            std::io::ErrorKind::AlreadyExists,
        )))
    }

    /// Atomically publishes `meta`: exclusive-create a unique temp,
    /// fd-stat check, write, then `renameat` onto `meta` with the temp
    /// fd still open. On any failure after creation, only the temp this
    /// invocation created is unlinked — never a collision path.
    pub fn store_metadata(&self, limits: &Limits, meta: &SessionMeta) -> Result<(), Error> {
        let mut bytes = Vec::with_capacity(256);
        meta.encode_into(limits, &mut bytes)?;
        let (tmp_name, fd) = self.create_meta_temp()?;
        let mut file = std::fs::File::from(fd);
        let published = (|| -> Result<(), Error> {
            let st = sys::fstat_fd(file.as_fd())?;
            if !stat_is_safe_private_file(&st, sys::effective_uid()) {
                return Err(Error::StatePathUnsafe);
            }
            file.write_all(&bytes)?;
            sys::renameat_within(self.dir.dirfd.as_fd(), &tmp_name, OsStr::new(META_FILE))?;
            Ok(())
        })();
        if published.is_err() {
            // The rename never happened, so the temp name still refers
            // to the file this invocation exclusively created.
            let _ = sys::unlinkat_file(self.dir.dirfd.as_fd(), &tmp_name);
        }
        // The temp fd stays open through the rename and is dropped here.
        drop(file);
        published
    }

    /// Two-gate stale-socket recovery. Gate 1 is the failed connect
    /// probe; gate 2 (the exclusive lock) is this type. The probe is
    /// bound to the locked directory's identity via the dirfd
    /// ([`sys::probe_unix_connect_at`]) — a renamed or replaced display
    /// path can neither divert the probe nor authorize an unlink.
    /// Returns whether the socket entry was removed.
    pub fn recover_stale_socket(&self) -> Result<bool, Error> {
        let dirfd = self.dir.dirfd.as_fd();
        let outcome = sys::probe_unix_connect_at(dirfd, OsStr::new(SOCKET_FILE))?;
        self.recover_stale_given(outcome)
    }

    /// The decision half, testable with an injected probe outcome.
    /// Connected/Pending prove only "not stale"; Absent leaves nothing
    /// to do; only Refused reaches the validated unlink, and only when
    /// the entry itself is a euid-owned, exactly-0600, non-symlink
    /// socket — anything else is retained with
    /// [`Error::StatePathUnsafe`]. An entry that disappears between
    /// probe, stat, and unlink is benign `Ok(false)`; no unvalidated
    /// entry is ever removed.
    pub(crate) fn recover_stale_given(&self, outcome: ProbeOutcome) -> Result<bool, Error> {
        match outcome {
            ProbeOutcome::Connected | ProbeOutcome::Pending | ProbeOutcome::Absent => Ok(false),
            ProbeOutcome::Refused => {
                let dirfd = self.dir.dirfd.as_fd();
                let st = match sys::fstatat_nofollow(dirfd, OsStr::new(SOCKET_FILE)) {
                    Ok(st) => st,
                    // Vanished between probe and stat: nothing stale
                    // remains to remove.
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(false),
                    Err(e) => return Err(Error::Io(e)),
                };
                if !stat_is_safe_socket(&st, sys::effective_uid()) {
                    return Err(Error::StatePathUnsafe);
                }
                match sys::unlinkat_file(dirfd, OsStr::new(SOCKET_FILE)) {
                    Ok(()) => Ok(true),
                    // Vanished between stat and unlink: equally benign.
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
                    Err(e) => Err(Error::Io(e)),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Metadata record (v1, big-endian, no trailing bytes)
// ---------------------------------------------------------------------------

/// Recorded child identity (all values validated positive `pid_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildMeta {
    pid: u32,
    pgid: u32,
    start_ticks: u64,
}

impl ChildMeta {
    /// Validates `1..=i32::MAX` PID/PGID (commit 4's post-spawn rewrite
    /// is the intended caller).
    pub fn new(pid: libc::pid_t, pgid: libc::pid_t, start_ticks: u64) -> Result<Self, Error> {
        if pid <= 0 || pgid <= 0 {
            return Err(Error::MetadataInvalid);
        }
        Ok(Self {
            pid: pid as u32,
            pgid: pgid as u32,
            start_ticks,
        })
    }

    /// Recorded child PID.
    pub fn pid(&self) -> libc::pid_t {
        self.pid as libc::pid_t
    }

    /// Recorded child process-group id.
    pub fn pgid(&self) -> libc::pid_t {
        self.pgid as libc::pid_t
    }

    /// Recorded `/proc/<pid>/stat` start ticks.
    pub fn start_ticks(&self) -> u64 {
        self.start_ticks
    }
}

/// The exact v1 metadata record (plans/m2-plan.md §8). Fields are
/// private; the validating constructors accept argv0 only — no API
/// takes full argv or environment, so neither can ever reach disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMeta {
    name: String,
    broker_pid: u32,
    broker_start_ticks: u64,
    child: Option<ChildMeta>,
    created_unix_ms: u64,
    exec_label: String,
    exec_truncated: bool,
    origins: Vec<String>,
}

/// argv0 → bounded UTF-8 display label (`to_string_lossy`, capped on a
/// char boundary, with the truncation flagged).
fn display_label(argv0: &OsStr) -> (String, bool) {
    let full = argv0.to_string_lossy();
    let s: &str = &full;
    if s.len() <= EXEC_LABEL_MAX_BYTES {
        return (s.to_owned(), false);
    }
    let mut end = EXEC_LABEL_MAX_BYTES;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    (s[..end].to_owned(), true)
}

impl SessionMeta {
    /// Builds the pre-spawn record (`child_present = 0`).
    pub fn new(
        name: &str,
        limits: &Limits,
        argv0: &OsStr,
        broker_pid: libc::pid_t,
        broker_start_ticks: u64,
        created_unix_ms: u64,
    ) -> Result<Self, Error> {
        if !frame::validate_name(name, limits) {
            return Err(Error::NameInvalid);
        }
        if broker_pid <= 0 {
            return Err(Error::MetadataInvalid);
        }
        let (exec_label, exec_truncated) = display_label(argv0);
        Ok(Self {
            name: name.to_owned(),
            broker_pid: broker_pid as u32,
            broker_start_ticks,
            child: None,
            created_unix_ms,
            exec_label,
            exec_truncated,
            origins: Vec::new(),
        })
    }

    /// Sets validated origins: at most [`ORIGIN_COUNT_MAX`] entries of
    /// at most [`ORIGIN_LABEL_MAX_BYTES`] bytes each. Over-cap input is
    /// [`Error::MetadataInvalid`] — never truncated.
    pub fn with_origins(mut self, origins: Vec<String>) -> Result<Self, Error> {
        if origins.len() > ORIGIN_COUNT_MAX
            || origins.iter().any(|o| o.len() > ORIGIN_LABEL_MAX_BYTES)
        {
            return Err(Error::MetadataInvalid);
        }
        self.origins = origins;
        Ok(self)
    }

    /// Attaches the recorded child identity (already validated by
    /// [`ChildMeta::new`]).
    pub fn with_child(mut self, child: ChildMeta) -> Self {
        self.child = Some(child);
        self
    }

    /// Validated session name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Broker PID (validated positive).
    pub fn broker_pid(&self) -> libc::pid_t {
        self.broker_pid as libc::pid_t
    }

    /// Broker `/proc` start ticks.
    pub fn broker_start_ticks(&self) -> u64 {
        self.broker_start_ticks
    }

    /// Recorded child identity, when a child has been spawned.
    pub fn child(&self) -> Option<&ChildMeta> {
        self.child.as_ref()
    }

    /// Creation wall-clock milliseconds.
    pub fn created_unix_ms(&self) -> u64 {
        self.created_unix_ms
    }

    /// Bounded UTF-8 display label built from argv0.
    pub fn exec_label(&self) -> &str {
        &self.exec_label
    }

    /// Whether the display label was cut at the byte cap.
    pub fn exec_truncated(&self) -> bool {
        self.exec_truncated
    }

    /// Validated origin labels.
    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    /// Encodes the exact v1 record, re-validating every cap. The total
    /// size check is defense-in-depth ([`Error::MetadataTooLarge`]) —
    /// with default limits, individually-bounded fields cannot reach it.
    pub fn encode_into(&self, limits: &Limits, out: &mut Vec<u8>) -> Result<(), Error> {
        if !frame::validate_name(&self.name, limits) {
            return Err(Error::NameInvalid);
        }
        let pid_ok = |p: u32| (1..=i32::MAX as u32).contains(&p);
        let child_ok = match &self.child {
            None => true,
            Some(c) => pid_ok(c.pid) && pid_ok(c.pgid),
        };
        if self.name.len() > usize::from(u16::MAX)
            || self.exec_label.len() > EXEC_LABEL_MAX_BYTES
            || self.origins.len() > ORIGIN_COUNT_MAX
            || self.origins.iter().any(|o| o.len() > ORIGIN_LABEL_MAX_BYTES)
            || !pid_ok(self.broker_pid)
            || !child_ok
        {
            return Err(Error::MetadataInvalid);
        }
        let start = out.len();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.name.len() as u16).to_be_bytes());
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(&self.broker_pid.to_be_bytes());
        out.extend_from_slice(&self.broker_start_ticks.to_be_bytes());
        match &self.child {
            None => out.push(0),
            Some(c) => {
                out.push(1);
                out.extend_from_slice(&c.pid.to_be_bytes());
                out.extend_from_slice(&c.pgid.to_be_bytes());
                out.extend_from_slice(&c.start_ticks.to_be_bytes());
            }
        }
        out.extend_from_slice(&self.created_unix_ms.to_be_bytes());
        out.extend_from_slice(&(self.exec_label.len() as u16).to_be_bytes());
        out.extend_from_slice(self.exec_label.as_bytes());
        out.push(u8::from(self.exec_truncated));
        out.push(self.origins.len() as u8);
        for origin in &self.origins {
            out.push(origin.len() as u8);
            out.extend_from_slice(origin.as_bytes());
        }
        if out.len() - start > METADATA_MAX_BYTES {
            out.truncate(start);
            return Err(Error::MetadataTooLarge);
        }
        Ok(())
    }

    /// Total parser: validates the size cap, magic, every length
    /// against the remaining bytes, option bytes, origin caps, UTF-8
    /// fields, the name policy, stored PID ranges, and trailing EOF —
    /// all before any heap allocation.
    pub fn decode(buf: &[u8], limits: &Limits) -> Result<Self, Error> {
        if buf.len() > METADATA_MAX_BYTES {
            return Err(Error::MetadataTooLarge);
        }
        let mut r = Reader { buf, pos: 0 };
        if r.take(MAGIC.len())? != MAGIC {
            return Err(Error::MetadataInvalid);
        }
        let name_len = usize::from(r.u16()?);
        let name = std::str::from_utf8(r.take(name_len)?).map_err(|_| Error::MetadataInvalid)?;
        if !frame::validate_name(name, limits) {
            return Err(Error::MetadataInvalid);
        }
        let pid_ok = |p: u32| (1..=i32::MAX as u32).contains(&p);
        let broker_pid = r.u32()?;
        if !pid_ok(broker_pid) {
            return Err(Error::MetadataInvalid);
        }
        let broker_start_ticks = r.u64()?;
        let child = match r.u8()? {
            0 => None,
            1 => {
                let pid = r.u32()?;
                let pgid = r.u32()?;
                let start_ticks = r.u64()?;
                if !pid_ok(pid) || !pid_ok(pgid) {
                    return Err(Error::MetadataInvalid);
                }
                Some(ChildMeta {
                    pid,
                    pgid,
                    start_ticks,
                })
            }
            _ => return Err(Error::MetadataInvalid),
        };
        let created_unix_ms = r.u64()?;
        let label_len = usize::from(r.u16()?);
        if label_len > EXEC_LABEL_MAX_BYTES {
            return Err(Error::MetadataInvalid);
        }
        let exec_label =
            std::str::from_utf8(r.take(label_len)?).map_err(|_| Error::MetadataInvalid)?;
        let exec_truncated = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MetadataInvalid),
        };
        let origin_count = usize::from(r.u8()?);
        if origin_count > ORIGIN_COUNT_MAX {
            return Err(Error::MetadataInvalid);
        }
        let mut origin_slices: [&str; ORIGIN_COUNT_MAX] = [""; ORIGIN_COUNT_MAX];
        for slot in origin_slices.iter_mut().take(origin_count) {
            let len = usize::from(r.u8()?);
            if len > ORIGIN_LABEL_MAX_BYTES {
                return Err(Error::MetadataInvalid);
            }
            *slot = std::str::from_utf8(r.take(len)?).map_err(|_| Error::MetadataInvalid)?;
        }
        if r.pos != buf.len() {
            return Err(Error::MetadataInvalid);
        }
        // Every check passed; only now do the field allocations happen.
        Ok(Self {
            name: name.to_owned(),
            broker_pid,
            broker_start_ticks,
            child,
            created_unix_ms,
            exec_label: exec_label.to_owned(),
            exec_truncated,
            origins: origin_slices[..origin_count].iter().map(|s| (*s).to_owned()).collect(),
        })
    }
}

/// Allocation-free bounded cursor for [`SessionMeta::decode`].
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::MetadataInvalid)?;
        if end > self.buf.len() {
            return Err(Error::MetadataInvalid);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::classify_probe_errno;
    use nix::errno::Errno;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::sync::atomic::AtomicUsize;

    fn limits() -> Limits {
        Limits::default()
    }

    fn stat_with(mode: u32, uid: libc::uid_t) -> nix::sys::stat::FileStat {
        // SAFETY: libc::stat is plain data; a zeroed value is valid.
        let mut st: nix::sys::stat::FileStat = unsafe { std::mem::zeroed() };
        st.st_mode = mode;
        st.st_uid = uid;
        st
    }

    fn dir_ok(mode: u32, uid: libc::uid_t, euid: libc::uid_t) -> bool {
        stat_is_safe_dir(&stat_with(mode, uid), euid)
    }

    fn file_ok(mode: u32, uid: libc::uid_t, euid: libc::uid_t) -> bool {
        stat_is_safe_private_file(&stat_with(mode, uid), euid)
    }

    fn sock_ok(mode: u32, uid: libc::uid_t, euid: libc::uid_t) -> bool {
        stat_is_safe_socket(&stat_with(mode, uid), euid)
    }

    #[test]
    fn stat_policy_matrix_rejects_wrong_uid_mode_and_type() {
        let euid = sys::effective_uid();
        let other = euid.wrapping_add(1);

        assert!(dir_ok(libc::S_IFDIR | 0o700, euid, euid));
        assert!(!dir_ok(libc::S_IFDIR | 0o700, other, euid));
        for mode in [
            0o750, 0o500, 0o770, 0o707, 0o600, 0o755, 0o777, 0o4700, 0o2700, 0o1700, 0o000,
        ] {
            assert!(
                !dir_ok(libc::S_IFDIR | mode, euid, euid),
                "dir mode {mode:o} must be rejected"
            );
        }
        for typ in [
            libc::S_IFREG,
            libc::S_IFLNK,
            libc::S_IFSOCK,
            libc::S_IFIFO,
            libc::S_IFCHR,
        ] {
            assert!(!dir_ok(typ | 0o700, euid, euid));
        }

        assert!(file_ok(libc::S_IFREG | 0o600, euid, euid));
        assert!(!file_ok(libc::S_IFREG | 0o600, other, euid));
        for mode in [
            0o400, 0o200, 0o640, 0o604, 0o660, 0o606, 0o644, 0o666, 0o700, 0o4600, 0o2600, 0o1600,
        ] {
            assert!(
                !file_ok(libc::S_IFREG | mode, euid, euid),
                "file mode {mode:o} must be rejected"
            );
        }
        for typ in [
            libc::S_IFDIR,
            libc::S_IFLNK,
            libc::S_IFSOCK,
            libc::S_IFIFO,
            libc::S_IFCHR,
        ] {
            assert!(!file_ok(typ | 0o600, euid, euid));
        }

        assert!(sock_ok(libc::S_IFSOCK | 0o600, euid, euid));
        assert!(!sock_ok(libc::S_IFSOCK | 0o600, other, euid));
        for mode in [0o660, 0o666, 0o644, 0o700, 0o000, 0o4600] {
            assert!(
                !sock_ok(libc::S_IFSOCK | mode, euid, euid),
                "socket mode {mode:o} must be rejected"
            );
        }
        for typ in [libc::S_IFREG, libc::S_IFDIR, libc::S_IFLNK, libc::S_IFIFO] {
            assert!(!sock_ok(typ | 0o600, euid, euid));
        }
    }

    #[test]
    fn normal_components_rejects_relative_dot_and_dotdot() {
        assert_eq!(
            normal_components(Path::new("/a/b")).expect("absolute"),
            vec![OsStr::new("a"), OsStr::new("b")]
        );
        assert_eq!(
            normal_components(Path::new("/")).expect("bare root"),
            Vec::<&OsStr>::new()
        );
        assert!(normal_components(Path::new("a/b")).is_none());
        assert!(normal_components(Path::new("")).is_none());
        // Raw-segment rejections Path::components() would normalize away.
        assert!(normal_components(Path::new("/.")).is_none());
        assert!(normal_components(Path::new("/a/../b")).is_none());
        assert!(normal_components(Path::new("/a/./b")).is_none());
        assert!(normal_components(Path::new("relative/..")).is_none());
    }

    #[test]
    fn probe_errno_classification_is_conservative() {
        assert_eq!(
            classify_probe_errno(Errno::EINPROGRESS),
            Some(ProbeOutcome::Pending)
        );
        assert_eq!(
            classify_probe_errno(Errno::EAGAIN),
            Some(ProbeOutcome::Pending)
        );
        assert_eq!(
            classify_probe_errno(Errno::ENOENT),
            Some(ProbeOutcome::Absent)
        );
        assert_eq!(
            classify_probe_errno(Errno::ECONNREFUSED),
            Some(ProbeOutcome::Refused)
        );
        for e in [
            Errno::ECONNRESET,
            Errno::EACCES,
            Errno::ETIMEDOUT,
            Errno::ENOTSOCK,
            Errno::EIO,
        ] {
            assert_eq!(classify_probe_errno(e), None, "{e} must propagate");
        }
    }

    #[test]
    fn discovery_error_classification_propagates_unexpected_io() {
        for skip in [
            Error::MetadataInvalid,
            Error::MetadataTooLarge,
            Error::StatePathUnsafe,
            Error::Io(std::io::Error::from_raw_os_error(libc::ENOENT)),
        ] {
            assert!(discovery_skippable(&skip), "{skip} is entry-local");
        }
        // Typed classification happens upstream (open_failure_error), so
        // raw I/O other than the ENOENT race must always propagate —
        // resource failures especially.
        for propagate in [
            Error::Io(std::io::Error::from_raw_os_error(libc::EMFILE)),
            Error::Io(std::io::Error::from_raw_os_error(libc::ENFILE)),
            Error::Io(std::io::Error::from_raw_os_error(libc::ENOMEM)),
            Error::Io(std::io::Error::from_raw_os_error(libc::EIO)),
            Error::Io(std::io::Error::from_raw_os_error(libc::EACCES)),
            Error::Io(std::io::Error::from_raw_os_error(libc::ENOTDIR)),
            Error::AlreadyExists,
        ] {
            assert!(!discovery_skippable(&propagate), "{propagate} propagates");
        }
    }

    fn sample_meta(name: &str) -> SessionMeta {
        SessionMeta::new(name, &limits(), OsStr::new("/bin/sh"), 1234, 42, 1_000)
            .expect("meta")
            .with_origins(vec!["cli".to_owned(), "env".to_owned()])
            .expect("origins")
            .with_child(ChildMeta::new(4321, 4321, 77).expect("child"))
    }

    #[test]
    fn metadata_round_trips_both_child_arms() {
        let with_child = sample_meta("s1");
        let mut buf = Vec::new();
        with_child.encode_into(&limits(), &mut buf).expect("encode");
        assert_eq!(
            SessionMeta::decode(&buf, &limits()).expect("decode"),
            with_child
        );

        let without = SessionMeta::new("s1", &limits(), OsStr::new("sh"), 1, 0, 0).expect("meta");
        let mut buf2 = Vec::new();
        without.encode_into(&limits(), &mut buf2).expect("encode");
        assert_eq!(
            SessionMeta::decode(&buf2, &limits()).expect("decode"),
            without
        );
    }

    #[test]
    fn metadata_parser_battery_rejects_malformed_records() {
        let meta = sample_meta("s1"); // name_len == 2
        let mut valid = Vec::new();
        meta.encode_into(&limits(), &mut valid).expect("encode");
        let off_pid = MAGIC.len() + 2 + 2; // magic | name_len | "s1"
        let off_child = off_pid + 4 + 8; // broker pid + start ticks

        // Truncation at every prefix length errs and never panics.
        for end in 0..valid.len() {
            assert!(SessionMeta::decode(&valid[..end], &limits()).is_err());
        }

        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 0xFF;
        assert!(matches!(
            SessionMeta::decode(&bad_magic, &limits()),
            Err(Error::MetadataInvalid)
        ));

        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(matches!(
            SessionMeta::decode(&trailing, &limits()),
            Err(Error::MetadataInvalid)
        ));

        let mut bad_utf8 = valid.clone();
        bad_utf8[MAGIC.len() + 2] = 0xFF; // first name byte
        assert!(matches!(
            SessionMeta::decode(&bad_utf8, &limits()),
            Err(Error::MetadataInvalid)
        ));

        let mut bad_name = valid.clone();
        bad_name[MAGIC.len() + 2] = b'-'; // "-1" fails validate_name
        assert!(matches!(
            SessionMeta::decode(&bad_name, &limits()),
            Err(Error::MetadataInvalid)
        ));

        let mut pid_zero = valid.clone();
        pid_zero[off_pid..off_pid + 4].copy_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(
            SessionMeta::decode(&pid_zero, &limits()),
            Err(Error::MetadataInvalid)
        ));

        let mut option_two = valid.clone();
        option_two[off_child] = 2;
        assert!(matches!(
            SessionMeta::decode(&option_two, &limits()),
            Err(Error::MetadataInvalid)
        ));

        let mut huge_pgid = valid.clone();
        huge_pgid[off_child + 1 + 4] = 0xFF; // child pgid > i32::MAX
        assert!(matches!(
            SessionMeta::decode(&huge_pgid, &limits()),
            Err(Error::MetadataInvalid)
        ));

        // Crafted origin overflow: a no-origin record whose count byte
        // claims 5 empty origins parses structurally but must be
        // rejected by the count gate; 65-byte origins by the len gate.
        let no_origins =
            SessionMeta::new("s1", &limits(), OsStr::new("sh"), 1, 0, 0).expect("meta");
        let mut base = Vec::new();
        no_origins.encode_into(&limits(), &mut base).expect("encode");
        let mut five = base.clone();
        *five.last_mut().expect("count byte") = 5;
        five.extend_from_slice(&[0, 0, 0, 0, 0]);
        assert!(matches!(
            SessionMeta::decode(&five, &limits()),
            Err(Error::MetadataInvalid)
        ));
        let mut long_origin = base.clone();
        *long_origin.last_mut().expect("count byte") = 1;
        long_origin.push(65);
        long_origin.extend_from_slice(&[b'a'; 65]);
        assert!(matches!(
            SessionMeta::decode(&long_origin, &limits()),
            Err(Error::MetadataInvalid)
        ));

        // The other option byte: exec_truncated must also be 0 or 1.
        let mut bad_flag = base.clone();
        let flag_idx = bad_flag.len() - 2; // ... | exec_truncated | origin_count
        bad_flag[flag_idx] = 2;
        assert!(matches!(
            SessionMeta::decode(&bad_flag, &limits()),
            Err(Error::MetadataInvalid)
        ));

        assert!(matches!(
            SessionMeta::decode(&[0u8; METADATA_MAX_BYTES + 1], &limits()),
            Err(Error::MetadataTooLarge)
        ));
    }

    #[test]
    fn exec_label_caps_on_char_boundary() {
        let long: String = std::iter::once('a')
            .chain(std::iter::repeat_n('\u{e9}', 200))
            .collect();
        let meta = SessionMeta::new("s1", &limits(), OsStr::new(&long), 1, 0, 0).expect("meta");
        assert!(meta.exec_truncated());
        let label = meta.exec_label();
        assert_eq!(label.len(), 255); // byte 256 splits an 'é'
        assert!(label.is_char_boundary(label.len()));
        assert!(long.starts_with(label));

        let short = SessionMeta::new("s1", &limits(), OsStr::new("sh"), 1, 0, 0).expect("meta");
        assert!(!short.exec_truncated());
        assert_eq!(short.exec_label(), "sh");
    }

    #[test]
    fn constructor_validation_rejects_out_of_range_values() {
        assert!(matches!(
            SessionMeta::new("bad name", &limits(), OsStr::new("sh"), 1, 0, 0),
            Err(Error::NameInvalid)
        ));
        for pid in [0, -1, -50] {
            assert!(matches!(
                SessionMeta::new("s1", &limits(), OsStr::new("sh"), pid, 0, 0),
                Err(Error::MetadataInvalid)
            ));
        }
        let base = SessionMeta::new("s1", &limits(), OsStr::new("sh"), 1, 0, 0).expect("meta");
        assert!(matches!(
            base.clone().with_origins(vec![String::new(); 5]),
            Err(Error::MetadataInvalid)
        ));
        assert!(matches!(
            base.clone().with_origins(vec!["a".repeat(65)]),
            Err(Error::MetadataInvalid)
        ));
        assert!(base.with_origins(vec!["a".repeat(64); 4]).is_ok());
        for (pid, pgid) in [(0, 1), (1, 0), (-1, 1)] {
            assert!(
                matches!(ChildMeta::new(pid, pgid, 0), Err(Error::MetadataInvalid)),
                "({pid}, {pgid}) must be rejected"
            );
        }
        assert!(ChildMeta::new(1, 1, 0).is_ok());
    }

    static FIXTURE: AtomicUsize = AtomicUsize::new(0);

    /// Ownership guard over an exclusively-created fixture base. Held
    /// for the whole test; on drop it best-effort removes only the base
    /// this guard itself created.
    struct Fixture {
        base: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let mut private_dir = std::fs::DirBuilder::new();
            private_dir.mode(0o700);
            for _ in 0..64 {
                let n = FIXTURE.fetch_add(1, Ordering::Relaxed);
                let unique = format!("everpty-session-{}-{}", std::process::id(), n);
                let base = std::env::temp_dir().join(unique);
                match private_dir.create(&base) {
                    Ok(()) => return Self { base },
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("fixture base: {e}"),
                }
            }
            panic!("fixture base: exhausted unique names");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn fixture_root() -> (Fixture, StateRoot) {
        let fx = Fixture::new();
        let candidate = fx.base.join("root");
        let root = resolve_state_root_from(std::slice::from_ref(&candidate)).expect("state root");
        (fx, root)
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[test]
    fn stale_given_refused_validates_before_unlink() {
        let (_fx, root) = fixture_root();
        let limits = limits();

        // Refused + non-socket entry: error, retained (the branch the
        // errno-agnostic public test cannot pin down deterministically).
        let dir = root.session("s1", &limits).expect("dir");
        let locked = dir.lock().expect("lock");
        let planted = locked.dir().socket_path();
        std::fs::write(&planted, b"").expect("plant");
        chmod(&planted, 0o600);
        assert!(matches!(
            locked.recover_stale_given(ProbeOutcome::Refused),
            Err(Error::StatePathUnsafe)
        ));
        assert!(planted.exists(), "non-socket entry must be retained");

        // Uncertain outcomes keep the path without even validating it.
        for outcome in [
            ProbeOutcome::Connected,
            ProbeOutcome::Pending,
            ProbeOutcome::Absent,
        ] {
            assert!(!locked.recover_stale_given(outcome).expect("keep"));
        }
        assert!(planted.exists());

        // Refused + genuine dead 0600 socket: validated unlink.
        let dir2 = root.session("s2", &limits).expect("dir");
        let locked2 = dir2.lock().expect("lock");
        let sock = locked2.dir().socket_path();
        drop(std::os::unix::net::UnixListener::bind(&sock).expect("bind"));
        chmod(&sock, 0o600);
        let removed = locked2.recover_stale_given(ProbeOutcome::Refused);
        assert!(removed.expect("recover"), "dead socket must be removed");
        assert!(!sock.exists(), "dead socket must be unlinked");

        // Refused with no entry at all (vanished before the stat):
        // benign Ok(false), never an error, nothing removed.
        let dir3 = root.session("s3", &limits).expect("dir");
        let locked3 = dir3.lock().expect("lock");
        let benign = locked3.recover_stale_given(ProbeOutcome::Refused);
        assert!(!benign.expect("benign"), "missing entry is not removal");
    }
}
