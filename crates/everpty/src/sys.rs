//! Audited syscall wrappers (plans/m2-plan.md §1).
//!
//! Every OS interface everpty touches goes through this module. Direct
//! `libc` is used only where nix 0.31.3 is insufficient: the
//! TIOCGWINSZ/TIOCSWINSZ/TIOCSCTTY ioctls, `send(MSG_NOSIGNAL)`, the
//! allocation-free `execve` for the post-fork child, and dirfd
//! directory enumeration (`fdopendir`/`readdir` — nix's `dir::Dir`
//! sits behind the unpinned `dir` feature). Each wrapper names the
//! syscall it wraps. Nothing here prints, reads global args, or exits,
//! and nothing allocates from untrusted encoded lengths (directory
//! enumeration and path construction allocate only from OS-provided
//! names).

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;

use nix::fcntl::{Flock, FlockArg, OFlag};
use nix::sys::signal::Signal;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

// ---------------------------------------------------------------------------
// PTY
// ---------------------------------------------------------------------------

/// `openpty(3)` (nix `term` feature). Returns the already-open master and
/// slave fds; the slave is never reopened.
pub fn openpty(rows: u16, cols: u16) -> io::Result<(OwnedFd, OwnedFd)> {
    let winsize = nix::pty::Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let r = nix::pty::openpty(&winsize, None).map_err(io::Error::other)?;
    Ok((r.master, r.slave))
}

/// `ioctl(fd, TIOCGWINSZ)` — libc: nix 0.31 has no winsize helper.
pub fn get_winsize(fd: BorrowedFd<'_>) -> io::Result<(u16, u16)> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `ws` is a valid, fully-sized winsize out-parameter.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((ws.ws_row, ws.ws_col))
}

/// `ioctl(fd, TIOCSWINSZ)` — libc.
pub fn set_winsize(fd: BorrowedFd<'_>, rows: u16, cols: u16) -> io::Result<()> {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `ws` is a valid, fully-sized winsize in-parameter.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `ioctl(fd, TIOCSCTTY, 0)` in the freshly-`setsid`-ed child, on the
/// inherited openpty slave fd — libc. Async-signal-safe.
///
/// # Safety
/// Must be called in the post-fork child on a session leader, before
/// `execve`, on an fd that is safe to use as the controlling terminal.
pub unsafe fn set_controlling_tty(fd: RawFd) -> io::Result<()> {
    let r = libc::ioctl(fd, libc::TIOCSCTTY, 0i32);
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Signals, reaping, process control
// ---------------------------------------------------------------------------

/// `prctl(PR_SET_PDEATHSIG)` followed by the `getppid()` race check
/// (nix `process` feature). Returns `false` when the parent already died
/// (caller — the post-fork child — must exit immediately).
pub fn set_pdeathsig_checked(expected_parent: libc::pid_t) -> bool {
    if nix::sys::prctl::set_pdeathsig(Some(Signal::SIGKILL)).is_err() {
        return false;
    }
    nix::unistd::getppid().as_raw() == expected_parent
}

/// `waitpid(pid, WNOHANG)` (nix). `Ok(None)` while the child still runs.
pub fn waitpid_nohang(pid: libc::pid_t) -> io::Result<Option<(bool, u32)>> {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    let status = waitpid(nix::unistd::Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG))
        .map_err(io::Error::other)?;
    match status {
        WaitStatus::StillAlive => Ok(None),
        WaitStatus::Exited(_, code) => Ok(Some((false, code as u32))),
        WaitStatus::Signaled(_, sig, _) => Ok(Some((true, sig as u32))),
        WaitStatus::Stopped(..)
        | WaitStatus::PtraceEvent(..)
        | WaitStatus::PtraceSyscall(_)
        | WaitStatus::Continued(_) => Ok(None),
    }
}

/// `killpg(2)` (nix) — signals a whole process group.
pub fn killpg(pgid: libc::pid_t, sig: Signal) -> io::Result<()> {
    let pgid = checked_signal_target(pgid)?;
    // nix negates the pid internally: killpg(pgid) -> kill(-pgid, sig)
    nix::sys::signal::killpg(pgid, sig).map_err(io::Error::other)
}

/// `kill(2)` (nix).
pub fn kill(pid: libc::pid_t, sig: Signal) -> io::Result<()> {
    let pid = checked_signal_target(pid)?;
    nix::sys::signal::kill(pid, sig).map_err(io::Error::other)
}

/// Reject Linux's special zero and negative `kill(2)` targets. Everpty only
/// signals a previously recorded, identity-checked PID or process group.
fn checked_signal_target(raw: libc::pid_t) -> io::Result<nix::unistd::Pid> {
    if raw <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "signal target must be a positive PID or PGID",
        ));
    }
    Ok(nix::unistd::Pid::from_raw(raw))
}

/// Errors from [`parse_proc_stat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcStatError {
    NoComm,
    MissingField(&'static str),
    BadNumber(&'static str),
}

impl std::fmt::Display for ProcStatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoComm => write!(f, "proc stat has no comm field"),
            Self::MissingField(n) => write!(f, "proc stat missing field {n}"),
            Self::BadNumber(n) => write!(f, "proc stat field {n} is not a number"),
        }
    }
}
impl std::error::Error for ProcStatError {}

fn parse_u64(b: &[u8], name: &'static str) -> Result<u64, ProcStatError> {
    if b.is_empty() || b.len() > 20 || !b.iter().all(|c| c.is_ascii_digit()) {
        return Err(ProcStatError::BadNumber(name));
    }
    let mut v: u64 = 0;
    for c in b {
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c - b'0')))
            .ok_or(ProcStatError::BadNumber(name))?;
    }
    Ok(v)
}

/// Reads `/proc/<pid>/stat` field layout and returns the parent PID
/// (field 4) and start ticks (field 22). Pure total parser over the read
/// bytes; the comm field may contain spaces and parentheses, so parsing
/// resumes after the LAST `)`.
pub fn parse_proc_stat(bytes: &[u8]) -> Result<(libc::pid_t, u64), ProcStatError> {
    let close = bytes
        .iter()
        .rposition(|&b| b == b')')
        .ok_or(ProcStatError::NoComm)?;
    let rest = &bytes[(close + 1)..];
    let mut fields = rest.split(|&b| b == b' ').filter(|f| !f.is_empty());
    let mut next = || fields.next().ok_or(ProcStatError::MissingField("field"));
    // field 3: state; field 4: ppid; fields 5..=21 (17 fields) precede
    // field 22 (starttime).
    next()?;
    let ppid_str = next()?;
    for _ in 0..17 {
        next()?;
    }
    let start_str = next()?;
    let ppid = parse_u64(ppid_str, "ppid")?;
    let start = parse_u64(start_str, "starttime")?;
    if ppid > i32::MAX as u64 {
        return Err(ProcStatError::BadNumber("ppid"));
    }
    Ok((ppid as libc::pid_t, start))
}

/// `/proc/<pid>/stat` start ticks for a live pid (bounded 512-byte read).
pub fn proc_start_ticks(pid: libc::pid_t) -> io::Result<u64> {
    let path = format!("/proc/{pid}/stat");
    let buf = read_bounded(Path::new(&path), 512)?;
    let (_, start) = parse_proc_stat(&buf).map_err(io::Error::other)?;
    Ok(start)
}

fn read_bounded(path: &Path, cap: usize) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 256];
    loop {
        if buf.len() >= cap {
            break;
        }
        let want = chunk.len().min(cap - buf.len());
        let n = f.read(&mut chunk[..want])?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    if buf.is_empty() {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Socket credentials and no-SIGPIPE writes
// ---------------------------------------------------------------------------

/// `getsockopt(SO_PEERCRED)` (nix `socket`): the connecting peer's uid.
pub fn peer_uid(fd: BorrowedFd<'_>) -> io::Result<libc::uid_t> {
    let creds = getsockopt(&fd, PeerCredentials).map_err(io::Error::other)?;
    Ok(creds.uid())
}

/// Effective uid of this process (nix `user`).
pub fn effective_uid() -> libc::uid_t {
    nix::unistd::geteuid().as_raw() as libc::uid_t
}

/// `send(fd, buf, MSG_NOSIGNAL)` — libc: a stream write that can never
/// raise SIGPIPE; a closed peer surfaces as `EPIPE`.
pub fn send_no_sigpipe(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `buf` is a valid readable buffer of `len` bytes for the
    // duration of the call; `send` does not retain the pointer.
    let n = unsafe {
        libc::send(
            fd.as_raw_fd(),
            buf.as_ptr().cast::<std::ffi::c_void>(),
            buf.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

// ---------------------------------------------------------------------------
// Locking and durable metadata files
// ---------------------------------------------------------------------------

/// A held per-session `flock(2)`. Dropping the guard releases the lock;
/// the broker holds it for its whole lifetime.
pub struct SessionLock(Flock<std::fs::File>);

impl SessionLock {
    /// The guard is held while this everpty process lives.
    pub fn held(&self) -> bool {
        self.0.metadata().is_ok()
    }
}

/// `flock(2)` exclusive + non-blocking (nix `fs`). `Ok(None)` when a
/// live owner already holds the lock.
pub fn acquire_session_lock(file: std::fs::File) -> io::Result<Option<SessionLock>> {
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(g) => Ok(Some(SessionLock(g))),
        Err((f, e)) if e == nix::errno::Errno::EWOULDBLOCK => {
            drop(f);
            Ok(None)
        }
        Err((_, e)) => Err(io::Error::from(e)),
    }
}

const PRIVATE_FILE_MODE: nix::sys::stat::Mode =
    nix::sys::stat::Mode::S_IRUSR.union(nix::sys::stat::Mode::S_IWUSR);

/// `open(2)` with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`,
/// mode 0600 (nix `fs`): exclusive-create for atomic metadata writes.
pub fn create_exclusive_private(path: &Path) -> io::Result<OwnedFd> {
    nix::fcntl::open(
        path,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        PRIVATE_FILE_MODE,
    )
    .map_err(io::Error::other)
}

/// `open(2)` with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC` (nix `fs`).
pub fn open_read_nofollow(path: &Path) -> io::Result<OwnedFd> {
    nix::fcntl::open(
        path,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(io::Error::other)
}

/// `rename(2)` (std) for the atomic publish half of metadata writes.
pub fn rename_atomic(old: &Path, new: &Path) -> io::Result<()> {
    std::fs::rename(old, new)
}

// ---------------------------------------------------------------------------
// Directory-relative session state (session.rs)
// ---------------------------------------------------------------------------
//
// These wrappers preserve the raw errno (`io::Error::from(Errno)`) because
// session.rs dispatches on ENOENT/EEXIST/ELOOP/ENOTDIR to walk, create,
// and classify paths without ever trusting a path string twice.

const PRIVATE_DIR_MODE: nix::sys::stat::Mode = nix::sys::stat::Mode::S_IRWXU;

/// `open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC)` (nix `fs`): the anchor fd
/// for component-by-component directory walks. `/` cannot be a symlink.
pub fn open_root_dir() -> io::Result<OwnedFd> {
    nix::fcntl::open(
        Path::new("/"),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(io::Error::from)
}

/// `openat(2)` with `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` (nix
/// `fs`): opens one child directory, refusing symlinks and non-dirs.
pub fn openat_dir(dirfd: BorrowedFd<'_>, name: &std::ffi::OsStr) -> io::Result<OwnedFd> {
    nix::fcntl::openat(
        dirfd,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(io::Error::from)
}

/// `mkdirat(2)` mode 0700 (nix `fs`).
pub fn mkdirat_private(dirfd: BorrowedFd<'_>, name: &std::ffi::OsStr) -> io::Result<()> {
    nix::sys::stat::mkdirat(dirfd, name, PRIVATE_DIR_MODE).map_err(io::Error::from)
}

/// `openat(2)` with `O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`,
/// mode 0600 (nix `fs`): the lock-file opener. No `O_EXCL` (the lock file
/// is reopened across owner death) and no `O_TRUNC`; `O_NONBLOCK` keeps a
/// FIFO planted at the lock name from blocking the open.
pub fn open_lock_file_at(dirfd: BorrowedFd<'_>, name: &std::ffi::OsStr) -> io::Result<OwnedFd> {
    nix::fcntl::openat(
        dirfd,
        name,
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        PRIVATE_FILE_MODE,
    )
    .map_err(io::Error::from)
}

/// `openat(2)` with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK` (nix
/// `fs`): metadata reader open; `O_NONBLOCK` keeps a FIFO named `meta`
/// from blocking, and the caller fd-stats before reading a byte.
pub fn open_meta_read_at(dirfd: BorrowedFd<'_>, name: &std::ffi::OsStr) -> io::Result<OwnedFd> {
    nix::fcntl::openat(
        dirfd,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(io::Error::from)
}

/// `openat(2)` with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`,
/// mode 0600 (nix `fs`): exclusive-create of a metadata temp file
/// relative to the session directory fd.
pub fn create_exclusive_private_at(
    dirfd: BorrowedFd<'_>,
    name: &std::ffi::OsStr,
) -> io::Result<OwnedFd> {
    nix::fcntl::openat(
        dirfd,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        PRIVATE_FILE_MODE,
    )
    .map_err(io::Error::from)
}

/// `renameat(2)` (nix `fs`) with the same directory fd on both sides:
/// the atomic publish half of a metadata rewrite.
pub fn renameat_within(
    dirfd: BorrowedFd<'_>,
    old: &std::ffi::OsStr,
    new: &std::ffi::OsStr,
) -> io::Result<()> {
    nix::fcntl::renameat(dirfd, old, dirfd, new).map_err(io::Error::from)
}

/// `unlinkat(2)` without `AT_REMOVEDIR` (nix `fs`): removes one
/// non-directory entry relative to the directory fd.
pub fn unlinkat_file(dirfd: BorrowedFd<'_>, name: &std::ffi::OsStr) -> io::Result<()> {
    nix::unistd::unlinkat(dirfd, name, nix::unistd::UnlinkatFlags::NoRemoveDir)
        .map_err(io::Error::from)
}

/// `fstatat(2)` with `AT_SYMLINK_NOFOLLOW` (nix `fs`): stats the entry
/// itself — a symlink stats as a symlink, never its target.
pub fn fstatat_nofollow(
    dirfd: BorrowedFd<'_>,
    name: &std::ffi::OsStr,
) -> io::Result<nix::sys::stat::FileStat> {
    nix::sys::stat::fstatat(dirfd, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)
}

/// `fstat(2)` (nix `fs`) on an already-open fd — the only stat a policy
/// decision may trust, since it cannot race a path swap.
pub fn fstat_fd(fd: BorrowedFd<'_>) -> io::Result<nix::sys::stat::FileStat> {
    nix::sys::stat::fstat(fd).map_err(io::Error::from)
}

/// Directory enumeration on a dirfd — libc `fdopendir(3)`/`readdir(3)`
/// (nix's `dir::Dir` sits behind the unpinned `dir` feature). Opens
/// `.` through the dirfd first so the DIR stream owns an INDEPENDENT
/// open file description — an `F_DUPFD` duplicate would share, and
/// mutate, the caller's directory offset. Returns entry names minus
/// `.`/`..`; never recurses.
pub fn read_dir_at(dirfd: BorrowedFd<'_>) -> io::Result<Vec<std::ffi::OsString>> {
    let snapshot = openat_dir(dirfd, std::ffi::OsStr::new("."))?;
    let raw = snapshot.into_raw_fd();
    // SAFETY: on success the DIR stream takes ownership of `raw`.
    let dir = unsafe { libc::fdopendir(raw) };
    if dir.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so `raw` is still owned here.
        unsafe { libc::close(raw) };
        return Err(e);
    }
    // SAFETY: `dir` stays valid until the closedir below; read_entries
    // only dereferences entry pointers between readdir calls.
    let result = unsafe { read_entries(dir) };
    // SAFETY: closes the stream and its fd exactly once.
    let closed = unsafe { libc::closedir(dir) };
    if closed != 0 && result.is_ok() {
        return Err(io::Error::last_os_error());
    }
    result
}

/// # Safety
/// `dir` must be a valid open DIR stream; the caller closes it.
unsafe fn read_entries(dir: *mut libc::DIR) -> io::Result<Vec<std::ffi::OsString>> {
    use std::os::unix::ffi::OsStrExt;
    let mut names = Vec::new();
    loop {
        // readdir signals end-of-stream and error identically (NULL);
        // only a changed errno distinguishes them.
        nix::errno::Errno::clear();
        let ent = libc::readdir(dir);
        if ent.is_null() {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(0) => Ok(names),
                _ => Err(e),
            };
        }
        let name = std::ffi::CStr::from_ptr((*ent).d_name.as_ptr());
        let bytes = name.to_bytes();
        if bytes != b"." && bytes != b".." {
            names.push(std::ffi::OsStr::from_bytes(bytes).to_os_string());
        }
    }
}

/// What a non-blocking `connect(2)` on a session socket path proved.
/// Only `Refused` is evidence of staleness; `Connected` and `Pending`
/// mean exactly "not proven stale" — a handshake reached something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The connect completed: some process accepted or holds the socket.
    Connected,
    /// `EINPROGRESS`/`EAGAIN`: the connect is still in flight or the
    /// listener backlog is full — uncertain, so treated as not stale.
    Pending,
    /// `ENOENT`: no filesystem entry at the path.
    Absent,
    /// `ECONNREFUSED`: an entry exists but nothing accepts on it.
    Refused,
}

/// Maps a connect errno onto [`ProbeOutcome`]; anything unclassified
/// (`None`) must propagate as an error and never justify an unlink.
pub(crate) fn classify_probe_errno(e: nix::errno::Errno) -> Option<ProbeOutcome> {
    use nix::errno::Errno;
    match e {
        Errno::EINPROGRESS | Errno::EAGAIN => Some(ProbeOutcome::Pending),
        Errno::ENOENT => Some(ProbeOutcome::Absent),
        Errno::ECONNREFUSED => Some(ProbeOutcome::Refused),
        _ => None,
    }
}

/// `socket(2)` + non-blocking `connect(2)` on an `AF_UNIX` stream path
/// (nix `socket`, `SOCK_NONBLOCK|SOCK_CLOEXEC`). The probe fd drops
/// immediately; no byte is ever sent. This raw-path form re-resolves
/// `path` — whenever a directory capability exists, use
/// [`probe_unix_connect_at`] instead so the probe cannot be diverted
/// by a renamed or replaced display path.
pub fn probe_unix_connect(path: &Path) -> io::Result<ProbeOutcome> {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(io::Error::from)?;
    let addr = UnixAddr::new(path).map_err(io::Error::from)?;
    match connect(fd.as_raw_fd(), &addr) {
        Ok(()) => Ok(ProbeOutcome::Connected),
        Err(e) => classify_probe_errno(e).ok_or_else(|| io::Error::from(e)),
    }
}

/// Non-blocking connect probe on `<dirfd>/name` through the
/// `/proc/self/fd` magic link: resolution goes through the OPEN FILE
/// DESCRIPTION, so the probe is bound to the directory's identity even
/// after its display path is renamed or replaced. Whenever a directory
/// capability exists, probes must use this form, never a re-resolvable
/// path. `name` must be exactly one normal component: empty, `.`,
/// `..`, or anything containing `/` is `InvalidInput`.
pub fn probe_unix_connect_at(
    dirfd: BorrowedFd<'_>,
    name: &std::ffi::OsStr,
) -> io::Result<ProbeOutcome> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "probe name must be one normal path component",
        ));
    }
    let via_fd = format!("/proc/self/fd/{}", dirfd.as_raw_fd());
    probe_unix_connect(&Path::new(&via_fd).join(name))
}

// ---------------------------------------------------------------------------
// Post-fork child helpers (async-signal-safe only)
// ---------------------------------------------------------------------------

/// Prepared exec payload: all allocation happens BEFORE fork. The child
/// only touches the prebuilt pointers.
pub struct ExecPlan {
    path: CString,
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
    _keep: Vec<CString>,
}

impl ExecPlan {
    /// Builds path/argv/envp CStrings and null-terminated pointer arrays.
    /// Fails (before any fork) if any element contains a NUL byte.
    pub fn new(
        path: &std::ffi::OsStr,
        argv: &[std::ffi::OsString],
        envp: &[std::ffi::OsString],
    ) -> io::Result<Self> {
        let mut keep = Vec::with_capacity(2 + argv.len() + envp.len());
        let path_c = cstring(path)?;
        keep.push(path_c.clone());
        let mut argv_p = Vec::with_capacity(argv.len() + 1);
        for a in argv {
            let c = cstring(a)?;
            argv_p.push(c.as_ptr());
            keep.push(c);
        }
        argv_p.push(std::ptr::null());
        let mut envp_p = Vec::with_capacity(envp.len() + 1);
        for e in envp {
            let c = cstring(e)?;
            envp_p.push(c.as_ptr());
            keep.push(c);
        }
        envp_p.push(std::ptr::null());
        Ok(Self {
            path: path_c,
            argv: argv_p,
            envp: envp_p,
            _keep: keep,
        })
    }

    /// `setsid(2)` in the child — nix unistd (thin, signal-safe).
    pub fn child_setsid() -> io::Result<()> {
        nix::unistd::setsid().map(|_| ()).map_err(io::Error::other)
    }

    /// `dup2(2)` in the child — libc, async-signal-safe.
    ///
    /// # Safety
    /// Post-fork child context only.
    pub unsafe fn child_dup2(old: RawFd, new: RawFd) -> io::Result<()> {
        if libc::dup2(old, new) < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `close(2)` in the child — libc, async-signal-safe.
    ///
    /// # Safety
    /// Post-fork child context only.
    pub unsafe fn child_close(fd: RawFd) {
        libc::close(fd);
    }

    /// `execve(2)` with the prebuilt pointer arrays — libc, allocation
    /// free. Returns only on failure.
    ///
    /// # Safety
    /// Post-fork child context only; on success the process is replaced.
    pub unsafe fn execve(&self) -> io::Error {
        let _r = libc::execve(
            self.path.as_ptr(),
            self.argv.as_ptr().cast::<*const libc::c_char>(),
            self.envp.as_ptr().cast::<*const libc::c_char>(),
        );
        io::Error::last_os_error()
    }
}

fn cstring(s: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(s.as_encoded_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL byte in path, argument, or environment entry",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn winsize_round_trip_through_openpty() {
        let (master, _slave) = openpty(24, 80).expect("openpty");
        assert_eq!(get_winsize(master.as_fd()).expect("get"), (24, 80));
        set_winsize(master.as_fd(), 30, 100).expect("set");
        assert_eq!(get_winsize(master.as_fd()).expect("get"), (30, 100));
    }

    #[test]
    fn proc_stat_parses_and_is_total() {
        let mut line: Vec<u8> = b"1234 (some (name)) S 1 ".to_vec();
        for i in 0..17 {
            let _ = i;
            line.extend_from_slice(b"42 ");
        }
        line.extend_from_slice(b"987654 0 0 0 0 0 0 0 17 2 0 0 0 0 0\n");
        let (ppid, start) = parse_proc_stat(&line).expect("parse");
        assert_eq!(ppid, 1);
        assert_eq!(start, 987654);
        // Truncations at every length must never panic.
        for end in 0..line.len() {
            let _ = parse_proc_stat(&line[..end]);
        }
        assert!(parse_proc_stat(b"no comm here").is_err());
        assert!(parse_proc_stat(b"1 (x) S notanumber").is_err());
        assert!(parse_proc_stat(b"").is_err());
    }

    #[test]
    fn proc_start_ticks_of_self_is_stable() {
        let a = proc_start_ticks(std::process::id() as libc::pid_t).expect("self stat");
        let b = proc_start_ticks(std::process::id() as libc::pid_t).expect("self stat");
        assert_eq!(a, b);
        assert!(proc_start_ticks(-1).is_err());
    }

    #[test]
    fn flock_is_exclusive() {
        let dir = std::env::temp_dir().join(format!("everpty-sys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let p = dir.join("lock");
        let f1 = std::fs::File::create(&p).expect("create");
        let guard = acquire_session_lock(f1).expect("flock1").expect("acquired");
        let f2 = std::fs::File::open(&p).expect("open");
        assert!(acquire_session_lock(f2).expect("flock2").is_none());
        drop(guard);
        let f3 = std::fs::OpenOptions::new()
            .read(true)
            .open(&p)
            .expect("reopen");
        assert!(acquire_session_lock(f3).expect("flock3").is_some());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn exclusive_create_refuses_second_and_nofollow() {
        let dir = std::env::temp_dir().join(format!("everpty-sys-x-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let p = dir.join("meta.tmp");
        let _ = std::fs::remove_file(&p);
        let _f = create_exclusive_private(&p).expect("create");
        assert!(create_exclusive_private(&p).is_err());
        let link = dir.join("meta.link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&p, &link).expect("symlink");
        assert!(open_read_nofollow(&link).is_err());
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&link);
    }

    #[test]
    fn send_no_sigpipe_surfaces_epipe() {
        use std::os::unix::net::UnixStream;
        let (a, b) = UnixStream::pair().expect("pair");
        drop(b);
        a.set_nonblocking(true).expect("nonblock");
        // Peer closed: eventually EPIPE; never a SIGPIPE death.
        for _ in 0..200 {
            match send_no_sigpipe(a.as_fd(), b"x") {
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    assert_eq!(e.raw_os_error(), Some(libc::EPIPE));
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn peer_uid_sees_self() {
        use std::os::unix::net::UnixStream;
        let (a, b) = UnixStream::pair().expect("pair");
        assert_eq!(peer_uid(a.as_fd()).expect("uid"), effective_uid());
        drop((a, b));
    }

    #[test]
    fn exec_plan_rejects_nul_and_builds_arrays() {
        use std::ffi::OsString;
        let plan = ExecPlan::new(
            "/bin/sh".as_ref(),
            &[OsString::from("/bin/sh"), OsString::from("-c")],
            &[OsString::from("A=1")],
        )
        .expect("plan");
        assert_eq!(plan.argv.len(), 3); // 2 args + null
        assert_eq!(plan.envp.len(), 2);
        assert!(plan.argv.last().map_or(true, |p| p.is_null()));
        assert!(
            ExecPlan::new("a\0b".as_ref(), &[], &[]).is_err(),
            "NUL must fail before fork"
        );
    }

    #[test]
    fn signal_targets_are_validated_without_sending_signals() {
        for target in [0, -1, -2] {
            assert_eq!(
                checked_signal_target(target)
                    .expect_err("special target must be rejected")
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(checked_signal_target(1).expect("positive PID").as_raw(), 1);

        // Type-check both public wrappers without invoking either syscall.
        let _: fn(libc::pid_t, Signal) -> io::Result<()> = kill;
        let _: fn(libc::pid_t, Signal) -> io::Result<()> = killpg;
    }

    #[test]
    fn waitpid_nohang_on_non_child_is_error() {
        // Waiting on a non-child fails with ECHILD: never reaps what we
        // did not spawn.
        assert!(waitpid_nohang(1).is_err());
    }

    #[test]
    fn rename_atomic_publishes() {
        let dir = std::env::temp_dir().join(format!("everpty-sys-r-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let tmp = dir.join("t.tmp");
        let fin = dir.join("t.fin");
        std::fs::write(&tmp, b"hello").expect("write");
        rename_atomic(&tmp, &fin).expect("rename");
        assert_eq!(std::fs::read(&fin).expect("read"), b"hello");
        let _ = std::fs::remove_file(&fin);
    }
}
