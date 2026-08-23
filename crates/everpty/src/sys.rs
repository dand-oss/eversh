//! Audited syscall wrappers (plans/m2-plan.md §1).
//!
//! Every OS interface everpty touches goes through this module. Direct
//! `libc` is used only where nix 0.31.3 is insufficient: the
//! TIOCGWINSZ/TIOCSWINSZ/TIOCSCTTY ioctls, `send(MSG_NOSIGNAL)`, dirfd
//! directory enumeration (`fdopendir`/`readdir` — nix's `dir::Dir`
//! sits behind the unpinned `dir` feature), and the post-fork child
//! sequence (signal reset, `dup2`, `close`, `write`, `_exit`, and the
//! allocation-free `execve` over prebuilt pointer arrays). Each wrapper
//! names the syscall it wraps. Nothing here prints, reads global args,
//! or exits — except the child-only `child_exit`, which the post-fork
//! child MUST use — and nothing allocates from untrusted encoded
//! lengths (directory enumeration and path construction allocate only
//! from OS-provided names).

use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;

use nix::fcntl::{Flock, FlockArg, OFlag};
use nix::sys::signal::Signal;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

// Re-exported so the broker names poll types through this module only.
pub use nix::poll::{PollFd, PollFlags};

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

// ---------------------------------------------------------------------------
// Signals, reaping, process control
// ---------------------------------------------------------------------------
//
// These wrappers preserve the raw errno (`io::Error::from(Errno)`) so
// callers can dispatch on `ESRCH`/`ECHILD` without guessing.

/// `waitpid(pid, WNOHANG)` (nix). `Ok(None)` while the child still
/// runs. Rejects every non-positive PID before waitpid runs —
/// `waitpid(0)`/`waitpid(-n)` are wait-any/group forms that could reap
/// a process this broker never spawned.
pub fn waitpid_nohang(pid: libc::pid_t) -> io::Result<Option<(bool, u32)>> {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    let pid = checked_signal_target(pid)?;
    let status = waitpid(pid, Some(WaitPidFlag::WNOHANG)).map_err(io::Error::from)?;
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

/// Blocking `waitpid` on one recorded child (nix). Retries `EINTR`
/// and rejects every non-positive PID first, exactly like
/// [`waitpid_nohang`]. Returns `(signaled, code)`.
pub fn waitpid_blocking(pid: libc::pid_t) -> io::Result<(bool, u32)> {
    use nix::sys::wait::{waitpid, WaitStatus};
    let pid = checked_signal_target(pid)?;
    loop {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(_, code)) => return Ok((false, code as u32)),
            Ok(WaitStatus::Signaled(_, sig, _)) => return Ok((true, sig as u32)),
            Ok(_) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(io::Error::from(e)),
        }
    }
}

/// `getpgid(2)` (nix) of one positive PID — the group-identity
/// re-check before any group signal. `ESRCH` means the process is
/// gone.
pub fn getpgid_of(pid: libc::pid_t) -> io::Result<libc::pid_t> {
    let pid = checked_signal_target(pid)?;
    nix::unistd::getpgid(Some(pid))
        .map(|p| p.as_raw())
        .map_err(io::Error::from)
}

/// Non-consuming exit observation: `waitid(P_PID,
/// WEXITED|WNOHANG|WNOWAIT)` (nix). Returns the child's exact
/// `(signaled, code)` once it has exited while leaving it UNREAPED,
/// so its PID/PGID/start-ticks identity anchor stays valid until the
/// one real reap; `Ok(None)` while it still runs. Rejects every
/// non-positive PID like the other wait wrappers.
pub fn observe_exit_nowait(pid: libc::pid_t) -> io::Result<Option<(bool, u32)>> {
    use nix::sys::wait::{waitid, Id, WaitPidFlag, WaitStatus};
    let pid = checked_signal_target(pid)?;
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    match waitid(Id::Pid(pid), flags) {
        Ok(WaitStatus::StillAlive) => Ok(None),
        Ok(WaitStatus::Exited(_, code)) => Ok(Some((false, code as u32))),
        Ok(WaitStatus::Signaled(_, sig, _)) => Ok(Some((true, sig as u32))),
        // WEXITED-only waits report no stop/trace states; anything
        // unexpected is treated as still-running, never as an exit.
        Ok(_) => Ok(None),
        Err(e) => Err(io::Error::from(e)),
    }
}

/// `killpg(2)` (nix) — signals a whole process group.
pub fn killpg(pgid: libc::pid_t, sig: Signal) -> io::Result<()> {
    let pgid = checked_signal_target(pgid)?;
    // nix negates the pid internally: killpg(pgid) -> kill(-pgid, sig)
    nix::sys::signal::killpg(pgid, sig).map_err(io::Error::from)
}

/// `kill(2)` (nix).
pub fn kill(pid: libc::pid_t, sig: Signal) -> io::Result<()> {
    let pid = checked_signal_target(pid)?;
    nix::sys::signal::kill(pid, sig).map_err(io::Error::from)
}

/// Reject Linux's special zero and negative PID/PGID targets. Everpty
/// only signals, waits on, or inspects a previously recorded,
/// identity-checked PID or process group.
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
// Poll, identity-bound listener sockets, monotonic clock
// ---------------------------------------------------------------------------

/// `poll(2)` (nix `poll`). `None` waits indefinitely; `Some(ms)` is
/// CLAMPED to `i32::MAX` milliseconds (the syscall's own limit — a
/// caller asking for more gets the maximum legal wait, never an
/// error). Returns the number of entries with nonzero revents.
pub fn poll(fds: &mut [PollFd<'_>], timeout_ms: Option<u32>) -> io::Result<usize> {
    use nix::poll::{poll, PollTimeout};
    let timeout = match timeout_ms {
        None => PollTimeout::NONE,
        Some(ms) => PollTimeout::try_from(ms.min(i32::MAX as u32))
            .expect("clamped to the i32::MAX legal range"),
    };
    poll(fds, timeout)
        .map(|n| n as usize)
        .map_err(io::Error::from)
}

/// `listen(2)` (nix `socket`). The backlog is clamped by the kernel.
pub fn listen(fd: BorrowedFd<'_>, backlog: i32) -> io::Result<()> {
    use nix::sys::socket::{listen, Backlog};
    let backlog = Backlog::new(backlog).map_err(io::Error::other)?;
    listen(&fd, backlog).map_err(io::Error::from)
}

/// `accept4(SOCK_NONBLOCK|SOCK_CLOEXEC)` (nix `socket`). `Ok(None)`
/// means the backlog is empty (`EAGAIN`/`EWOULDBLOCK`); the returned
/// descriptor is nonblocking and close-on-exec like the listener.
pub fn accept_nonblock(listener: BorrowedFd<'_>) -> io::Result<Option<OwnedFd>> {
    use nix::sys::socket::{accept4, SockFlag};
    use std::os::fd::FromRawFd;
    match accept4(
        listener.as_raw_fd(),
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
    ) {
        Ok(raw) => Ok(Some(unsafe { OwnedFd::from_raw_fd(raw) })),
        Err(e) if e == nix::errno::Errno::EAGAIN || e == nix::errno::Errno::EWOULDBLOCK => {
            Ok(None)
        }
        Err(e) => Err(io::Error::from(e)),
    }
}

/// `recv(2)` with no flags (nix `socket`), retrying `EINTR`. `Ok(None)`
/// is `EAGAIN` (nothing readable now); `Ok(Some(0))` is EOF (peer shut
/// down); any bytes are data received this call.
pub fn recv(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Option<usize>> {
    use nix::sys::socket::{recv, MsgFlags};
    loop {
        match recv(fd.as_raw_fd(), buf, MsgFlags::empty()) {
            Ok(n) => return Ok(Some(n)),
            Err(e) if e == nix::errno::Errno::EINTR => continue,
            Err(e) if e == nix::errno::Errno::EAGAIN || e == nix::errno::Errno::EWOULDBLOCK => {
                return Ok(None)
            }
            Err(e) => return Err(io::Error::from(e)),
        }
    }
}

/// One normal directory component: non-empty, not `.`/`..`, no `/`.
fn normal_entry_name(name: &std::ffi::OsStr) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let b = name.as_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket entry name must be one normal path component",
        ));
    }
    Ok(())
}

/// The no-follow dirfd-relative identity of a directory entry: the
/// (device, inode, type, uid) tuple that pins any cleanup to the exact
/// object this call created, never a replaced one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryIdentity {
    pub dev: u64,
    pub ino: u64,
    pub kind: u32,
    pub uid: libc::uid_t,
}

impl EntryIdentity {
    /// Captures the identity from a no-follow stat.
    pub fn from_stat(st: &nix::sys::stat::FileStat) -> Self {
        Self {
            dev: st.st_dev,
            ino: st.st_ino,
            kind: st.st_mode & libc::S_IFMT,
            uid: st.st_uid,
        }
    }

    /// The pure cleanup gate: the captured identity still names an
    /// euid-owned Unix socket entry.
    pub fn still_is_socket_of(&self, euid: libc::uid_t) -> bool {
        self.uid == euid && self.kind == libc::S_IFSOCK
    }
}

/// The pure failure-cleanup decision: after any post-identity failure
/// (chmod, verify, listen), the just-created entry may be unlinked
/// ONLY when a fresh no-follow stat still returns the EXACT captured
/// identity. A vanished entry (`None`), a replaced one, or a missing
/// capture never justifies an unlink.
pub(crate) fn cleanup_should_unlink(
    captured: &EntryIdentity,
    fresh: Option<EntryIdentity>,
) -> bool {
    fresh == Some(*captured)
}

/// `socket(2)` + `bind(2)` + `fstatat(AT_SYMLINK_NOFOLLOW)` +
/// `fchmodat(AT_SYMLINK_NOFOLLOW)` + `listen(2)` (nix): ONE
/// identity-aware operation that binds an `AF_UNIX` `SOCK_STREAM`
/// `SOCK_NONBLOCK|SOCK_CLOEXEC` listener at `<dirfd>/name` THROUGH THE
/// DIRECTORY CAPABILITY and returns it already listening. The bind
/// path is built from RAW OsStr bytes as `/proc/self/fd/<dirfd>/<name>`
/// (renaming the display path cannot divert it; non-UTF-8 names
/// survive intact). NO process-global umask is ever touched. After the
/// bind the entry's no-follow identity (device/inode/type/uid) is
/// captured — if that capture itself fails, the error is returned
/// WITHOUT any unlink. The mode is then set to EXACTLY 0600 with
/// no-follow `fchmodat`, a re-stat must show the SAME identity, euid
/// ownership, and exactly 0600, and the listener is started. ANY
/// failure after identity capture (chmod, verify, listen) attempts the
/// identity-gated cleanup — a fresh no-follow stat that still matches
/// the captured identity unlinks the entry; a replaced or unverified
/// entry is retained — and the ORIGINAL failure is returned. If safe
/// no-follow chmod is unsupported the call fails: there is no
/// path-following chmod and no umask fallback.
pub fn bind_unix_listener_at(
    dirfd: BorrowedFd<'_>,
    name: &std::ffi::OsStr,
    backlog: i32,
) -> io::Result<OwnedFd> {
    use nix::sys::socket::{bind, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    use nix::sys::stat::{fchmodat, FchmodatFlags, Mode};
    normal_entry_name(name)?;
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(io::Error::from)?;
    // Raw-byte /proc path: no to_string_lossy, non-UTF-8 intact.
    let via_fd = {
        let mut p = std::ffi::OsString::from(format!("/proc/self/fd/{}/", dirfd.as_raw_fd()));
        p.push(name);
        std::path::PathBuf::from(p)
    };
    let addr = UnixAddr::new(&via_fd).map_err(io::Error::from)?;
    bind(fd.as_raw_fd(), &addr).map_err(io::Error::from)?;
    // Capture the created entry's identity before touching anything.
    // A failed capture returns the error WITHOUT a blind unlink.
    let created = match fstatat_nofollow(dirfd, name) {
        Ok(st) => EntryIdentity::from_stat(&st),
        Err(e) => return Err(e),
    };
    let euid = effective_uid();
    if !created.still_is_socket_of(euid) {
        // Wrong shape/owner: unverified objects are never unlinked.
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "bound entry is not an euid-owned socket",
        ));
    }
    // The identity-gated cleanup helper: fresh no-follow stat must
    // still match the captured identity or the entry is retained.
    let cleanup_if_ours = || {
        let fresh = fstatat_nofollow(dirfd, name)
            .ok()
            .map(|st| EntryIdentity::from_stat(&st));
        if cleanup_should_unlink(&created, fresh) {
            let _ = unlinkat_file(dirfd, name);
        }
    };
    let mode_0600 = Mode::S_IRUSR.union(Mode::S_IWUSR);
    if let Err(e) = fchmodat(dirfd, name, mode_0600, FchmodatFlags::NoFollowSymlink) {
        let original = io::Error::from(e);
        cleanup_if_ours();
        return Err(original);
    }
    match fstatat_nofollow(dirfd, name) {
        // A failed verification stat propagates its ORIGINAL error.
        Err(e) => {
            cleanup_if_ours();
            return Err(e);
        }
        Ok(st) => {
            let verified = EntryIdentity::from_stat(&st) == created
                && st.st_uid == euid
                && (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK
                && (st.st_mode & 0o7777) == 0o600;
            if !verified {
                // A logical identity/mode mismatch stays PermissionDenied.
                cleanup_if_ours();
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "socket entry failed the identity+exact-0600 verification",
                ));
            }
        }
    }
    if let Err(e) = listen(fd.as_fd(), backlog) {
        let original = io::Error::from(e);
        cleanup_if_ours();
        return Err(original);
    }
    Ok(fd)
}

/// `clock_gettime(CLOCK_MONOTONIC)` — libc: the production monotonic
/// millisecond source behind the broker's injected `Clock`. Failure is
/// EXPLICIT (`io::Result`): a release build never substitutes a zero
/// timestamp. The millisecond conversion saturates at `u64::MAX`.
pub fn clock_monotonic_ms() -> io::Result<u64> {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `ts` is a valid, fully-sized out-parameter.
    let r = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    let ms = (ts.tv_sec as u64)
        .checked_mul(1000)
        .and_then(|m| m.checked_add(ts.tv_nsec as u64 / 1_000_000))
        .unwrap_or(u64::MAX);
    Ok(ms)
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
// Process creation and stdio plumbing
// ---------------------------------------------------------------------------

/// Which side of [`fork`] this process is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forked {
    /// The parent; carries the child's PID (always positive).
    Parent(libc::pid_t),
    /// The child. Only the async-signal-safe `child_*` helpers,
    /// [`set_controlling_tty`], and [`ExecPlan::execve`] may run here.
    Child,
}

/// `fork(2)` (nix). The broker forks exactly once per session child.
///
/// # Safety
/// The caller's child branch must restrict itself to async-signal-safe
/// operations — no allocation, locking, or unwinding — until `execve`
/// or `_exit`.
pub unsafe fn fork() -> io::Result<Forked> {
    match nix::unistd::fork() {
        Ok(nix::unistd::ForkResult::Parent { child }) => Ok(Forked::Parent(child.as_raw())),
        Ok(nix::unistd::ForkResult::Child) => Ok(Forked::Child),
        Err(e) => Err(io::Error::from(e)),
    }
}

/// `pipe2(O_CLOEXEC)` (nix): the exec-error pipe. Returns
/// `(read, write)`; both ends close on any exec, so a successful
/// `execve` turns the parent's blocking read into a clean EOF.
pub fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    nix::unistd::pipe2(OFlag::O_CLOEXEC).map_err(io::Error::from)
}

/// `socketpair(AF_UNIX, SOCK_STREAM, SOCK_CLOEXEC)` (nix `socket`):
/// the spawn's ready/go synchronization channel. One bidirectional
/// pair carries both barrier bytes, and because it is a SOCKET the
/// parent's release write can go through [`send_no_sigpipe`] — no
/// parent-side synchronization write is ever able to raise `SIGPIPE`.
/// Both ends close on exec.
pub fn socketpair_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
    let pair = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    );
    pair.map_err(io::Error::from)
}

/// Blocking `read(2)` of exactly one byte (nix) — the parent half of
/// the spawn barrier. `Ok(false)` means EOF: the peer end closed
/// without sending. Retries `EINTR`.
pub fn read_byte_blocking(fd: BorrowedFd<'_>) -> io::Result<bool> {
    let mut byte = [0u8; 1];
    loop {
        match nix::unistd::read(fd, &mut byte) {
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(true),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(io::Error::from(e)),
        }
    }
}

/// Blocking `read(2)` of exactly `buf.len()` bytes (nix), retrying
/// `EINTR` and short reads. EOF before the buffer fills is
/// `UnexpectedEof` — the record was truncated, never half-accepted.
pub fn read_exact_blocking(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        match nix::unistd::read(fd, &mut buf[done..]) {
            Ok(0) => {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            Ok(n) => done += n,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(io::Error::from(e)),
        }
    }
    Ok(())
}

/// Re-homes a descriptor above the stdio slots with
/// `fcntl(F_DUPFD_CLOEXEC, 3)` (nix) when it landed on 0..=2 —
/// possible when the broker inherited closed stdio. Working
/// descriptors must never collide with the child's stdio remap
/// targets. The raised copy is CLOEXEC; child-side uses survive
/// because `dup2` clears CLOEXEC on its target descriptor.
pub fn ensure_fd_above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;
    if fd.as_raw_fd() > 2 {
        return Ok(fd);
    }
    let arg = nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(3);
    let raw = nix::fcntl::fcntl(&fd, arg).map_err(io::Error::from)?;
    // SAFETY: F_DUPFD_CLOEXEC returned a fresh descriptor we own; the
    // original closes when `fd` drops here.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// `fcntl(F_GETFL)` + `fcntl(F_SETFL, +O_NONBLOCK)` (nix) — the PTY
/// master must never block the broker loop.
pub fn set_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL).map_err(io::Error::from)?;
    let flags = OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK;
    nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFL(flags))
        .map(|_| ())
        .map_err(io::Error::from)
}

// ---------------------------------------------------------------------------
// Post-fork child helpers (async-signal-safe only)
// ---------------------------------------------------------------------------
//
// Everything below the `ExecPlan` constructor runs in the post-fork
// child: raw libc, no allocation, no formatting, no locking, no
// unwinding. Failures surface as raw errno values (`i32`) so the child
// can report them through the exec-error pipe without constructing
// rich errors.

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

    /// `execve(2)` with the prebuilt pointer arrays — libc, allocation
    /// free. Returns the raw errno; on success the process image is
    /// replaced and this never returns.
    ///
    /// # Safety
    /// Post-fork child context only.
    pub unsafe fn execve(&self) -> i32 {
        let _r = libc::execve(
            self.path.as_ptr(),
            self.argv.as_ptr().cast::<*const libc::c_char>(),
            self.envp.as_ptr().cast::<*const libc::c_char>(),
        );
        last_errno()
    }
}

/// Raw errno of the last failed call — a direct read of the thread's
/// errno location (nix `Errno::last_raw`), async-signal-safe: no
/// `std::io::Error` is ever constructed on a post-fork path.
fn last_errno() -> i32 {
    nix::errno::Errno::last_raw()
}

/// `prctl(PR_SET_PDEATHSIG, SIGKILL)` followed by the `getppid()`
/// race check — raw libc, raw errno, allocation-free. Rejects every
/// non-positive expected-parent PID (`EINVAL`) before prctl runs.
/// `Ok(false)` means the parent already died and the child must exit
/// immediately.
///
/// # Safety
/// Post-fork child context only. (The rejection path performs no
/// syscall; unit tests exercise only that path.)
pub unsafe fn child_set_pdeathsig_checked(expected_parent: libc::pid_t) -> Result<bool, i32> {
    if expected_parent <= 0 {
        return Err(libc::EINVAL);
    }
    let deathsig = libc::SIGKILL as libc::c_ulong;
    if libc::prctl(libc::PR_SET_PDEATHSIG, deathsig, 0, 0, 0) != 0 {
        return Err(last_errno());
    }
    Ok(libc::getppid() == expected_parent)
}

/// The dispositions the child resets to `SIG_DFL` before exec. An
/// IGNORED disposition survives `execve` (handled ones revert on
/// their own), so every signal the broker ignores or blocks for its
/// signalfd — plus the terminal job-control set — is reset
/// explicitly.
const CHILD_RESET_SIGNALS: [libc::c_int; 9] = [
    libc::SIGCHLD,
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGHUP,
    libc::SIGPIPE,
    libc::SIGTSTP,
    libc::SIGTTIN,
    libc::SIGTTOU,
];

/// Restores the child's signal state: empties the signal mask
/// (`sigprocmask(SIG_SETMASK)`) and resets every
/// [`CHILD_RESET_SIGNALS`] disposition to `SIG_DFL`. Libc,
/// async-signal-safe.
///
/// # Safety
/// Post-fork child context only.
pub unsafe fn child_reset_signals() -> Result<(), i32> {
    let mut set: libc::sigset_t = std::mem::zeroed();
    if libc::sigemptyset(&mut set) != 0 {
        return Err(last_errno());
    }
    if libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut()) != 0 {
        return Err(last_errno());
    }
    for sig in CHILD_RESET_SIGNALS {
        if libc::signal(sig, libc::SIG_DFL) == libc::SIG_ERR {
            return Err(last_errno());
        }
    }
    Ok(())
}

/// `setsid(2)` in the child — libc, async-signal-safe.
///
/// # Safety
/// Post-fork child context only.
pub unsafe fn child_setsid() -> Result<(), i32> {
    if libc::setsid() < 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `ioctl(fd, TIOCSCTTY, 0)` in the freshly-`setsid`-ed child, on the
/// inherited openpty slave fd — libc, async-signal-safe.
///
/// # Safety
/// Post-fork child context only, on a session leader, before `execve`,
/// on an fd that is safe to use as the controlling terminal.
pub unsafe fn set_controlling_tty(fd: RawFd) -> Result<(), i32> {
    if libc::ioctl(fd, libc::TIOCSCTTY, 0i32) != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `dup2(2)` in the child — libc, async-signal-safe. Retries `EINTR`.
///
/// # Safety
/// Post-fork child context only.
pub unsafe fn child_dup2(old: RawFd, new: RawFd) -> Result<(), i32> {
    loop {
        if libc::dup2(old, new) >= 0 {
            return Ok(());
        }
        let errno = last_errno();
        if errno != libc::EINTR {
            return Err(errno);
        }
    }
}

/// `close(2)` in the child — libc, async-signal-safe. Close errors are
/// deliberately ignored: the descriptor is gone either way and the
/// child is about to exec or exit.
///
/// # Safety
/// Post-fork child context only.
pub unsafe fn child_close(fd: RawFd) {
    libc::close(fd);
}

/// `write(2)` of one complete fixed-size record in the child — libc,
/// async-signal-safe. Retries `EINTR` and short writes.
///
/// # Safety
/// Post-fork child context only.
pub unsafe fn child_write_exact(fd: RawFd, buf: &[u8]) -> Result<(), i32> {
    let mut done = 0usize;
    while done < buf.len() {
        let n = libc::write(
            fd,
            buf[done..].as_ptr().cast::<libc::c_void>(),
            buf.len() - done,
        );
        if n < 0 {
            let errno = last_errno();
            if errno == libc::EINTR {
                continue;
            }
            return Err(errno);
        }
        if n == 0 {
            return Err(libc::EIO);
        }
        done += n as usize;
    }
    Ok(())
}

/// Blocking `read(2)` of one byte in the child — libc,
/// async-signal-safe. `Ok(true)` = a byte arrived, `Ok(false)` = EOF
/// (the parent released or abandoned the pipe). Retries `EINTR`.
///
/// # Safety
/// Post-fork child context only.
pub unsafe fn child_read_byte(fd: RawFd) -> Result<bool, i32> {
    let mut byte = 0u8;
    loop {
        let ptr = (&mut byte as *mut u8).cast::<libc::c_void>();
        let n = libc::read(fd, ptr, 1);
        if n == 1 {
            return Ok(true);
        }
        if n == 0 {
            return Ok(false);
        }
        let errno = last_errno();
        if errno != libc::EINTR {
            return Err(errno);
        }
    }
}

/// `_exit(2)` — libc: ends the child without unwinding, atexit
/// handlers, or stdio flushing. The libraries-never-exit invariant
/// binds the broker process; the post-fork child MUST exit this way on
/// any pre-exec failure.
///
/// # Safety
/// Post-fork child context only.
pub unsafe fn child_exit(code: i32) -> ! {
    libc::_exit(code)
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
        // Peer closed: EPIPE must actually be OBSERVED (never a
        // SIGPIPE death, and never a silent pass without the errno).
        let mut saw_epipe = false;
        for _ in 0..1000 {
            match send_no_sigpipe(a.as_fd(), b"x") {
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(e) => {
                    assert_eq!(e.raw_os_error(), Some(libc::EPIPE));
                    saw_epipe = true;
                    break;
                }
            }
        }
        assert!(saw_epipe, "EPIPE was never observed");
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
            // The wait, group-inspect, and PDEATHSIG guards reject the
            // same special targets BEFORE any syscall runs. These are
            // rejection paths only: the PDEATHSIG helper is never
            // called with a positive PID in any test harness, so prctl
            // never runs here.
            assert_eq!(
                waitpid_nohang(target).expect_err("waitpid guard").kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                waitpid_blocking(target).expect_err("waitpid guard").kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                getpgid_of(target).expect_err("getpgid guard").kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                observe_exit_nowait(target).expect_err("waitid guard").kind(),
                io::ErrorKind::InvalidInput
            );
            // SAFETY: the rejection path performs no syscall; prctl is
            // never reached with a non-positive expected parent.
            assert_eq!(
                unsafe { child_set_pdeathsig_checked(target) },
                Err(libc::EINVAL)
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
        // did not spawn. The positive PID passes the guard, so the
        // failure comes from waitpid itself.
        let e = waitpid_nohang(1).expect_err("non-child");
        assert_ne!(e.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(e.raw_os_error(), Some(libc::ECHILD));
    }

    #[test]
    fn pipe_cloexec_and_nonblocking_flags() {
        let (r, w) = pipe_cloexec().expect("pipe2");
        for fd in [r.as_raw_fd(), w.as_raw_fd()] {
            // SAFETY: querying flags on an owned, open descriptor.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0, "F_GETFD");
            assert_ne!(flags & libc::FD_CLOEXEC, 0, "exec must revoke the pipe");
        }
        set_nonblocking(r.as_fd()).expect("nonblock");
        // SAFETY: querying flags on an owned, open descriptor.
        let fl = unsafe { libc::fcntl(r.as_raw_fd(), libc::F_GETFL) };
        assert!(fl >= 0, "F_GETFL");
        assert_ne!(fl & libc::O_NONBLOCK, 0);
        // Pipe ends have distinct open file descriptions: the write
        // end's status flags are untouched.
        // SAFETY: querying flags on an owned, open descriptor.
        let flw = unsafe { libc::fcntl(w.as_raw_fd(), libc::F_GETFL) };
        assert!(flw >= 0, "F_GETFL");
        assert_eq!(flw & libc::O_NONBLOCK, 0);
        // A descriptor already above the stdio slots passes through
        // ensure_fd_above_stdio unchanged.
        let raw = r.as_raw_fd();
        let r = ensure_fd_above_stdio(r).expect("ensure");
        assert_eq!(r.as_raw_fd(), raw);
    }

    #[test]
    fn sync_socketpair_flags_and_barrier_bytes() {
        // Process-free descriptor coverage of the spawn barrier shape:
        // CLOEXEC on both ends, one byte each way through the
        // SIGPIPE-proof sender, then EOF once a peer end drops.
        let (a, b) = socketpair_cloexec().expect("socketpair");
        for fd in [a.as_raw_fd(), b.as_raw_fd()] {
            // SAFETY: querying flags on an owned, open descriptor.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0, "F_GETFD");
            assert_ne!(flags & libc::FD_CLOEXEC, 0, "exec must revoke the sync socket");
        }
        assert_eq!(send_no_sigpipe(a.as_fd(), &[1]).expect("ready send"), 1);
        assert!(read_byte_blocking(b.as_fd()).expect("ready"), "byte expected");
        assert_eq!(send_no_sigpipe(b.as_fd(), &[1]).expect("go send"), 1);
        assert!(read_byte_blocking(a.as_fd()).expect("go"), "byte expected");
        drop(a);
        let eof = read_byte_blocking(b.as_fd()).expect("eof read");
        assert!(!eof, "a dropped peer must read as EOF, not a byte");
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

    /// Bounded-retry EXCLUSIVE 0700 fixture base as an RAII guard: it
    /// owns only the directory it itself created (plain create, never
    /// create_dir_all, never pre-cleaning), and Drop removes exactly
    /// that base — never anything else.
    struct BaseGuard(std::path::PathBuf);

    impl BaseGuard {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::DirBuilderExt;
            for i in 0..64u32 {
                let p = std::env::temp_dir().join(format!(
                    "everpty-sys-{tag}-{}-{i}",
                    std::process::id()
                ));
                let mut b = std::fs::DirBuilder::new();
                b.mode(0o700);
                if b.create(&p).is_ok() {
                    return Self(p);
                }
            }
            panic!("no exclusive fixture base for {tag}");
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for BaseGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn poll_reports_ready_immediate_empty_and_clamps_huge_waits() {
        use std::io::Write;
        let (r, w) = pipe_cloexec().expect("pipe");
        let mut w = std::fs::File::from(w);
        // Nothing writable on the read end: a zero timeout returns 0.
        let mut fds = [PollFd::new(r.as_fd(), PollFlags::POLLIN)];
        assert_eq!(poll(&mut fds, Some(0)).expect("poll empty"), 0);
        w.write(b"x").expect("write");
        // A ready fd with an over-i32::MAX requested wait returns
        // immediately: the clamp turns an invalid duration into the
        // maximum legal one instead of an error.
        let mut fds = [PollFd::new(r.as_fd(), PollFlags::POLLIN)];
        assert_eq!(poll(&mut fds, Some(u32::MAX)).expect("poll clamped"), 1);
        assert!(fds[0]
            .revents()
            .unwrap_or(PollFlags::empty())
            .contains(PollFlags::POLLIN));
    }

    #[test]
    fn clock_monotonic_never_goes_backwards() {
        let a = clock_monotonic_ms().expect("t1");
        let b = clock_monotonic_ms().expect("t2");
        assert!(b >= a, "monotonic clock went backwards: {a} -> {b}");
    }

    #[test]
    fn entry_identity_gate_is_pure_and_conservative() {
        let euid = effective_uid();
        // stat_with-shaped identities through the pure gate.
        let id = |mode: u32, uid: libc::uid_t| {
            // SAFETY: libc::stat is plain data; a zeroed value is valid.
            let mut st: nix::sys::stat::FileStat = unsafe { std::mem::zeroed() };
            st.st_mode = mode;
            st.st_uid = uid;
            EntryIdentity::from_stat(&st)
        };
        assert!(id(libc::S_IFSOCK | 0o600, euid).still_is_socket_of(euid));
        // Wrong type, wrong owner, or both → refuse.
        assert!(!id(libc::S_IFREG | 0o600, euid).still_is_socket_of(euid));
        assert!(!id(libc::S_IFLNK | 0o600, euid).still_is_socket_of(euid));
        assert!(!id(libc::S_IFSOCK | 0o600, euid.wrapping_add(1)).still_is_socket_of(euid));
        // Equality pins the exact object (dev/ino participate).
        let mut a = id(libc::S_IFSOCK | 0o600, euid);
        assert_eq!(a, id(libc::S_IFSOCK | 0o600, euid));
        let mut b = a;
        b.ino += 1;
        assert_ne!(a, b);
        a.dev += 1;
        assert_ne!(a, b);
    }

    #[test]
    fn cleanup_decision_is_identity_gated() {
        // The injected failure-path matrix for the cleanup rule: only
        // an EXACT identity match may unlink.
        let euid = effective_uid();
        let captured = EntryIdentity {
            dev: 7,
            ino: 42,
            kind: libc::S_IFSOCK,
            uid: euid,
        };
        // Fresh stat identical → unlink.
        assert!(cleanup_should_unlink(&captured, Some(captured)));
        // Replaced entry (different inode, device, type, or owner) →
        // retain.
        for mutated in [
            EntryIdentity { ino: 43, ..captured },
            EntryIdentity { dev: 8, ..captured },
            EntryIdentity { kind: libc::S_IFREG, ..captured },
            EntryIdentity { uid: euid.wrapping_add(1), ..captured },
        ] {
            assert!(
                !cleanup_should_unlink(&captured, Some(mutated)),
                "a replaced entry must be retained"
            );
        }
        // Vanished entry (fresh stat failed) → nothing to remove, and
        // no missing capture ever justifies an unlink.
        assert!(!cleanup_should_unlink(&captured, None));
    }

    #[test]
    fn identity_bound_listener_is_exact_0600_and_round_trips() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        let guard = BaseGuard::new("l");
        let dir = guard.path();
        let name = std::ffi::OsString::from("socket");
        let dirf = std::fs::File::open(dir).expect("dir open");

        // Bad entry names are rejected before any syscall.
        for bad in ["", ".", "..", "a/b"] {
            assert_eq!(
                bind_unix_listener_at(dirf.as_fd(), std::ffi::OsStr::new(bad), 16)
                    .expect_err("bad entry name")
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }

        let listener = bind_unix_listener_at(dirf.as_fd(), &name, 16).expect("bind");
        let st = std::fs::symlink_metadata(dir.join(&name)).expect("stat entry");
        assert_eq!(st.mode() & libc::S_IFMT, libc::S_IFSOCK, "must be a socket");
        assert_eq!(st.mode() & 0o7777, 0o600, "exact 0600 mode");
        drop(listener);
        let _ = std::fs::remove_file(dir.join(&name));

        // A RAW NON-UTF-8 component name binds and cleans up the same
        // way (no to_string_lossy anywhere in the path).
        let raw = std::ffi::OsStr::from_bytes(b"\xff\xfe-raw");
        let listener = bind_unix_listener_at(dirf.as_fd(), raw, 16).expect("raw bind");
        let st = std::fs::symlink_metadata(dir.join(raw)).expect("stat raw entry");
        assert_eq!(st.mode() & 0o7777, 0o600, "raw-name socket exact 0600");
        drop(listener);
        let _ = std::fs::remove_file(dir.join(raw));

        // Full round trip on a fresh name.
        let name2 = std::ffi::OsString::from("socket2");
        let listener = bind_unix_listener_at(dirf.as_fd(), &name2, 16).expect("bind");
        // Empty backlog: accept returns None without blocking.
        assert!(accept_nonblock(listener.as_fd()).expect("accept empty").is_none());
        // Real same-UID peer: connect, accept, credentials, data, EOF.
        let client = std::os::unix::net::UnixStream::connect(dir.join(&name2)).expect("connect");
        client.set_nonblocking(true).expect("client nonblock");
        let accepted = accept_nonblock(listener.as_fd()).expect("accept").expect("conn");
        assert_eq!(peer_uid(accepted.as_fd()).expect("uid"), effective_uid());
        assert!(recv(accepted.as_fd(), &mut [0u8; 8]).expect("recv empty").is_none());
        assert_eq!(send_no_sigpipe(client.as_fd(), b"hi").expect("send"), 2);
        let mut buf = [0u8; 8];
        assert_eq!(recv(accepted.as_fd(), &mut buf).expect("recv"), Some(2));
        assert_eq!(&buf[..2], b"hi");
        drop(client);
        // Peer gone: recv reports EOF (0), never an error.
        assert_eq!(recv(accepted.as_fd(), &mut buf).expect("eof"), Some(0));
        drop(listener);
        let _ = std::fs::remove_file(dir.join(&name2));
    }
}
