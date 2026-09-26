//! Locate only the destination user's existing SSH agent, without executing
//! keychain's saved shell fragment or starting another agent.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const PROBE_DEADLINE: Duration = Duration::from_millis(500);
const MAX_AGENT_REPLY: usize = 256 * 1024;

fn current_uid() -> u32 {
    everpty::sys::effective_uid()
}

fn usable_socket(path: &Path, uid: u32) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    meta.uid() == uid && meta.file_type().is_socket() && agent_has_identities(path)
}

fn wait_ready(stream: &UnixStream, flags: everpty::sys::PollFlags, deadline: Instant) -> bool {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return false;
    }
    let millis = remaining.as_millis().min(u32::MAX as u128) as u32;
    let mut fds = [everpty::sys::PollFd::new(stream.as_fd(), flags)];
    everpty::sys::poll(&mut fds, Some(millis.max(1))).is_ok_and(|count| count > 0)
}

fn write_bounded(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> bool {
    while !bytes.is_empty() {
        if !wait_ready(stream, everpty::sys::PollFlags::POLLOUT, deadline) {
            return false;
        }
        match stream.write(bytes) {
            Ok(0) => return false,
            Ok(n) => bytes = &bytes[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return false,
        }
    }
    true
}

fn read_bounded(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> bool {
    while !bytes.is_empty() {
        if !wait_ready(stream, everpty::sys::PollFlags::POLLIN, deadline) {
            return false;
        }
        match stream.read(bytes) {
            Ok(0) => return false,
            Ok(n) => bytes = &mut bytes[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return false,
        }
    }
    true
}

fn identities_loaded(reply: &[u8]) -> bool {
    if reply.len() < 5 || reply[0] != 12 {
        return false;
    }
    let count = u32::from_be_bytes([reply[1], reply[2], reply[3], reply[4]]) as usize;
    if count == 0 || count > 1024 {
        return false;
    }
    let mut rest = &reply[5..];
    for _ in 0..count {
        for _ in 0..2 {
            if rest.len() < 4 {
                return false;
            }
            let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            if len > rest.len() - 4 {
                return false;
            }
            rest = &rest[4 + len..];
        }
    }
    rest.is_empty()
}

fn agent_has_identities(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let Some(name) = path.file_name() else {
        return false;
    };
    let Ok(directory) = fs::File::open(parent) else {
        return false;
    };
    let deadline = Instant::now() + PROBE_DEADLINE;
    let Ok(fd) = everpty::sys::connect_unix_at(directory.as_fd(), name) else {
        return false;
    };
    let mut stream = UnixStream::from(fd);
    if !wait_ready(&stream, everpty::sys::PollFlags::POLLOUT, deadline)
        || !everpty::sys::socket_error(stream.as_fd()).is_ok_and(|error| error.is_none())
    {
        return false;
    }
    // SSH agent protocol: a four-byte length and SSH2_AGENTC_REQUEST_IDENTITIES (11).
    if !write_bounded(&mut stream, &[0, 0, 0, 1, 11], deadline) {
        return false;
    }
    let mut header = [0; 4];
    if !read_bounded(&mut stream, &mut header, deadline) {
        return false;
    }
    let size = u32::from_be_bytes(header) as usize;
    if !(5..=MAX_AGENT_REPLY).contains(&size) {
        return false;
    }
    let mut reply = vec![0; size];
    read_bounded(&mut stream, &mut reply, deadline) && identities_loaded(&reply)
}

fn parse_saved_socket(contents: &str) -> Option<PathBuf> {
    let line = contents.lines().next()?;
    let value = line
        .strip_prefix("SSH_AUTH_SOCK=\"")?
        .strip_suffix("\"; export SSH_AUTH_SOCK")?;
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\n' | b'\r' | b'"' | b'\\' | b'`' | b'$'))
    {
        return None;
    }
    Some(PathBuf::from(value))
}

/// Return a live inherited socket, or the saved keychain socket for this
/// host. Missing or untrusted state simply leaves agent access unavailable.
pub fn resolve(inherited: Option<&OsStr>, home: Option<&Path>, hostname: &str) -> Option<OsString> {
    let uid = current_uid();
    if let Some(inherited) = inherited {
        if usable_socket(Path::new(inherited), uid) {
            return Some(inherited.to_owned());
        }
    }
    if hostname.is_empty()
        || !hostname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return None;
    }
    let home = home?;
    let home_meta = fs::symlink_metadata(home).ok()?;
    if !home.is_absolute() || !home_meta.file_type().is_dir() || home_meta.uid() != uid {
        return None;
    }
    let directory = home.join(".keychain");
    let dir_meta = fs::symlink_metadata(&directory).ok()?;
    if !dir_meta.file_type().is_dir()
        || dir_meta.uid() != uid
        || dir_meta.permissions().mode() & 0o022 != 0
    {
        return None;
    }
    let saved = directory.join(format!("{hostname}-sh"));
    let meta = fs::symlink_metadata(&saved).ok()?;
    if !meta.file_type().is_file()
        || meta.uid() != uid
        || meta.permissions().mode() & 0o077 != 0
        || meta.len() > 1024
    {
        return None;
    }
    let data = fs::read_to_string(saved).ok()?;
    let socket = parse_saved_socket(&data)?;
    usable_socket(&socket, uid).then(|| socket.into_os_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn answering_agent(
        listener: UnixListener,
        count: usize,
        identities: u32,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            for _ in 0..count {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 5];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(request, [0, 0, 0, 1, 11]);
                let mut reply = vec![12];
                reply.extend_from_slice(&identities.to_be_bytes());
                for _ in 0..identities {
                    reply.extend_from_slice(&1_u32.to_be_bytes());
                    reply.push(b'k');
                    reply.extend_from_slice(&0_u32.to_be_bytes());
                }
                stream
                    .write_all(&(reply.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(&reply).unwrap();
            }
        })
    }

    #[test]
    fn reuses_live_inherited_then_saved_socket_and_rejects_untrusted_state() {
        let root = std::env::temp_dir().join(format!("eversh-agent-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(".keychain")).unwrap();
        fs::set_permissions(root.join(".keychain"), fs::Permissions::from_mode(0o700)).unwrap();
        let inherited = root.join("inherited.sock");
        let saved_socket = root.join("saved.sock");
        let listener1 = answering_agent(UnixListener::bind(&inherited).unwrap(), 1, 1);
        let listener2 = answering_agent(UnixListener::bind(&saved_socket).unwrap(), 4, 1);
        let empty = root.join("empty.sock");
        let empty_listener = answering_agent(UnixListener::bind(&empty).unwrap(), 1, 0);
        let state = root.join(".keychain/testhost-sh");
        fs::write(&state, format!("SSH_AUTH_SOCK=\"{}\"; export SSH_AUTH_SOCK\nSSH_AGENT_PID=1; export SSH_AGENT_PID;\n", saved_socket.display())).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            resolve(Some(inherited.as_os_str()), Some(&root), "testhost"),
            Some(inherited.clone().into_os_string())
        );
        assert_eq!(
            resolve(None, Some(&root), "testhost"),
            Some(saved_socket.clone().into_os_string())
        );
        assert_eq!(
            resolve(Some(OsStr::new("/missing")), Some(&root), "testhost"),
            Some(saved_socket.clone().into_os_string())
        );
        assert_eq!(
            resolve(Some(empty.as_os_str()), Some(&root), "testhost"),
            Some(saved_socket.clone().into_os_string())
        );
        let stalled = root.join("stalled.sock");
        let stalled_listener = UnixListener::bind(&stalled).unwrap();
        let stalled_thread = thread::spawn(move || {
            let (_stream, _) = stalled_listener.accept().unwrap();
            thread::sleep(Duration::from_millis(700));
        });
        let began = Instant::now();
        assert_eq!(
            resolve(Some(stalled.as_os_str()), Some(&root), "testhost"),
            Some(saved_socket.clone().into_os_string())
        );
        assert!(began.elapsed() < Duration::from_millis(900));
        assert!(!usable_socket(&saved_socket, current_uid().wrapping_add(1)));
        fs::remove_file(&saved_socket).unwrap();
        assert_eq!(resolve(None, Some(&root), "testhost"), None);
        let _replacement = UnixListener::bind(&saved_socket).unwrap();
        fs::write(
            &state,
            "SSH_AUTH_SOCK=$(touch /tmp/unsafe); export SSH_AUTH_SOCK\n",
        )
        .unwrap();
        assert_eq!(resolve(None, Some(&root), "testhost"), None);
        fs::write(
            &state,
            format!(
                "SSH_AUTH_SOCK=\"{}\"; export SSH_AUTH_SOCK\n",
                saved_socket.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(resolve(None, Some(&root), "testhost"), None);
        listener1.join().unwrap();
        listener2.join().unwrap();
        empty_listener.join().unwrap();
        stalled_thread.join().unwrap();
        fs::remove_dir_all(&root).unwrap();
    }
}
