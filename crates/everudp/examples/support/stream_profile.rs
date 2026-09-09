//! Opt-in preflight snapshots of the exact configs handed to each driver.
//! Pinned noQ Debug implementations omit crypto, tokens and token stores.
//! These are local built settings, not negotiated peer transport parameters.

use super::Runtime;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub const DIRECTORY_ENV: &str = "EVERUDP_STREAM_PROFILE_DIR";

pub fn client(
    runtime: Runtime,
    config: &noq::ClientConfig,
    initial_gso_cap: usize,
) -> io::Result<()> {
    capture(runtime, "client", || {
        format!("{config:?}; socket_initial_gso_cap={initial_gso_cap}")
    })
}

pub fn server(
    runtime: Runtime,
    config: &noq::ServerConfig,
    initial_gso_cap: usize,
) -> io::Result<()> {
    capture(runtime, "server", || {
        format!("{config:?}; socket_initial_gso_cap={initial_gso_cap}")
    })
}

fn capture(runtime: Runtime, side: &str, snapshot: impl FnOnce() -> String) -> io::Result<()> {
    let Some(directory) = std::env::var_os(DIRECTORY_ENV) else {
        return Ok(());
    };
    write_snapshot(Path::new(&directory), runtime, side, &snapshot())
}

fn write_snapshot(
    directory: &Path,
    runtime: Runtime,
    side: &str,
    snapshot: &str,
) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(directory)?;
    if !metadata.is_dir()
        || metadata.uid() != everpty::sys::effective_uid()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(io::Error::other(
            "profile directory must be private and owned by this user",
        ));
    }
    if snapshot.len() > 16 * 1024 || snapshot.contains('\n') {
        return Err(io::Error::other("invalid bounded profile snapshot"));
    }
    let name = format!("{}-{side}-{}-built.txt", runtime.name(), std::process::id());
    let mut file = std::fs::File::from(everpty::sys::create_exclusive_private(
        &directory.join(name),
    )?);
    writeln!(file, "everudp-stream-built-profile-v1")?;
    writeln!(
        file,
        "runtime={} side={side} pid={}",
        runtime.name(),
        std::process::id()
    )?;
    writeln!(file, "scope=local-built-not-negotiated")?;
    writeln!(file, "{snapshot}")?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    #[test]
    fn private_receipt_is_exclusive_and_rejects_unsafe_directory() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "everudp-stream-profile-{}-{unique}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .expect("private directory");
        write_snapshot(&directory, Runtime::Native, "client", "config").expect("receipt");
        assert!(write_snapshot(&directory, Runtime::Native, "client", "replacement").is_err());
        let file = directory.join(format!("native-client-{}-built.txt", std::process::id()));
        assert_eq!(
            std::fs::metadata(&file).expect("metadata").mode() & 0o777,
            0o600
        );
        assert!(std::fs::read_to_string(&file)
            .expect("receipt")
            .contains("scope=local-built-not-negotiated"));
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("unsafe mode");
        assert!(write_snapshot(&directory, Runtime::Ordinary, "client", "config").is_err());
        std::fs::remove_file(file).expect("remove own receipt");
        std::fs::remove_dir(directory).expect("remove own empty directory");
    }
}
