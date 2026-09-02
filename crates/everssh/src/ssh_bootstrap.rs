//! Bounded OpenSSH process ownership and exact bootstrap acquisition.

use crate::bootstrap::BootstrapRecord;
use crate::error::Error;
use crate::limits::Limits;
use crate::ssh_policy::{validate_effective_config, SshPlan, SSH_PROGRAM};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::time::Instant;
use zeroize::Zeroize;

const CONFIG_OUTPUT_MAX: usize = 64 * 1024;
const STDERR_MAX: usize = 16 * 1024;

pub(crate) struct SecretBytes {
    bytes: Vec<u8>,
    overflow: bool,
}

impl SecretBytes {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn overflowed(&self) -> bool {
        self.overflow
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("length", &self.bytes.len())
            .field("overflow", &self.overflow)
            .finish()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Exclusive owner of one process. Ordinary errors use async kill+wait; Drop
/// is the cancellation backstop and makes one bounded synchronous kill/reap
/// attempt without ever detaching the still-owned child handle.
pub(crate) struct ChildOwner {
    child: Option<Child>,
    cleanup_timeout: Duration,
    cleanup_deadline: Option<std::time::Instant>,
    transferable: bool,
    released: bool,
}

impl ChildOwner {
    pub(crate) fn spawn(command: &mut Command, cleanup_timeout: Duration) -> Result<Self, Error> {
        Self::spawn_with_transfer(command, cleanup_timeout, false)
    }

    pub(crate) fn spawn_transferable(
        command: &mut Command,
        cleanup_timeout: Duration,
    ) -> Result<Self, Error> {
        Self::spawn_with_transfer(command, cleanup_timeout, true)
    }

    fn spawn_with_transfer(
        command: &mut Command,
        cleanup_timeout: Duration,
        transferable: bool,
    ) -> Result<Self, Error> {
        if std::time::Instant::now()
            .checked_add(cleanup_timeout)
            .is_none()
        {
            return Err(Error::InvalidLimits(
                crate::error::LimitViolation::DeadlineOverflow,
            ));
        }
        // Ordinary children retain Tokio's kill backstop. The private server
        // opts out only because its protocol has an explicit transfer point.
        command.kill_on_drop(!transferable);
        let child = command.spawn().map_err(Error::Io)?;
        Ok(Self {
            child: Some(child),
            cleanup_timeout,
            cleanup_deadline: None,
            transferable,
            released: false,
        })
    }

    pub(crate) fn take_stdin(&mut self) -> Result<ChildStdin, Error> {
        self.child_mut()?
            .stdin
            .take()
            .ok_or(Error::SshProcessFailed)
    }

    pub(crate) fn take_stdout(&mut self) -> Result<ChildStdout, Error> {
        self.child_mut()?
            .stdout
            .take()
            .ok_or(Error::SshProcessFailed)
    }

    fn take_stderr(&mut self) -> Result<ChildStderr, Error> {
        self.child_mut()?
            .stderr
            .take()
            .ok_or(Error::SshProcessFailed)
    }

    fn child_mut(&mut self) -> Result<&mut Child, Error> {
        self.child.as_mut().ok_or(Error::SshProcessFailed)
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        self.child_mut()?.try_wait().map_err(Error::Io)
    }

    pub(crate) async fn wait(&mut self) -> Result<ExitStatus, Error> {
        self.child_mut()?.wait().await.map_err(Error::Io)
    }

    pub(crate) async fn kill_and_reap(&mut self) -> Result<(), Error> {
        let deadline = self.freeze_cleanup_deadline();
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };

        let (already_exited, mut first_cleanup_error) = match child.try_wait() {
            Ok(status) => (status.is_some(), None),
            Err(error) => (false, Some(error)),
        };
        if !already_exited {
            match child.start_kill() {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
                Err(error) if first_cleanup_error.is_none() => first_cleanup_error = Some(error),
                Err(_) => {}
            }
        }
        tokio::time::timeout_at(Instant::from_std(deadline), child.wait())
            .await
            .map_err(|_| Error::BootstrapTimedOut)?
            .map_err(Error::Io)?;
        if let Some(error) = first_cleanup_error {
            return Err(Error::Io(error));
        }
        Ok(())
    }

    fn freeze_cleanup_deadline(&mut self) -> std::time::Instant {
        if let Some(deadline) = self.cleanup_deadline {
            return deadline;
        }
        let now = std::time::Instant::now();
        let deadline = now.checked_add(self.cleanup_timeout).unwrap_or(now);
        self.cleanup_deadline = Some(deadline);
        deadline
    }

    /// Deliberately transfer a released one-shot process to the system reaper.
    pub(crate) fn release(mut self) -> Result<(), Error> {
        if !self.transferable {
            return Err(Error::SshProcessFailed);
        }
        self.released = true;
        drop(self.child.take());
        Ok(())
    }
}

impl std::fmt::Debug for ChildOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChildOwner")
            .field("pid", &self.child.as_ref().and_then(Child::id))
            .field("released", &self.released)
            .finish()
    }
}

impl Drop for ChildOwner {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let deadline = self.freeze_cleanup_deadline();
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = child.start_kill();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Ok(None) | Err(_) => break,
            }
        }
    }
}

pub async fn verify_effective_config(plan: &SshPlan, limits: &Limits) -> Result<(), Error> {
    let output = run_owned_ssh(&plan.config_query_args(), CONFIG_OUTPUT_MAX, limits).await?;
    if output.overflowed() {
        return Err(Error::SshPolicyRejected);
    }
    validate_effective_config(output.as_slice())
}

pub async fn acquire_bootstrap(plan: &SshPlan, limits: &Limits) -> Result<BootstrapRecord, Error> {
    let output = run_owned_ssh(&plan.bootstrap_args(), limits.bootstrap_record_max, limits).await?;
    if output.overflowed() {
        return Err(Error::BootstrapMalformed);
    }
    parse_exact_bootstrap(output, limits)
}

async fn run_owned_ssh(
    arguments: &[String],
    stdout_max: usize,
    limits: &Limits,
) -> Result<SecretBytes, Error> {
    limits.validate()?;
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(limits.bootstrap_timeout_ms))
        .ok_or(Error::BootstrapTimedOut)?;
    let mut command = Command::new(SSH_PROGRAM);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut owner = ChildOwner::spawn(&mut command, limits.finalize_timeout())?;
    let stdout = owner.take_stdout()?;
    let stderr = owner.take_stderr()?;

    let gathered = tokio::time::timeout_at(deadline, async {
        let (stdout, stderr, status) = tokio::join!(
            read_capped_to_eof(stdout, stdout_max),
            read_capped_to_eof(stderr, STDERR_MAX),
            owner.wait(),
        );
        (stdout, stderr, status)
    })
    .await;

    let (stdout, _stderr, status) = match gathered {
        Ok((stdout, stderr, status)) => (stdout?, stderr?, status?),
        Err(_) => {
            let _ = owner.kill_and_reap().await;
            return Err(Error::BootstrapTimedOut);
        }
    };
    if !status.success() {
        return Err(Error::SshProcessFailed);
    }
    Ok(stdout)
}

fn parse_exact_bootstrap(output: SecretBytes, limits: &Limits) -> Result<BootstrapRecord, Error> {
    let bytes = output.as_slice();
    if bytes.is_empty()
        || bytes.len() > limits.bootstrap_record_max
        || bytes.last() != Some(&b'\n')
        || bytes.contains(&b'\r')
        || bytes[..bytes.len() - 1].contains(&b'\n')
    {
        return Err(Error::BootstrapMalformed);
    }
    let line =
        std::str::from_utf8(&bytes[..bytes.len() - 1]).map_err(|_| Error::BootstrapMalformed)?;
    let record = BootstrapRecord::parse(line, limits)?;
    let canonical = record.encode();
    if canonical.as_str().as_bytes() != bytes {
        return Err(Error::BootstrapMalformed);
    }
    Ok(record)
}

pub(crate) async fn read_capped_to_eof<R>(
    mut reader: R,
    maximum: usize,
) -> Result<SecretBytes, Error>
where
    R: AsyncRead + Unpin,
{
    let mut output = SecretBytes {
        bytes: Vec::new(),
        overflow: false,
    };
    output
        .bytes
        .try_reserve_exact(maximum.saturating_add(1))
        .map_err(|_| Error::BridgeAllocation)?;
    let mut scratch = [0u8; 4096];
    loop {
        let count = match reader.read(&mut scratch).await {
            Ok(count) => count,
            Err(error) => {
                scratch.zeroize();
                return Err(Error::Io(error));
            }
        };
        if count == 0 {
            break;
        }
        let remaining = maximum.saturating_add(1).saturating_sub(output.bytes.len());
        let retained = count.min(remaining);
        output.bytes.extend_from_slice(&scratch[..retained]);
        output.overflow |= retained < count || output.bytes.len() > maximum;
        scratch[..count].zeroize();
    }
    scratch.zeroize();
    Ok(output)
}

pub(crate) async fn read_capped_line<R>(
    reader: &mut R,
    maximum: usize,
    deadline: Instant,
) -> Result<SecretBytes, Error>
where
    R: AsyncRead + Unpin,
{
    let mut captured = SecretBytes {
        bytes: Vec::new(),
        overflow: false,
    };
    captured
        .bytes
        .try_reserve_exact(maximum)
        .map_err(|_| Error::BridgeAllocation)?;
    loop {
        if captured.bytes.len() >= maximum {
            return Err(Error::BootstrapMalformed);
        }
        let mut byte = [0u8; 1];
        let outcome = tokio::time::timeout_at(deadline, reader.read(&mut byte)).await;
        let count = match outcome {
            Ok(Ok(count)) => count,
            Ok(Err(error)) => {
                byte.zeroize();
                return Err(Error::Io(error));
            }
            Err(_) => {
                byte.zeroize();
                return Err(Error::BootstrapTimedOut);
            }
        };
        if count == 0 {
            byte.zeroize();
            return Err(Error::BootstrapMalformed);
        }
        captured.bytes.push(byte[0]);
        byte.zeroize();
        if captured.bytes.last() == Some(&b'\n') {
            return Ok(captured);
        }
    }
}

pub(crate) async fn require_eof<R>(reader: &mut R, deadline: Instant) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    let outcome = tokio::time::timeout_at(deadline, reader.read(&mut byte)).await;
    let result = match outcome {
        Ok(Ok(count)) => Ok(count),
        Ok(Err(error)) => Err(Error::Io(error)),
        Err(_) => Err(Error::BootstrapTimedOut),
    };
    byte.zeroize();
    match result? {
        0 => Ok(()),
        _ => Err(Error::ReleaseRejected),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::bootstrap::SecretToken;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn secret_capture_debug_reports_only_shape() {
        let captured = SecretBytes {
            bytes: b"sensitive-bootstrap-token".to_vec(),
            overflow: true,
        };
        let debug = format!("{captured:?}");
        assert!(debug.contains("length: 25"));
        assert!(debug.contains("overflow: true"));
        assert!(!debug.contains("sensitive"));
        assert!(!debug.contains("bootstrap-token"));
    }

    #[tokio::test]
    async fn capped_reader_drains_and_marks_overflow() {
        let input = tokio::io::duplex(64);
        let (mut writer, reader) = input;
        let producer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            writer.write_all(b"abcdef").await.unwrap();
        });
        let captured = read_capped_to_eof(reader, 4).await.unwrap();
        producer.await.unwrap();
        assert_eq!(captured.as_slice(), b"abcde");
        assert!(captured.overflowed());
    }

    #[tokio::test]
    async fn exact_line_and_eof_readers_reject_every_boundary_shape() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut exact = b"abc\n".as_slice();
        let line = read_capped_line(&mut exact, 4, deadline).await.unwrap();
        assert_eq!(line.as_slice(), b"abc\n");
        assert!(require_eof(&mut exact, deadline).await.is_ok());

        for bytes in [b"".as_slice(), b"abc", b"abcd", b"abc\r\n"] {
            let mut input = bytes;
            let result = read_capped_line(&mut input, 4, deadline).await;
            assert!(result.is_err(), "accepted line input {bytes:?}");
        }

        let captured = read_capped_to_eof(b"abcde".as_slice(), 4).await.unwrap();
        assert_eq!(captured.as_slice(), b"abcde");
        assert!(captured.overflowed());

        let mut trailing = b"x".as_slice();
        assert!(require_eof(&mut trailing, deadline).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn child_owner_kills_and_reaps_on_explicit_cleanup_and_drop() {
        fn sleeping_command() -> Command {
            let mut command = Command::new("sh");
            command
                .args(["-c", "exec sleep 30"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            command
        }

        let mut command = sleeping_command();
        let mut owner = ChildOwner::spawn(&mut command, Duration::from_secs(2)).unwrap();
        let pid = owner.child.as_ref().and_then(Child::id).unwrap();
        owner.kill_and_reap().await.unwrap();
        assert!(owner.try_wait().unwrap().is_some());
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());

        let mut command = sleeping_command();
        let owner = ChildOwner::spawn(&mut command, Duration::from_secs(2)).unwrap();
        let pid = owner.child.as_ref().and_then(Child::id).unwrap();
        let task = tokio::spawn(async move {
            let _owner = owner;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn only_transferable_children_can_be_released() {
        let mut command = Command::new("sh");
        command
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut owner = ChildOwner::spawn(&mut command, Duration::from_secs(1)).unwrap();
        assert!(owner.wait().await.unwrap().success());
        assert!(owner.release().is_err());

        let mut command = Command::new("sh");
        command
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut owner =
            ChildOwner::spawn_transferable(&mut command, Duration::from_secs(1)).unwrap();
        assert!(owner.wait().await.unwrap().success());
        assert!(owner.release().is_ok());
    }

    #[test]
    fn exact_bootstrap_rejects_trailing_data() {
        let limits = Limits::default();
        let record = BootstrapRecord::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            4444,
            [7; 32],
            SecretToken::from_bytes([8; 32]),
            crate::association::AssociationId::from_bytes([0x57; 16]).unwrap(),
            9,
        )
        .unwrap();
        let mut bytes = record.encode().as_str().as_bytes().to_vec();
        bytes.extend_from_slice(b"x");
        assert!(parse_exact_bootstrap(
            SecretBytes {
                bytes,
                overflow: false
            },
            &limits
        )
        .is_err());
    }
}
