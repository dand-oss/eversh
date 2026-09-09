//! Unbuffered local descriptor adapters for the matched stream clients.
//! Construct after authenticated terminal activation, and drop before restoring
//! the terminal. Both modes execute the same read_fd/write_fd operations.

use everpty::sys;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite, ReadBuf};

pub struct Descriptor<'fd> {
    fd: BorrowedFd<'fd>,
    _flags: sys::NonblockingGuard<'fd>,
}

impl<'fd> Descriptor<'fd> {
    pub fn new(fd: BorrowedFd<'fd>) -> io::Result<Self> {
        Ok(Self {
            fd,
            _flags: sys::NonblockingGuard::new(fd)?,
        })
    }
}

impl AsFd for Descriptor<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd
    }
}

impl Read for Descriptor<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        sys::read_fd(self.fd, bytes)
    }
}

impl Write for Descriptor<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        sys::write_fd(self.fd, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Tokio readiness around the identical unbuffered descriptor operations.
/// Requires an eventable descriptor (PTY, pipe, socket), not a regular file.
pub struct AsyncDescriptor<'fd> {
    ready: AsyncFd<OwnedFd>,
    descriptor: Descriptor<'fd>,
}

impl<'fd> AsyncDescriptor<'fd> {
    pub fn new(fd: BorrowedFd<'fd>) -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let descriptor = Descriptor::new(fd)?;
        let ready = AsyncFd::new(sys::duplicate_cloexec(fd)?)?;
        Ok(Self { ready, descriptor })
    }
}

impl AsyncRead for AsyncDescriptor<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        // Re-poll after stale readiness to register the waiter. Bound races
        // with readiness refresh so a single call cannot monopolize the loop.
        for _ in 0..2 {
            let mut ready = std::task::ready!(this.ready.poll_read_ready(cx))?;
            match ready.try_io(|_| this.descriptor.read(buffer.initialize_unfilled())) {
                Ok(Ok(count)) => {
                    buffer.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => {}
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for AsyncDescriptor<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        for _ in 0..2 {
            let mut ready = std::task::ready!(this.ready.poll_write_ready(cx))?;
            match ready.try_io(|_| this.descriptor.write(bytes)) {
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                Ok(result) => return Poll::Ready(result),
                Err(_) => {}
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    // No buffered bytes and no ownership of the caller's terminal descriptor.
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn native_descriptor_preserves_would_block_bytes_and_eof() {
        let (local, mut peer) = UnixStream::pair().expect("pair");
        let mut descriptor = Descriptor::new(local.as_fd()).expect("descriptor");
        let mut bytes = [0; 3];
        assert_eq!(
            descriptor
                .read(&mut bytes)
                .expect_err("empty socket")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        peer.write_all(b"abc").expect("peer write");
        assert_eq!(descriptor.read(&mut bytes).expect("read"), 3);
        assert_eq!(&bytes, b"abc");
        assert_eq!(descriptor.write(b"xyz").expect("write"), 3);
        peer.read_exact(&mut bytes).expect("peer read");
        assert_eq!(&bytes, b"xyz");
        peer.shutdown(std::net::Shutdown::Write).expect("peer EOF");
        assert_eq!(descriptor.read(&mut bytes).expect("EOF"), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_descriptor_rearms_after_cancelled_pending_read() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tokio::time::timeout(Duration::from_secs(2), async {
            let (local, mut peer) = UnixStream::pair().expect("pair");
            let mut descriptor = AsyncDescriptor::new(local.as_fd()).expect("descriptor");
            let mut bytes = [0; 3];
            assert!(tokio::time::timeout(
                Duration::from_millis(10),
                descriptor.read_exact(&mut bytes)
            )
            .await
            .is_err());
            peer.write_all(b"abc").expect("peer write");
            descriptor
                .read_exact(&mut bytes)
                .await
                .expect("read after cancellation");
            assert_eq!(&bytes, b"abc");
            descriptor
                .write_all(b"xyz")
                .await
                .expect("unbuffered write");
            peer.read_exact(&mut bytes).expect("peer read");
            assert_eq!(&bytes, b"xyz");
            peer.shutdown(std::net::Shutdown::Write).expect("peer EOF");
            assert_eq!(descriptor.read(&mut bytes).await.expect("EOF"), 0);
        })
        .await
        .expect("bounded descriptor test");
    }
}
