//! Socket ownership for the disposable floor, without a runtime or helper task.
//!
//! Uses the same noQ UDP implementation and receive-batch shape as its Tokio
//! adapter. Error policy belongs to the reactor: raw send errors are preserved,
//! including MTU-probe errors, rather than silently declared accepted here.

use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, UdpSocket};
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, BorrowedFd};

use noq::udp::{RecvMeta, Transmit, UdpSocketState, BATCH_SIZE};

pub struct FloorSocket {
    socket: UdpSocket,
    state: UdpSocketState,
    buffers: Box<[u8]>,
    metadata: [RecvMeta; BATCH_SIZE],
    slot_bytes: usize,
    received: usize,
    transmit_segment_cap: NonZeroUsize,
    #[cfg(all(test, feature = "stream-floor"))]
    block_next_send: std::sync::atomic::AtomicBool,
}

impl FloorSocket {
    /// Own an already route-selected socket. Buffer sizing matches noQ's
    /// `RecvState::new`; allocation occurs once before the timed loop.
    pub fn new(socket: UdpSocket, config: &noq_proto::EndpointConfig) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        let state = UdpSocketState::new((&socket).into())?;
        let slot_bytes = (config.get_max_udp_payload_size().min(64 * 1024) as usize)
            .checked_mul(state.gro_segments().get())
            .ok_or_else(|| io::Error::other("floor receive slot overflow"))?;
        let total = slot_bytes
            .checked_mul(BATCH_SIZE)
            .ok_or_else(|| io::Error::other("floor receive batch overflow"))?;
        Ok(Self {
            socket,
            state,
            buffers: vec![0; total].into_boxed_slice(),
            metadata: [RecvMeta::default(); BATCH_SIZE],
            slot_bytes,
            received: 0,
            transmit_segment_cap: NonZeroUsize::MAX,
            #[cfg(all(test, feature = "stream-floor"))]
            block_next_send: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Match the pinned ordinary noQ connection driver's GSO batch bound.
    /// See vendor/noq/src/connection.rs MAX_TRANSMIT_SEGMENTS (noQ 1.1.1).
    /// The generic datagram floor retains its existing platform limit.
    #[cfg(feature = "stream-floor")]
    pub fn new_stream_floor(
        socket: UdpSocket,
        config: &noq_proto::EndpointConfig,
    ) -> io::Result<Self> {
        let mut result = Self::new(socket, config)?;
        result.transmit_segment_cap = NonZeroUsize::new(10).expect("known nonzero batch cap");
        Ok(result)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }

    pub fn max_transmit_segments(&self) -> NonZeroUsize {
        self.state.max_gso_segments().min(self.transmit_segment_cap)
    }

    /// One nonblocking receive syscall batch. Caller must consume all slots
    /// before invoking this again, including each GRO segment in a slot.
    pub fn receive(&mut self) -> io::Result<usize> {
        self.received = 0;
        let mut chunks = self.buffers.chunks_mut(self.slot_bytes);
        let mut slices: [IoSliceMut<'_>; BATCH_SIZE] =
            std::array::from_fn(|_| IoSliceMut::new(chunks.next().expect("fixed receive batch")));
        let count = self
            .state
            .recv((&self.socket).into(), &mut slices, &mut self.metadata)?;
        if count > BATCH_SIZE
            || self.metadata[..count]
                .iter()
                .any(|meta| meta.len > self.slot_bytes || (meta.len != 0 && meta.stride == 0))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid UDP receive metadata",
            ));
        }
        self.received = count;
        Ok(count)
    }

    pub fn packet(&self, index: usize) -> Option<(&RecvMeta, &[u8])> {
        if index >= self.received {
            return None;
        }
        let meta = &self.metadata[index];
        let start = index * self.slot_bytes;
        Some((meta, &self.buffers[start..start + meta.len]))
    }

    /// No ownership transfer on failure. In particular WouldBlock means the
    /// reactor must retain the exact payload and metadata for another attempt.
    pub fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        #[cfg(all(test, feature = "stream-floor"))]
        if self
            .block_next_send
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.state.try_send((&self.socket).into(), transmit)
    }

    /// Unit-test-only kernel-send fault boundary, absent from executable builds.
    #[cfg(all(test, feature = "stream-floor"))]
    pub(crate) fn block_next_send(&self) {
        self.block_next_send
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl AsFd for FloorSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use everpty::sys::{poll, PollFd, PollFlags};

    #[test]
    fn loopback_preserves_payload_and_receive_metadata_without_runtime() {
        let config = noq_proto::EndpointConfig::default();
        let mut receiver = FloorSocket::new(
            UdpSocket::bind("127.0.0.1:0").expect("floor test fixture succeeds"),
            &config,
        )
        .expect("floor test fixture succeeds");
        let sender = FloorSocket::new(
            UdpSocket::bind("127.0.0.1:0").expect("floor test fixture succeeds"),
            &config,
        )
        .expect("floor test fixture succeeds");
        assert_eq!(
            receiver
                .receive()
                .expect_err("floor test fixture rejects operation")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let payload = b"floor socket fixture";
        sender
            .try_send(&Transmit {
                destination: receiver.local_addr().expect("floor test fixture succeeds"),
                ecn: None,
                contents: payload,
                segment_size: None,
                src_ip: None,
            })
            .expect("floor test fixture succeeds");
        {
            let mut fds = [PollFd::new(receiver.as_fd(), PollFlags::POLLIN)];
            assert_eq!(
                poll(&mut fds, Some(1_000)).expect("floor test fixture succeeds"),
                1
            );
        }
        assert_eq!(receiver.receive().expect("floor test fixture succeeds"), 1);
        let (meta, bytes) = receiver.packet(0).expect("floor test fixture succeeds");
        assert_eq!(bytes, payload);
        assert_eq!(
            meta.addr,
            sender.local_addr().expect("floor test fixture succeeds")
        );
        assert_eq!(meta.stride, payload.len());
        assert!(receiver.packet(1).is_none());
        assert_eq!(
            receiver
                .receive()
                .expect_err("floor test fixture rejects operation")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(
            receiver.packet(0).is_none(),
            "failed receive must not expose stale bytes"
        );
    }

    #[cfg(feature = "stream-floor")]
    #[test]
    fn stream_batch_cap_matches_ordinary_without_changing_datagram_floor() {
        let config = noq_proto::EndpointConfig::default();
        let generic = FloorSocket::new(UdpSocket::bind("127.0.0.1:0").expect("bind"), &config)
            .expect("generic socket");
        assert_eq!(
            generic.max_transmit_segments(),
            generic.state.max_gso_segments()
        );
        let stream =
            FloorSocket::new_stream_floor(UdpSocket::bind("127.0.0.1:0").expect("bind"), &config)
                .expect("stream socket");
        assert_eq!(
            stream.max_transmit_segments().get(),
            stream.state.max_gso_segments().get().min(10)
        );
    }

    #[test]
    fn raw_send_error_is_not_reported_as_acceptance() {
        let socket = FloorSocket::new(
            UdpSocket::bind("127.0.0.1:0").expect("floor test fixture succeeds"),
            &noq_proto::EndpointConfig::default(),
        )
        .expect("floor test fixture succeeds");
        let oversized = vec![0; 65_536];
        assert!(socket
            .try_send(&Transmit {
                destination: "127.0.0.1:12345"
                    .parse()
                    .expect("floor test fixture succeeds"),
                ecn: None,
                contents: &oversized,
                segment_size: None,
                src_ip: None,
            })
            .is_err());
    }
}
