use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct FakeAgent {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeAgent {
    pub fn start(path: &Path, identities: u32) -> Self {
        let listener = UnixListener::bind(path).expect("bind fake agent");
        listener.set_nonblocking(true).expect("nonblocking agent");
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .ok();
                        let mut request = [0; 5];
                        if stream.read_exact(&mut request).is_err() || request != [0, 0, 0, 1, 11] {
                            continue;
                        }
                        let mut reply = vec![12];
                        reply.extend_from_slice(&identities.to_be_bytes());
                        for _ in 0..identities {
                            reply.extend_from_slice(&1_u32.to_be_bytes());
                            reply.push(b'k');
                            reply.extend_from_slice(&0_u32.to_be_bytes());
                        }
                        let _ = stream.write_all(&(reply.len() as u32).to_be_bytes());
                        let _ = stream.write_all(&reply);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for FakeAgent {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
