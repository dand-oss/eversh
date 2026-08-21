//! Binary-level test: drives the actual `noq-m0 server` process (no ssh) with
//! an in-process client standing in for the proxy's QUIC half. Reproduces the
//! sshd interaction pattern (banner before any uplink, delayed replies) that
//! must survive the bridge.

use noq_m0::config::Limits;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_noq-m0")
}

/// Echo TCP target: sends a banner immediately, then echoes each read after a
/// delay (mimics sshd sending KEXINIT after receiving ours).
struct EchoTarget {
    port: u16,
}
impl EchoTarget {
    fn spawn() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            let mut c = std::io::BufWriter::new(c);
            c.write_all(b"SSH-2.0-EchoTarget\r\n").unwrap();
            c.flush().unwrap();
            let mut buf = [0u8; 4096];
            loop {
                match c.get_mut().read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        std::thread::sleep(Duration::from_millis(100));
                        c.write_all(b"reply:").unwrap();
                        c.write_all(&buf[..n]).unwrap();
                        c.flush().unwrap();
                    }
                }
            }
        });
        Self { port }
    }
}

fn read_record(stream: &mut impl Read) -> String {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        assert_eq!(stream.read(&mut b).unwrap(), 1);
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
        assert!(line.len() < 4096, "record too large");
    }
    String::from_utf8(line).unwrap()
}

fn decode_hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[tokio::test]
async fn server_process_bridge_survives_banner_then_delayed_echo() {
    let target = EchoTarget::spawn();

    // Server child: authorized port over the inherited stdin pipe.
    let mut server: Child = Command::new(bin())
        .arg("server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    server
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{}\n", target.port).as_bytes())
        .unwrap();
    let mut server_stdout = server.stdout.take().unwrap();
    let record = read_record(&mut server_stdout);
    drop(server_stdout);
    let parts: Vec<&str> = record.split(' ').collect();
    assert_eq!(&parts[0..2], &["m0", "v1"]);
    let udp_port: u16 = parts[2].parse().unwrap();
    let spki = decode_hex(parts[3]);
    let token = decode_hex(parts[4]);

    let l = Limits::default();
    let ep = noq_m0::spike::client_endpoint(spki, &l).unwrap();
    let (_conn, mut send, mut recv) = noq_m0::spike::client_connect_auth(
        &ep,
        format!("127.0.0.1:{udp_port}").parse().unwrap(),
        &token,
        target.port,
        &l,
    )
    .await
    .expect("auth");

    // Banner arrives with no uplink data at all.
    let mut banner = vec![0u8; 64];
    let mut got = 0usize;
    tokio::time::timeout(Duration::from_secs(5), async {
        while got < 19 {
            match recv.read(&mut banner[got..]).await.unwrap() {
                Some(n) => got += n,
                None => break,
            }
        }
    })
    .await
    .expect("banner deadline");
    assert!(
        banner[..got].starts_with(b"SSH-2.0-EchoTarget"),
        "banner: {:?}",
        &banner[..got]
    );

    // KEXINIT-like uplink; delayed reply comes back.
    send.write_all(&[0x41u8; 1200]).await.unwrap();
    let mut chunk = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut chunk))
        .await
        .expect("reply deadline")
        .unwrap()
        .expect("stream open");
    assert_eq!(&chunk[..6], b"reply:");
    assert_eq!(n, 6 + 1200, "echoed payload size");

    // Half-close uplink; server child must exit finitely.
    send.finish().unwrap();
    let mut server = server;
    let status = tokio::task::spawn_blocking(move || server.wait())
        .await
        .expect("join");
    assert!(status.is_ok(), "server child exits within lease+drain");
}

#[test]
fn proxy_peer_process_end_to_end_banner_and_echo() {
    let target = EchoTarget::spawn();

    let mut server: Child = Command::new(bin())
        .arg("server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    server
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{}\n", target.port).as_bytes())
        .unwrap();
    let mut server_stdout = server.stdout.take().unwrap();
    let record = read_record(&mut server_stdout);
    drop(server_stdout);

    let mut proxy: Child = Command::new(bin())
        .arg("proxy-peer")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut proxy_stderr = proxy.stderr.take().unwrap();
    let mut proxy_stdin = proxy.stdin.take().unwrap();
    write!(proxy_stdin, "{}\n{}\n", record, target.port).unwrap();
    proxy_stdin.flush().unwrap();

    let mut proxy_stdout = proxy.stdout.take().unwrap();
    // Banner first, with no uplink written yet.
    let mut banner = vec![0u8; 64];
    let mut got = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    while got < 19 && Instant::now() < deadline {
        let n = proxy_stdout.read(&mut banner[got..]).unwrap();
        assert_ne!(n, 0, "proxy stdout EOF before banner");
        got += n;
    }
    assert!(banner[..got].starts_with(b"SSH-2.0-EchoTarget"));

    // Uplink payload, delayed echo down.
    proxy_stdin.write_all(&[0x42u8; 500]).unwrap();
    proxy_stdin.flush().unwrap();
    let mut reply = [0u8; 4096];
    let mut rn = 0;
    while rn < 6 + 500 {
        let n = proxy_stdout.read(&mut reply[rn..]).unwrap();
        assert_ne!(n, 0);
        rn += n;
    }
    assert_eq!(&reply[..6], b"reply:");
    assert_eq!(&reply[6..506], &[0x42u8; 500][..]);

    // Half-close stdin: the whole chain terminates finitely.
    drop(proxy_stdin);
    let mut rest = Vec::new();
    proxy_stdout.read_to_end(&mut rest).unwrap();
    let status = proxy.wait().unwrap();
    let mut errbuf = String::new();
    let _ = proxy_stderr.read_to_string(&mut errbuf);
    assert!(status.success(), "proxy-peer: {errbuf}");
    let server_status = server.wait().unwrap();
    assert!(server_status.success());
}
use std::time::Instant;
