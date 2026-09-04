//! everudp spike CLI. Private research roles only.

use everudp_spike::frame::{decode, Echo, Frame, Input, MTU_CEILING};
use everudp_spike::quic;
use everudp_spike::state::{EchoPolicy, PredictionState};
use everudp_spike::transport::{
    self, key_from_half, quic_bench, quic_server_endpoint_loop, summarize, udp_bench, udp_server,
};
use std::net::SocketAddr;

fn usage() -> ! {
    eprintln!(
        "usage: everudp-spike <role>\n\
         roles:\n\
           bench --transport udp|quic --prediction on|off --trials N [--host HOST]\n\
           udp-server --bind ADDR --key-hex 16HEX\n\
           udp-pty-server --bind ADDR --key-hex 16HEX --echo-command CMD\n\
           quic-server --bind ADDR\n\
           reach --transport udp|quic --host HOST [--key-hex 16HEX]\n\
           oracle"
    );
    std::process::exit(2);
}

fn arg(name: &str) -> String {
    std::env::args()
        .position(|a| a == name)
        .and_then(|i| std::env::args().nth(i + 1))
        .unwrap_or_else(|| usage())
}

fn opt_arg(name: &str, default: &str) -> String {
    std::env::args()
        .position(|a| a == name)
        .and_then(|i| std::env::args().nth(i + 1))
        .unwrap_or_else(|| default.to_string())
}

fn addr(value: &str) -> SocketAddr {
    value.parse().unwrap_or_else(|_| usage())
}

fn half_key(hex: &str) -> [u8; 8] {
    let bytes = hex.as_bytes();
    if bytes.len() != 16 {
        usage();
    }
    let mut out = [0u8; 8];
    for (i, chunk) in bytes.chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).unwrap_or_default();
        out[i] = u8::from_str_radix(text, 16).unwrap_or_else(|_| usage());
    }
    out
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = runtime.block_on(async {
        let role = std::env::args().nth(1).unwrap_or_default();
        match role.as_str() {
            "bench" => bench().await,
            "udp-server" => {
                let bind = addr(&arg("--bind"));
                let key = half_key(&arg("--key-hex"));
                udp_server(bind, key).await.map_err(|e| e.to_string())
            }
            "udp-pty-server" => {
                let bind = addr(&arg("--bind"));
                let key = half_key(&arg("--key-hex"));
                let command = arg("--echo-command");
                transport::udp_pty_server(bind, key, command)
                    .await
                    .map_err(|e| e.to_string())
            }
            "quic-server" => {
                let bind = addr(&arg("--bind"));
                let identity = quic::generate_identity();
                println!(
                    "spki={}",
                    identity
                        .spki_sha256
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                );
                let endpoint = quic::server_endpoint(&identity, bind).map_err(|e| e.to_string())?;
                quic_server_endpoint_loop(endpoint)
                    .await
                    .map_err(|e| e.to_string())
            }
            "reach" => reach().await,
            "oracle" => oracle().map_err(|e| e.to_string()),
            _ => usage(),
        }
    });
    if let Err(message) = code {
        eprintln!("everudp-spike: {message}");
        std::process::exit(1);
    }
}

async fn bench() -> Result<(), String> {
    let transport_name = arg("--transport");
    let prediction = match arg("--prediction").as_str() {
        "on" => true,
        "off" => false,
        _ => usage(),
    };
    let trials: usize = arg("--trials").parse().unwrap_or_else(|_| usage());
    let host = opt_arg("--host", "127.0.0.1:0");
    let host_addr: SocketAddr = host.parse().unwrap_or_else(|_| usage());
    let trials = match transport_name.as_str() {
        "udp" => {
            let key = [7u8; 8];
            let server_addr = if std::env::args().any(|a| a == "--server") {
                arg("--server").parse().unwrap_or_else(|_| usage())
            } else {
                spawn_udp_server(host_addr, key).await?
            };
            udp_bench(server_addr, key, prediction, trials)
                .await
                .map_err(|e| e.to_string())?
        }
        "quic" => {
            if std::env::args().any(|a| a == "--server") {
                let server_addr: SocketAddr = arg("--server").parse().unwrap_or_else(|_| usage());
                let spki = opt_arg("--spki-hex", "");
                let mut pin = [0u8; 32];
                if spki.len() == 64 {
                    for i in 0..32 {
                        pin[i] = u8::from_str_radix(&spki[i * 2..i * 2 + 2], 16)
                            .map_err(|_| "bad spki hex".to_string())?;
                    }
                } else {
                    usage();
                }
                let bind: SocketAddr = if server_addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                }
                .parse()
                .unwrap();
                let client = quic::client_endpoint(pin, bind).map_err(|e| e.to_string())?;
                let result = quic_bench(&client, server_addr, prediction, trials)
                    .await
                    .map_err(|e| e.to_string())?;
                report(&transport_name, prediction, result);
                return Ok(());
            }
            let bind: SocketAddr = if host_addr.is_ipv4() {
                "127.0.0.1:0"
            } else {
                "[::1]:0"
            }
            .parse()
            .unwrap();
            let identity = quic::generate_identity();
            let server = quic::server_endpoint(&identity, bind).map_err(|e| e.to_string())?;
            let server_addr = server.local_addr().map_err(|e| e.to_string())?;
            tokio::spawn(async move {
                let _ = quic_server_endpoint_loop(server).await;
            });
            let client =
                quic::client_endpoint(identity.spki_sha256, bind).map_err(|e| e.to_string())?;
            quic_bench(&client, server_addr, prediction, trials)
                .await
                .map_err(|e| e.to_string())?
        }
        _ => usage(),
    };
    report(&transport_name, prediction, trials);
    Ok(())
}

fn report(transport_name: &str, prediction: bool, trials: Vec<transport::Trial>) {
    let (median, p95, max, mean) = summarize(&trials);
    let samples: Vec<u128> = trials.iter().map(|trial| trial.correct_render_us).collect();
    println!(
        "{{\"transport\":\"{transport_name}\",\"prediction\":{prediction},\"trials\":{},\"median_us\":{median},\"p95_us\":{p95},\"max_us\":{max},\"mean_us\":{mean:.3},\"retransmits\":{},\"samples\":{samples:?}}}",
        trials.len(),
        trials.iter().map(|t| t.retransmits).sum::<u32>(),
        samples = samples
    );
}

async fn spawn_udp_server(bind: SocketAddr, key: [u8; 8]) -> Result<SocketAddr, String> {
    let server = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|e| e.to_string())?;
    let addr = server.local_addr().map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = run_udp_echo(server, key).await;
    });
    Ok(addr)
}

async fn run_udp_echo(socket: tokio::net::UdpSocket, key: [u8; 8]) -> std::io::Result<()> {
    use everudp_spike::aead::Substrate;
    let mut server = Substrate::new(
        key_from_half(key),
        transport::SESSION_PREFIX,
        transport::SERVER_COUNTER_BASE,
    );
    let mut packet = [0u8; MTU_CEILING];
    let mut wire = Vec::with_capacity(MTU_CEILING);
    loop {
        let (len, from) = socket.recv_from(&mut packet).await?;
        let plaintext = match server.open(&packet[..len], b"everudp-spike-v1") {
            Ok(plaintext) => plaintext,
            Err(_) => continue,
        };
        let Frame::Input(Input { seq, bytes, .. }) =
            decode(&plaintext).ok().unwrap_or(Frame::Keepalive)
        else {
            continue;
        };
        Echo { ack: seq, bytes }.encode(&mut wire);
        let sealed = server.seal(&wire, b"everudp-spike-v1");
        socket.send_to(&sealed, from).await?;
    }
}

async fn reach() -> Result<(), String> {
    let transport_name = arg("--transport");
    let server_addr: SocketAddr = arg("--host").parse().unwrap_or_else(|_| usage());
    match transport_name.as_str() {
        "udp" => {
            let key = half_key(&opt_arg("--key-hex", "0707070707070707"));
            let trials = udp_bench(server_addr, key, false, 1)
                .await
                .map_err(|e| e.to_string())?;
            println!(
                "{{\"reach\":true,\"transport\":\"udp\",\"us\":{}}}",
                trials[0].correct_render_us
            );
        }
        "quic" => {
            let spki_hex = arg("--spki-hex");
            let mut pin = [0u8; 32];
            let hex = spki_hex.as_bytes();
            if hex.len() != 64 {
                return Err("spki hex must be 64 characters".into());
            }
            for i in 0..32 {
                pin[i] = u8::from_str_radix(&spki_hex[i * 2..i * 2 + 2], 16)
                    .map_err(|_| "bad spki hex")?;
            }
            let bind: SocketAddr = if server_addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()
            .unwrap();
            let endpoint = quic::client_endpoint(pin, bind).map_err(|e| e.to_string())?;
            let trials = quic_bench(&endpoint, server_addr, false, 1)
                .await
                .map_err(|e| e.to_string())?;
            println!(
                "{{\"reach\":true,\"transport\":\"quic\",\"us\":{}}}",
                trials[0].correct_render_us
            );
        }
        _ => usage(),
    }
    Ok(())
}

fn oracle() -> Result<(), String> {
    let workloads: [(&str, &[u8]); 4] = [
        ("echo", b"hello everudp\n"),
        ("resize", b"\x1b[8;24;80tready\x1b[8;30;100tafter\n"),
        ("full-screen", b"\x1b[2J\x1b[Htitle\r\nrow-a\r\nrow-b\x1b[H"),
        ("tmux", b"\x1b]0;tmux\x07\x1b[?1049hpane-1\r\n\x1b[?1049l"),
    ];
    for (name, bytes) in workloads {
        let mut state = PredictionState::new(1, EchoPolicy::Predict);
        let (seq, _) = state.send(bytes);
        let reconciliation = state.reconcile(seq, bytes);
        if state.confirmed_bytes != bytes {
            return Err(format!("{name}: authoritative state mismatch"));
        }
        if format!("{reconciliation:?}").contains("Corrected") {
            return Err(format!("{name}: false correction"));
        }
    }
    let mut password = PredictionState::new(1, EchoPolicy::NoEcho);
    let (seq, displayed) = password.send(b"secret");
    if displayed || password.predicted_echo_displays != 0 {
        return Err("no-echo workload displayed a prediction".into());
    }
    password.reconcile(seq, b"secret");
    if password.predicted_echo_displays != 0 {
        return Err("no-echo reconciliation displayed a prediction".into());
    }
    println!("oracle: PASS echo/resize/full-screen/tmux/no-echo");
    Ok(())
}

#[allow(dead_code)]
fn unused_transport_import() {
    let _ = transport::EPOCH;
}
