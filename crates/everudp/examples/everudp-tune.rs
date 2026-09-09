//! Development-only transport-profile benchmark.
//!
//! This example executable is gated behind `everudp/tuning`; production
//! constructors and the shipped `everudp` binary cannot select these profiles.

use everssh::association::AssociationId;
use everudp::wire::{Ack, ConnectionRole, Kind};
use everudp::{
    ClientAssociation, ClientControlReceipt, ClientEndpoint, ClientHello, ClientIdentity,
    ClientInputFlush, ClientLink, ClientOutputReceipt, ControlDisposition,
    DevelopmentTransportTuning, GatewayAction, GatewayEndpoint, GatewayGeneration, GatewayIdentity,
    GatewayLifecycle, GatewayLink, GatewayReplaySlabs, InputOperation, InputReceipt,
    InvitationStore, Limits, OutputFlush, OutputOperation, QuicAckPolicy, ResumePosition,
};
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

const QUIET_WINDOW: Duration = Duration::from_millis(20);

#[derive(Debug, Clone, Copy)]
struct Arguments {
    tuning: DevelopmentTransportTuning,
    loss_percent: u8,
    trials: usize,
    seed: u64,
}

#[derive(Debug)]
struct TrialTimings {
    total_us: Vec<u64>,
    local_send_us: Vec<u64>,
    gateway_accept_us: Vec<u64>,
    gateway_echo_us: Vec<u64>,
}

impl TrialTimings {
    fn new(trials: usize) -> Self {
        Self {
            total_us: Vec::with_capacity(trials),
            local_send_us: Vec::with_capacity(trials),
            gateway_accept_us: Vec::with_capacity(trials),
            gateway_echo_us: Vec::with_capacity(trials),
        }
    }
}

#[derive(Debug)]
struct LossProxy {
    client_address: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<io::Result<ProxyCounts>>,
}

#[derive(Debug, Default)]
struct ProxyCounts {
    client_packets: u64,
    server_packets: u64,
    client_drops: u64,
    server_drops: u64,
}

#[derive(Debug, Clone, Copy)]
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn drops(&mut self, percent: u8) -> bool {
        percent != 0 && self.next() % 100 < u64::from(percent)
    }
}

impl LossProxy {
    async fn start(gateway_address: SocketAddr, loss_percent: u8, seed: u64) -> io::Result<Self> {
        let client_socket = UdpSocket::bind(loopback()).await?;
        let server_socket = UdpSocket::bind(loopback()).await?;
        let client_address = client_socket.local_addr()?;
        let (shutdown, mut stopping) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut from_client = vec![0_u8; 65_536].into_boxed_slice();
            let mut from_server = vec![0_u8; 65_536].into_boxed_slice();
            let mut client_peer = None;
            let mut client_rng = XorShift64::new(seed);
            let mut server_rng = XorShift64::new(seed ^ 0xa5a5_5a5a_d3c3_b4b4);
            let mut counts = ProxyCounts::default();
            loop {
                tokio::select! {
                    _ = &mut stopping => break,
                    packet = client_socket.recv_from(&mut from_client) => {
                        let (length, peer) = packet?;
                        client_peer = Some(peer);
                        counts.client_packets += 1;
                        if client_rng.drops(loss_percent) {
                            counts.client_drops += 1;
                        } else {
                            server_socket.send_to(&from_client[..length], gateway_address).await?;
                        }
                    }
                    packet = server_socket.recv_from(&mut from_server) => {
                        let (length, _) = packet?;
                        counts.server_packets += 1;
                        if server_rng.drops(loss_percent) {
                            counts.server_drops += 1;
                        } else if let Some(peer) = client_peer {
                            client_socket.send_to(&from_server[..length], peer).await?;
                        }
                    }
                }
            }
            Ok(counts)
        });
        Ok(Self {
            client_address,
            shutdown,
            task,
        })
    }

    async fn finish(self) -> io::Result<ProxyCounts> {
        let _ = self.shutdown.send(());
        self.task
            .await
            .map_err(|error| io::Error::other(format!("loss proxy task: {error}")))?
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = parse_arguments()?;
    let (timings, counts) = run(arguments).await?;
    print_json(arguments, &timings, &counts);
    Ok(())
}

async fn run(arguments: Arguments) -> Result<(TrialTimings, ProxyCounts), Box<dyn Error>> {
    let limits = Limits::default();
    let generation = GatewayGeneration::from_bytes([0x52; 16])?;
    let association_id = AssociationId::from_bytes([0x29; 16])?;
    let store = Arc::new(Mutex::new(InvitationStore::new(
        "tuning", generation, &limits,
    )?));
    let gateway_identity = GatewayIdentity::generate()?;
    let gateway = GatewayEndpoint::bind_for_development_tuning(
        loopback(),
        &gateway_identity,
        Arc::clone(&store),
        limits,
        arguments.tuning,
    )?;
    let proxy =
        LossProxy::start(gateway.local_addr(), arguments.loss_percent, arguments.seed).await?;
    let client_identity = ClientIdentity::generate()?;
    let ticket = store
        .lock()
        .map_err(|_| io::Error::other("invitation store lock poisoned"))?
        .issue(
            association_id,
            ConnectionRole::Writer,
            client_identity.spki_sha256(),
            everpty::sys::clock_monotonic_ms()?,
        )?;
    let hello = ClientHello::initial(
        association_id,
        generation,
        ConnectionRole::Writer,
        ResumePosition {
            input_epoch: 0,
            next_input: 0,
            output_epoch: 0,
            next_output: 0,
            delivered_output_ack: 0,
        },
        ticket.token().clone(),
    )?;
    let client = ClientEndpoint::bind_for_development_tuning(
        loopback(),
        &client_identity,
        gateway_identity.spki_sha256(),
        limits,
        arguments.tuning,
    )?;
    let (admitted, session) = tokio::join!(
        gateway.accept_initial(),
        client.connect_initial(proxy.client_address, &hello)
    );
    let admitted = admitted?;
    let session = session?;

    let server = async {
        let mut lifecycle = GatewayLifecycle::new(&limits)?;
        let mut slabs = GatewayReplaySlabs::new(&limits)?;
        let (link, action) =
            GatewayLink::accept_initial(admitted, &mut lifecycle, &mut slabs, limits).await?;
        if action != GatewayAction::CommitEverptyWriter {
            return Err(io::Error::other("gateway did not commit the writer").into());
        }
        Ok::<_, Box<dyn Error>>((link, lifecycle, slabs))
    };
    let peer = async {
        let association =
            ClientAssociation::new(association_id, generation, ConnectionRole::Writer, limits)?;
        Ok::<_, Box<dyn Error>>(ClientLink::finish_initial(session, association, limits).await?)
    };
    let (server, peer) = tokio::join!(server, peer);
    let (mut gateway_link, _lifecycle, mut slabs) = server?;
    let mut client_link = peer?;
    let mut timings = TrialTimings::new(arguments.trials);

    for trial in 0..arguments.trials {
        let expected = [b'a' + u8::try_from(trial % 26)?];
        let started = Instant::now();
        client_link.association_mut().queue_input(&expected)?;
        if client_link.flush_input().await? != (ClientInputFlush::Sent { records: 1 }) {
            return Err(io::Error::other("input operation did not flush exactly once").into());
        }
        let local_send = started.elapsed();

        let mut accepted = [0_u8; 1];
        let mut accepted_calls = 0_u8;
        let input_receipt = gateway_link
            .receive_input(&mut slabs, |operation| {
                let InputOperation::Bytes(bytes) = operation else {
                    return Err(io::Error::other("non-byte tuning input"));
                };
                if bytes != expected || accepted_calls != 0 {
                    return Err(io::Error::other("wrong or duplicate tuning input"));
                }
                accepted.copy_from_slice(bytes);
                accepted_calls += 1;
                Ok(())
            })
            .await?;
        let next_expected = u64::try_from(trial)?
            .checked_add(1)
            .ok_or_else(|| io::Error::other("tuning sequence overflowed"))?;
        if input_receipt
            != (InputReceipt::Delivered {
                kind: Kind::Input,
                sequence: u64::try_from(trial)?,
                acknowledgement: next_expected,
            })
            || accepted_calls != 1
            || accepted != expected
        {
            return Err(io::Error::other("gateway accepted the wrong input sequence").into());
        }
        let gateway_accept = started.elapsed();
        if gateway_link.flush_control(&mut slabs).await? != 1 {
            return Err(io::Error::other("gateway emitted the wrong input ACK count").into());
        }
        slabs.push_output(Kind::Output, &accepted)?;
        if gateway_link.flush_output(&slabs).await? != (OutputFlush::Sent { records: 1 }) {
            return Err(io::Error::other("gateway emitted the wrong output count").into());
        }
        let gateway_echo = started.elapsed();

        match client_link.receive_control().await? {
            ClientControlReceipt::InputAck(Ack {
                epoch: 0,
                next_expected: observed,
            }) if observed == next_expected => {}
            _ => return Err(io::Error::other("client received the wrong input ACK").into()),
        }
        let mut sink_calls = 0_u8;
        let mut sink_elapsed = None;
        let output_receipt = client_link
            .receive_output(|operation| {
                let OutputOperation::Bytes(bytes) = operation else {
                    return Err(io::Error::other("non-byte tuning output"));
                };
                if bytes != expected || sink_calls != 0 {
                    return Err(io::Error::other("wrong or duplicate tuning output"));
                }
                sink_calls += 1;
                sink_elapsed = Some(started.elapsed());
                Ok(())
            })
            .await?;
        if output_receipt
            != (ClientOutputReceipt::Delivered {
                kind: Kind::Output,
                sequence: u64::try_from(trial)?,
                acknowledgement: next_expected,
            })
            || sink_calls != 1
        {
            return Err(io::Error::other("local sink accepted the wrong output sequence").into());
        }
        let total = sink_elapsed.ok_or_else(|| io::Error::other("sink time missing"))?;
        if client_link.flush_control().await? != 1 {
            return Err(io::Error::other("client emitted the wrong output ACK count").into());
        }
        match gateway_link.receive_control(&mut slabs).await? {
            everudp::ControlReceipt::OutputAck {
                acknowledgement:
                    Ack {
                        epoch: 0,
                        next_expected: observed,
                    },
                disposition: ControlDisposition::Applied,
            } if observed == next_expected => {}
            _ => return Err(io::Error::other("gateway received the wrong output ACK").into()),
        }
        timings.total_us.push(as_micros(total)?);
        timings.local_send_us.push(as_micros(local_send)?);
        timings.gateway_accept_us.push(as_micros(gateway_accept)?);
        timings.gateway_echo_us.push(as_micros(gateway_echo)?);
    }

    match tokio::time::timeout(
        QUIET_WINDOW,
        client_link.receive_output(|_| Err(io::Error::other("unexpected extra output"))),
    )
    .await
    {
        Err(_) => {}
        Ok(_) => return Err(io::Error::other("output arrived during the quiet window").into()),
    }

    client_link.close();
    gateway_link.close();
    let counts = proxy.finish().await?;
    Ok((timings, counts))
}

fn as_micros(duration: Duration) -> Result<u64, io::Error> {
    u64::try_from(duration.as_micros()).map_err(|_| io::Error::other("duration overflow"))
}

fn parse_arguments() -> Result<Arguments, Box<dyn Error>> {
    let values = std::env::args().skip(1).collect::<Vec<_>>();
    if values.len() != 6 {
        return Err(io::Error::other(
            "usage: everudp-tune INITIAL_RTT_MS ACK_POLICY GSO LOSS_PERCENT TRIALS SEED",
        )
        .into());
    }
    let initial_rtt_ms = values[0].parse::<u64>()?;
    let ack_policy = match values[1].as_str() {
        "off" => QuicAckPolicy::Disabled,
        "every-1ms" => QuicAckPolicy::EveryPacket1ms,
        "every-other-5ms" => QuicAckPolicy::EveryOtherPacket5ms,
        _ => return Err(io::Error::other("unknown ACK policy").into()),
    };
    let segmentation_offload = match values[2].as_str() {
        "off" => false,
        "on" => true,
        _ => return Err(io::Error::other("GSO must be on or off").into()),
    };
    let loss_percent = values[3].parse::<u8>()?;
    if !matches!(loss_percent, 0 | 5) {
        return Err(io::Error::other("loss must be 0 or 5 percent").into());
    }
    let trials = values[4].parse::<usize>()?;
    if trials == 0 || trials > 10_000 {
        return Err(io::Error::other("trials must be in [1, 10000]").into());
    }
    let seed = values[5].parse::<u64>()?;
    if seed == 0 {
        return Err(io::Error::other("seed must be nonzero").into());
    }
    let tuning = DevelopmentTransportTuning::new(initial_rtt_ms, ack_policy, segmentation_offload)
        .ok_or_else(|| io::Error::other("profile is outside the registered tuning matrix"))?;
    Ok(Arguments {
        tuning,
        loss_percent,
        trials,
        seed,
    })
}

fn print_json(arguments: Arguments, timings: &TrialTimings, counts: &ProxyCounts) {
    println!(
        "{{\"schema_version\":1,\"correct\":true,\"initial_rtt_ms\":{},\"ack_policy\":\"{}\",\"gso\":{},\"loss_percent\":{},\"trials\":{},\"seed\":{},\"proxy\":{{\"client_packets\":{},\"server_packets\":{},\"client_drops\":{},\"server_drops\":{}}},\"total_us\":{},\"local_send_us\":{},\"gateway_accept_us\":{},\"gateway_echo_us\":{}}}",
        arguments.tuning.initial_rtt_ms(),
        ack_label(arguments.tuning.ack_policy()),
        arguments.tuning.segmentation_offload(),
        arguments.loss_percent,
        arguments.trials,
        arguments.seed,
        counts.client_packets,
        counts.server_packets,
        counts.client_drops,
        counts.server_drops,
        json_numbers(&timings.total_us),
        json_numbers(&timings.local_send_us),
        json_numbers(&timings.gateway_accept_us),
        json_numbers(&timings.gateway_echo_us),
    );
}

fn ack_label(policy: QuicAckPolicy) -> &'static str {
    match policy {
        QuicAckPolicy::Disabled => "off",
        QuicAckPolicy::EveryPacket1ms => "every-1ms",
        QuicAckPolicy::EveryOtherPacket5ms => "every-other-5ms",
        QuicAckPolicy::EveryOtherPacket1ms => "every-other-1ms-experiment",
    }
}

fn json_numbers(values: &[u64]) -> String {
    let mut output = String::with_capacity(values.len().saturating_mul(8).saturating_add(2));
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str(&value.to_string());
    }
    output.push(']');
    output
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}
