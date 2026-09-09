//! Opt-in fixed-label terminal diagnostics; never carries protocol payloads.
#[cfg(feature = "path-diagnostics")]
pub(crate) fn record(event: &'static str) {
    record_line(event);
}

#[cfg(feature = "path-diagnostics")]
pub(crate) fn connection_counters(event: &'static str, connection: &noq::Connection) {
    let stats = connection.stats();
    record_line(&format!(
        "{event} udp_tx={} udp_rx={} stream_tx={} stream_rx={} ack_tx={} ack_rx={} crypto_tx={} crypto_rx={} lost={}",
        stats.udp_tx.datagrams, stats.udp_rx.datagrams,
        stats.frame_tx.stream, stats.frame_rx.stream,
        stats.frame_tx.acks, stats.frame_rx.acks,
        stats.frame_tx.crypto, stats.frame_rx.crypto, stats.lost_packets,
    ));
}

#[cfg(feature = "path-diagnostics")]
fn record_line(event: &str) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let Some(path) = std::env::var_os("EVERUDP_EXIT_TRACE") else {
        return;
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        let line = format!("{} {event}\n", std::process::id());
        if file
            .metadata()
            .is_ok_and(|metadata| metadata.len().saturating_add(line.len() as u64) <= 8192)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

#[cfg(feature = "path-diagnostics")]
pub(crate) fn install_panic_location_hook() {
    if std::env::var_os("EVERUDP_EXIT_TRACE").is_none() {
        return;
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(location) = info.location() {
            record_line(&format!(
                "gateway-panic-location {}:{}",
                location.file(),
                location.line()
            ));
            let backtrace = std::backtrace::Backtrace::force_capture().to_string();
            for line in backtrace.lines().take(40) {
                record_line(&format!("gateway-panic-frame {}", line.trim()));
            }
        }
        previous(info);
    }));
}

#[cfg(not(feature = "path-diagnostics"))]
pub(crate) fn record(_event: &'static str) {}
