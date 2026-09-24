//! Validated, bounded UDP port range selected by the operator (design §5).
//!
//! A [`UdpPortRange`] is the typed form of `--udp-port-range START:END`. It is
//! validated once at the process edge with the same rules the server-side
//! [`crate::transport::UdpBindPolicy::RouteSelectedPortRange`] enforces
//! (start at least one, start not after end, inclusive width within
//! [`Limits::max_udp_port_span`]), then carried as integers so every later
//! rendering (`START:END`) is canonical and injection-free by construction.

use crate::error::{Error, UdpPolicyViolation};
use crate::limits::Limits;
use crate::role_protocol::StartUdpPolicy;
use crate::transport::UdpBindPolicy;
use std::net::{IpAddr, SocketAddr, UdpSocket};

/// Longest canonical `START:END` text (`65535:65535`).
pub const UDP_PORT_RANGE_TEXT_MAX: usize = 11;

/// An inclusive, validated remote UDP port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPortRange {
    start: u16,
    end: u16,
}

impl UdpPortRange {
    /// Validate an inclusive range against `limits`.
    pub fn new(start: u16, end: u16, limits: &Limits) -> Result<Self, Error> {
        limits.validate()?;
        crate::transport::validate_range(start, end, limits)?;
        Ok(Self { start, end })
    }

    /// Parse the canonical `START:END` operator form: two unsigned decimal
    /// ports without signs, whitespace, or leading zeros, joined by one
    /// colon. Malformed text is rejected before any range rule is applied.
    pub fn parse(text: &str, limits: &Limits) -> Result<Self, Error> {
        let malformed = || Error::InvalidUdpPolicy(UdpPolicyViolation::RangeMalformed);
        if text.len() > UDP_PORT_RANGE_TEXT_MAX {
            return Err(malformed());
        }
        let (start, end) = text.split_once(':').ok_or_else(malformed)?;
        let start = parse_canonical_port(start).ok_or_else(malformed)?;
        let end = parse_canonical_port(end).ok_or_else(malformed)?;
        Self::new(start, end, limits)
    }

    pub fn start(self) -> u16 {
        self.start
    }

    pub fn end(self) -> u16 {
        self.end
    }

    /// The server-side bind policy for this range.
    pub fn bind_policy(self) -> UdpBindPolicy {
        UdpBindPolicy::RouteSelectedPortRange {
            start: self.start,
            end: self.end,
        }
    }

    /// The protected parent-to-server start policy for this range.
    pub fn start_policy(self) -> StartUdpPolicy {
        StartUdpPolicy::RouteSelectedPortRange {
            start: self.start,
            end: self.end,
        }
    }

    /// Bind the first free port of this range on exactly `ip`, in ascending
    /// order. A port in use moves on to the next; any other bind failure is
    /// returned immediately; a fully occupied range is
    /// [`Error::PortRangeExhausted`].
    pub fn bind_first_free(self, ip: IpAddr) -> Result<UdpSocket, Error> {
        for port in self.start..=self.end {
            match UdpSocket::bind(SocketAddr::new(ip, port)) {
                Ok(socket) => return Ok(socket),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
                Err(error) => return Err(Error::UdpBind(error)),
            }
        }
        Err(Error::PortRangeExhausted)
    }
}

impl std::fmt::Display for UdpPortRange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.start, self.end)
    }
}

fn parse_canonical_port(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port = text.parse::<u16>().ok()?;
    (port.to_string() == text).then_some(port)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn violation(result: Result<UdpPortRange, Error>) -> UdpPolicyViolation {
        match result {
            Err(Error::InvalidUdpPolicy(violation)) => violation,
            other => panic!("expected a UDP policy violation, got {other:?}"),
        }
    }

    #[test]
    fn parses_the_canonical_operator_form() {
        let limits = Limits::default();
        let range = UdpPortRange::parse("60000:60010", &limits).unwrap();
        assert_eq!((range.start(), range.end()), (60_000, 60_010));
        assert_eq!(range.to_string(), "60000:60010");
        let single = UdpPortRange::parse("1:1", &limits).unwrap();
        assert_eq!((single.start(), single.end()), (1, 1));
        assert_eq!(
            range.bind_policy(),
            UdpBindPolicy::RouteSelectedPortRange {
                start: 60_000,
                end: 60_010
            }
        );
        assert_eq!(
            range.start_policy(),
            StartUdpPolicy::RouteSelectedPortRange {
                start: 60_000,
                end: 60_010
            }
        );
    }

    #[test]
    fn applies_the_server_range_rules() {
        let limits = Limits::default();
        assert_eq!(
            violation(UdpPortRange::parse("0:10", &limits)),
            UdpPolicyViolation::RangeStartsAtZero
        );
        assert_eq!(
            violation(UdpPortRange::parse("60010:60000", &limits)),
            UdpPolicyViolation::RangeInverted
        );
        let widest = limits.max_udp_port_span as u16;
        assert!(UdpPortRange::parse(&format!("1:{widest}"), &limits).is_ok());
        assert_eq!(
            violation(UdpPortRange::parse(&format!("1:{}", widest + 1), &limits)),
            UdpPolicyViolation::RangeTooWide
        );
        assert_eq!(
            violation(UdpPortRange::new(1, 65_535, &limits)),
            UdpPolicyViolation::RangeTooWide
        );
    }

    #[test]
    fn rejects_malformed_text() {
        let limits = Limits::default();
        for text in [
            "",
            ":",
            "60000",
            "60000:",
            ":60010",
            "60000-60010",
            "60000:60010:1",
            " 60000:60010",
            "60000:60010 ",
            "+1:2",
            "01:2",
            "1:02",
            "65536:65537",
            "a:b",
            "60000:6001x",
            "１:2",
            "123456:1234567",
        ] {
            assert_eq!(
                violation(UdpPortRange::parse(text, &limits)),
                UdpPolicyViolation::RangeMalformed,
                "{text:?}"
            );
        }
    }

    #[test]
    fn binds_the_first_free_loopback_port_and_reports_exhaustion() {
        let limits = Limits::default();
        let loopback = IpAddr::from([127, 0, 0, 1]);
        let occupied = UdpSocket::bind((loopback, 0)).unwrap();
        let port = occupied.local_addr().unwrap().port();
        let exhausted = UdpPortRange::new(port, port, &limits).unwrap();
        assert!(matches!(
            exhausted.bind_first_free(loopback),
            Err(Error::PortRangeExhausted)
        ));
        drop(occupied);
        let bound = exhausted.bind_first_free(loopback).unwrap();
        assert_eq!(bound.local_addr().unwrap(), SocketAddr::new(loopback, port));
    }
}
