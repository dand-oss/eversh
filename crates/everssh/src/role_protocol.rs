//! Pure codecs for the authenticated SSH process boundary.

use crate::admission::AuthenticatedConnection;
use crate::error::Error;
use crate::limits::Limits;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Maximum canonical `client-ip client-port server-ip server-port` bytes.
pub const SSH_CONNECTION_MAX: usize = 91;
pub const SERVER_START_MAX: usize = 512;
pub const RELEASE_RECORD: &[u8] = b"everssh-release v1\n";

/// The only UDP policies that may cross the protected parent/server pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartUdpPolicy {
    RouteSelected,
    RouteSelectedPortRange { start: u16, end: u16 },
    Explicit(SocketAddr),
}

/// Non-secret inputs delivered from the authenticated bootstrap parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerStartRecord {
    authenticated: AuthenticatedConnection,
    policy: StartUdpPolicy,
}

impl ServerStartRecord {
    pub fn try_new(
        authenticated: AuthenticatedConnection,
        policy: StartUdpPolicy,
        limits: &Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        validate_record_connection(authenticated)?;
        validate_start_policy(authenticated.peer(), policy, limits)?;
        Ok(Self {
            authenticated,
            policy,
        })
    }

    pub fn authenticated(&self) -> AuthenticatedConnection {
        self.authenticated
    }

    pub fn policy(&self) -> StartUdpPolicy {
        self.policy
    }

    pub fn encode(&self) -> String {
        let peer = self.authenticated.peer();
        let local = self.authenticated.local();
        let mut output = String::with_capacity(SERVER_START_MAX);
        output.push_str("everssh-start v1 ");
        output.push_str(&peer.ip().to_string());
        output.push(' ');
        output.push_str(&peer.port().to_string());
        output.push(' ');
        output.push_str(&local.ip().to_string());
        output.push(' ');
        output.push_str(&local.port().to_string());
        match self.policy {
            StartUdpPolicy::RouteSelected => output.push_str(" route\n"),
            StartUdpPolicy::RouteSelectedPortRange { start, end } => {
                output.push_str(" range ");
                output.push_str(&start.to_string());
                output.push(' ');
                output.push_str(&end.to_string());
                output.push('\n');
            }
            StartUdpPolicy::Explicit(address) => {
                output.push_str(" explicit ");
                output.push_str(&address.ip().to_string());
                output.push(' ');
                output.push_str(&address.port().to_string());
                output.push('\n');
            }
        }
        debug_assert!(output.len() <= SERVER_START_MAX);
        output
    }

    /// Parse one complete line without its LF terminator.
    pub fn parse(line: &str, limits: &Limits) -> Result<Self, Error> {
        if line.is_empty() || line.len().saturating_add(1) > SERVER_START_MAX {
            return Err(Error::ServerStartMalformed);
        }
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.iter().any(|field| field.is_empty()) || fields.len() < 7 {
            return Err(Error::ServerStartMalformed);
        }
        if fields[0] != "everssh-start" || fields[1] != "v1" {
            return Err(Error::ServerStartMalformed);
        }
        let authenticated = connection_from_fields(&fields[2..6])?;
        let policy = match fields.as_slice() {
            [_, _, _, _, _, _, "route"] => StartUdpPolicy::RouteSelected,
            [_, _, _, _, _, _, "range", start, end] => StartUdpPolicy::RouteSelectedPortRange {
                start: parse_port(start)?,
                end: parse_port(end)?,
            },
            [_, _, _, _, _, _, "explicit", address, port] => {
                let ip = parse_ip(address)?;
                StartUdpPolicy::Explicit(SocketAddr::new(ip, parse_port(port)?))
            }
            _ => return Err(Error::ServerStartMalformed),
        };
        let record = Self::try_new(authenticated, policy, limits)?;
        if record.encode().strip_suffix('\n') != Some(line) {
            return Err(Error::ServerStartMalformed);
        }
        Ok(record)
    }
}

/// Totally parse the OpenSSH-authenticated connection environment value.
pub fn parse_ssh_connection(value: &str) -> Result<AuthenticatedConnection, Error> {
    if value.is_empty() || value.len() > SSH_CONNECTION_MAX || value.chars().any(char::is_control) {
        return Err(Error::SshConnectionMalformed);
    }
    let fields: Vec<&str> = value.split(' ').collect();
    if fields.len() != 4 || fields.iter().any(|field| field.is_empty()) {
        return Err(Error::SshConnectionMalformed);
    }
    connection_from_fields(&fields).map_err(|_| Error::SshConnectionMalformed)
}

fn connection_from_fields(fields: &[&str]) -> Result<AuthenticatedConnection, Error> {
    if fields.len() != 4 {
        return Err(Error::ServerStartMalformed);
    }
    let peer = SocketAddr::new(parse_ip(fields[0])?, parse_port(fields[1])?);
    let local = SocketAddr::new(parse_ip(fields[2])?, parse_port(fields[3])?);
    AuthenticatedConnection::new(peer, local)
}

fn parse_ip(value: &str) -> Result<IpAddr, Error> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(Error::ServerStartMalformed);
    }
    value.parse().map_err(|_| Error::ServerStartMalformed)
}

fn parse_port(value: &str) -> Result<u16, Error> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::ServerStartMalformed);
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| Error::ServerStartMalformed)?;
    if port == 0 || port.to_string() != value {
        return Err(Error::ServerStartMalformed);
    }
    Ok(port)
}

fn validate_record_connection(connection: AuthenticatedConnection) -> Result<(), Error> {
    for address in [connection.peer(), connection.local()] {
        if let SocketAddr::V6(address) = address {
            if address.scope_id() != 0 || address.ip().is_unicast_link_local() {
                return Err(Error::ServerStartMalformed);
            }
        }
    }
    Ok(())
}

fn validate_start_policy(
    peer: SocketAddr,
    policy: StartUdpPolicy,
    limits: &Limits,
) -> Result<(), Error> {
    match policy {
        StartUdpPolicy::RouteSelected => {
            if peer.ip().is_loopback() {
                return Err(Error::ServerStartMalformed);
            }
        }
        StartUdpPolicy::RouteSelectedPortRange { start, end } => {
            let width = u32::from(end).saturating_sub(u32::from(start)) + 1;
            if peer.ip().is_loopback()
                || start == 0
                || start > end
                || width > limits.max_udp_port_span
            {
                return Err(Error::ServerStartMalformed);
            }
        }
        StartUdpPolicy::Explicit(address) => {
            if address.port() == 0
                || address.is_ipv4() != peer.is_ipv4()
                || address.ip().is_loopback() != peer.ip().is_loopback()
                || !usable_policy_address(address)
            {
                return Err(Error::ServerStartMalformed);
            }
        }
    }
    Ok(())
}

fn usable_policy_address(address: SocketAddr) -> bool {
    match address {
        SocketAddr::V4(address) => {
            !address.ip().is_unspecified()
                && !address.ip().is_multicast()
                && *address.ip() != Ipv4Addr::BROADCAST
        }
        SocketAddr::V6(address) => {
            !address.ip().is_unspecified()
                && !address.ip().is_multicast()
                && !address.ip().is_unicast_link_local()
                && address.scope_id() == 0
        }
    }
}

pub fn validate_release(line: &[u8]) -> Result<(), Error> {
    if line == RELEASE_RECORD {
        Ok(())
    } else {
        Err(Error::ReleaseRejected)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ssh_connection_is_total_and_family_exact() {
        let parsed = parse_ssh_connection("192.0.2.1 50000 192.0.2.2 22").unwrap();
        assert_eq!(
            parsed.authorized_target_addr(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 22))
        );
        let parsed = parse_ssh_connection("2001:db8::1 50000 2001:db8::2 2222").unwrap();
        assert_eq!(
            parsed.authorized_target_addr(),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 2222))
        );
        for bad in [
            "",
            "192.0.2.1 1 192.0.2.2",
            "192.0.2.1 1 192.0.2.2 22 extra",
            "hostname 1 192.0.2.2 22",
            "192.0.2.1 0 192.0.2.2 22",
            "192.0.2.1 01 192.0.2.2 22",
            "192.0.2.1 1 ::1 22",
            "0.0.0.0 1 192.0.2.2 22",
            "fe80::1 1 fe80::2 22",
            "192.0.2.1 1 192.0.2.2 22 ",
        ] {
            assert!(parse_ssh_connection(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn start_and_release_are_canonical() {
        let limits = Limits::default();
        let connection = parse_ssh_connection("192.0.2.1 50000 192.0.2.2 22").unwrap();
        for policy in [
            StartUdpPolicy::RouteSelected,
            StartUdpPolicy::RouteSelectedPortRange {
                start: 4000,
                end: 4002,
            },
            StartUdpPolicy::Explicit("192.0.2.2:4444".parse().unwrap()),
        ] {
            let record = ServerStartRecord::try_new(connection, policy, &limits).unwrap();
            let encoded = record.encode();
            assert_eq!(
                ServerStartRecord::parse(encoded.strip_suffix('\n').unwrap(), &limits).unwrap(),
                record
            );
        }
        assert!(validate_release(RELEASE_RECORD).is_ok());
        assert!(validate_release(b"everssh-release v2\n").is_err());
    }
}
