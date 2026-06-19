//! Multicast socket helper (requires the `net` feature).
//!
//! OTP transform traffic is split across one multicast group per system
//! (`239.159.1.<system>`), plus a fixed advertisement group. This helper binds
//! the OTP port and joins whichever systems you ask for.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

use crate::{transform_multicast, ADVERTISEMENT_MULTICAST, PORT};

/// Options for [`join_multicast`].
#[derive(Debug, Clone)]
pub struct MulticastConfig {
    /// System numbers (1..=200) whose transform groups to join.
    pub systems: Vec<u8>,
    /// Whether to also join the advertisement group.
    pub join_advertisement: bool,
    /// UDP port. Defaults to [`PORT`].
    pub port: u16,
    /// Local interface to receive on (`0.0.0.0` lets the OS choose).
    pub interface: Ipv4Addr,
}

impl Default for MulticastConfig {
    fn default() -> Self {
        Self {
            systems: Vec::new(),
            join_advertisement: true,
            port: PORT,
            interface: Ipv4Addr::UNSPECIFIED,
        }
    }
}

/// Create a UDP socket joined to the requested OTP multicast groups.
///
/// Returned in blocking mode; wrap with your async runtime as needed.
pub fn join_multicast(cfg: &MulticastConfig) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    {
        let _ = socket.set_reuse_port(true);
    }

    let bind_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, cfg.port).into();
    socket.bind(&bind_addr.into())?;

    for &system in &cfg.systems {
        socket.join_multicast_v4(&transform_multicast(system), &cfg.interface)?;
    }
    if cfg.join_advertisement {
        socket.join_multicast_v4(&ADVERTISEMENT_MULTICAST, &cfg.interface)?;
    }

    Ok(socket.into())
}

/// Options for [`sender`].
#[derive(Debug, Clone)]
pub struct SenderConfig {
    /// Outgoing multicast interface (`0.0.0.0` lets the OS choose).
    pub interface: Ipv4Addr,
    /// Multicast TTL (hops). OTP is usually local; default `1`.
    pub ttl: u32,
    /// Loop multicast back to local sockets (useful for testing).
    pub loop_back: bool,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self { interface: Ipv4Addr::UNSPECIFIED, ttl: 1, loop_back: false }
    }
}

/// Create a UDP socket for transmitting OTP. Unlike the receiver, this is not
/// joined or connected to a single group — OTP transform traffic for system `N`
/// goes to [`transform_multicast(N)`](crate::transform_multicast) and
/// advertisements to [`ADVERTISEMENT_MULTICAST`]. Use [`send_to`](UdpSocket::send_to)
/// with the appropriate group, or see [`send_transform`].
pub fn sender(cfg: &SenderConfig) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_multicast_if_v4(&cfg.interface)?;
    socket.set_multicast_ttl_v4(cfg.ttl)?;
    socket.set_multicast_loop_v4(cfg.loop_back)?;
    Ok(socket.into())
}

/// Send an encoded OTP transform datagram to the multicast group for `system`.
pub fn send_transform(socket: &UdpSocket, system: u8, datagram: &[u8]) -> io::Result<usize> {
    socket.send_to(datagram, SocketAddr::from((transform_multicast(system), PORT)))
}
