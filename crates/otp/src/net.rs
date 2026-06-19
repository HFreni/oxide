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
