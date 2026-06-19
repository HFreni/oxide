//! UDP receiver helper (requires the `net` feature).
//!
//! EAP can be published as broadcast, multicast, or unicast over UDP. This
//! helper binds the EAP port with address/port reuse and, optionally, joins a
//! multicast group. Broadcast and unicast need no join — just bind.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

use crate::UDP_PORT;

/// Options for [`bind`].
#[derive(Debug, Clone)]
pub struct BindConfig {
    /// UDP port to bind. Defaults to [`UDP_PORT`].
    pub port: u16,
    /// Optional multicast group to join (TwinCAT multicast publishing).
    pub multicast_group: Option<Ipv4Addr>,
    /// Local interface (`0.0.0.0` lets the OS choose).
    pub interface: Ipv4Addr,
    /// Enable reception of broadcast datagrams.
    pub broadcast: bool,
}

impl Default for BindConfig {
    fn default() -> Self {
        Self {
            port: UDP_PORT,
            multicast_group: None,
            interface: Ipv4Addr::UNSPECIFIED,
            broadcast: true,
        }
    }
}

/// Bind a UDP socket for receiving EAP datagrams.
///
/// Returned in blocking mode; wrap with your async runtime as needed.
pub fn bind(cfg: &BindConfig) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    {
        let _ = socket.set_reuse_port(true);
    }
    if cfg.broadcast {
        socket.set_broadcast(true)?;
    }

    let bind_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, cfg.port).into();
    socket.bind(&bind_addr.into())?;

    if let Some(group) = cfg.multicast_group {
        socket.join_multicast_v4(&group, &cfg.interface)?;
    }

    Ok(socket.into())
}
