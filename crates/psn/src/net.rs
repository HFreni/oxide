//! Multicast socket helper (requires the `net` feature).
//!
//! Builds a UDP socket bound to the PSN port and joined to a PSN multicast
//! group, with `SO_REUSEADDR`/`SO_REUSEPORT` set so multiple PSN consumers can
//! share the port on one host. The returned [`std::net::UdpSocket`] integrates
//! with any runtime (blocking, tokio, async-std, …).

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

use crate::{DEFAULT_MULTICAST_ADDR, DEFAULT_PORT};

/// Options for [`join_multicast`].
#[derive(Debug, Clone)]
pub struct MulticastConfig {
    /// Multicast group to join. Defaults to [`DEFAULT_MULTICAST_ADDR`].
    pub group: Ipv4Addr,
    /// UDP port to bind. Defaults to [`DEFAULT_PORT`].
    pub port: u16,
    /// Local interface to receive on. `UNSPECIFIED` (`0.0.0.0`) lets the OS
    /// choose; set this to pin PSN to a specific NIC.
    pub interface: Ipv4Addr,
}

impl Default for MulticastConfig {
    fn default() -> Self {
        Self {
            group: DEFAULT_MULTICAST_ADDR,
            port: DEFAULT_PORT,
            interface: Ipv4Addr::UNSPECIFIED,
        }
    }
}

/// Create a UDP socket joined to the configured PSN multicast group.
///
/// The socket is returned in blocking mode; call
/// [`set_nonblocking`](UdpSocket::set_nonblocking) (or wrap it with your async
/// runtime, e.g. `tokio::net::UdpSocket::from_std`) as needed.
pub fn join_multicast(cfg: &MulticastConfig) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    // SO_REUSEPORT is not available on all platforms; ignore if unsupported.
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    {
        let _ = socket.set_reuse_port(true);
    }

    // Bind to the wildcard address on the PSN port. Binding to the group
    // address directly is rejected on some platforms (notably Windows), so we
    // bind wildcard and filter via the multicast join.
    let bind_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, cfg.port).into();
    socket.bind(&bind_addr.into())?;

    socket.join_multicast_v4(&cfg.group, &cfg.interface)?;

    Ok(socket.into())
}
