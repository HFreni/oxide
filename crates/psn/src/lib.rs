//! # PosiStageNet (PSN)
//!
//! A decoder for [PosiStageNet](https://posistage.net/) v2 — the open protocol
//! (developed by VYV and MA Lighting) for streaming the 3D position of tracked
//! objects on stage over UDP multicast.
//!
//! This crate is **receive-only**: it decodes `PSN_DATA` and `PSN_INFO` packets
//! off the wire. The wire format is little-endian and chunk-based; see
//! [`chunk`] for the framing and [`data`]/[`info`] for the payloads.
//!
//! ## Quick start
//!
//! ```no_run
//! use psn::{DataPacket, InfoPacket, Packet};
//!
//! # fn handle(buf: &[u8]) -> Result<(), psn::PsnError> {
//! match Packet::decode(buf)? {
//!     Packet::Data(data) => {
//!         for tracker in &data.trackers {
//!             if let Some(pos) = tracker.position {
//!                 println!("tracker {} at {:?}", tracker.id, pos);
//!             }
//!         }
//!     }
//!     Packet::Info(info) => {
//!         println!("system: {:?}", info.system_name);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! With the (default) `net` feature, [`net::join_multicast`] builds a UDP
//! socket already joined to the PSN multicast group.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod chunk;
pub mod data;
pub mod info;
mod read;

#[cfg(feature = "net")]
pub mod net;

pub use chunk::{ChunkHeader, ChunkReader};
pub use data::{DataHeader, DataPacket, Tracker};
pub use info::{InfoHeader, InfoPacket, TrackerInfo};

use std::net::Ipv4Addr;

/// Default PSN multicast group address (`236.10.10.10`).
pub const DEFAULT_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(236, 10, 10, 10);

/// Default PSN UDP port (`56565`).
pub const DEFAULT_PORT: u16 = 56565;

/// Top-level chunk id for a `PSN_INFO` packet.
pub const PSN_INFO_PACKET: u16 = 0x6756;
/// Top-level chunk id for a `PSN_DATA` packet.
pub const PSN_DATA_PACKET: u16 = 0x6755;

/// A 3-component vector of `f32`, used for position, speed, orientation, etc.
///
/// Units depend on the field per the PSN spec: position/target in **metres**,
/// speed in **m/s**, acceleration in **m/s²**, orientation in **radians**.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Vec3 {
    /// X component.
    pub x: f32,
    /// Y component.
    pub y: f32,
    /// Z component.
    pub z: f32,
}

impl Vec3 {
    /// Construct a vector from its components.
    pub const fn new(x: f32, y: f32, z: f32) -> Self {
        Self { x, y, z }
    }
}

impl From<Vec3> for [f32; 3] {
    fn from(v: Vec3) -> Self {
        [v.x, v.y, v.z]
    }
}

/// Errors produced while decoding a PSN packet.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PsnError {
    /// The buffer ended before a field could be fully read.
    #[error("unexpected end of buffer: needed {needed} more byte(s) at offset {offset}")]
    UnexpectedEof {
        /// Byte offset at which the read was attempted.
        offset: usize,
        /// Number of additional bytes that were required.
        needed: usize,
    },

    /// A chunk declared a length that runs past the end of its parent.
    #[error("chunk at offset {offset} declares length {len} but only {available} byte(s) remain")]
    ChunkOverrun {
        /// Byte offset of the chunk header.
        offset: usize,
        /// Declared data length.
        len: usize,
        /// Bytes actually available.
        available: usize,
    },

    /// The top-level chunk id was neither `PSN_INFO` nor `PSN_DATA`.
    #[error("unknown root chunk id {0:#06x} (expected PSN_INFO or PSN_DATA)")]
    UnknownRootChunk(u16),

    /// A string field was not valid UTF-8.
    #[error("invalid UTF-8 in string field at offset {offset}")]
    InvalidUtf8 {
        /// Byte offset of the string field.
        offset: usize,
    },
}

/// A decoded PSN packet: either tracker data or system/tracker info.
#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    /// A `PSN_DATA` packet carrying live tracker transforms.
    Data(DataPacket),
    /// A `PSN_INFO` packet carrying the system name and tracker names.
    Info(InfoPacket),
}

impl Packet {
    /// Decode a single PSN datagram, dispatching on the root chunk id.
    pub fn decode(buf: &[u8]) -> Result<Self, PsnError> {
        let mut reader = ChunkReader::new(buf);
        let chunk = reader
            .next()
            .ok_or(PsnError::UnexpectedEof { offset: 0, needed: 4 })??;
        match chunk.header.id {
            PSN_DATA_PACKET => Ok(Packet::Data(DataPacket::decode(chunk.data)?)),
            PSN_INFO_PACKET => Ok(Packet::Info(InfoPacket::decode(chunk.data)?)),
            other => Err(PsnError::UnknownRootChunk(other)),
        }
    }
}
