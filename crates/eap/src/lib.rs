//! # EAP — EtherCAT Automation Protocol (Network Variables)
//!
//! A decoder for Beckhoff TwinCAT's **EAP Network Variables** (NWV) — the
//! routable publisher/subscriber mechanism TwinCAT uses to broadcast process
//! data (axis positions, trims, statuses) over standard Ethernet or UDP/IP.
//! This is distinct from the cyclic EtherCAT fieldbus.
//!
//! This crate is **receive-only** and **little-endian** throughout. The wire
//! format was taken from the Beckhoff-authored Wireshark EtherCAT plugin
//! (`plugins/epan/ethercat/packet-nv.{h,c}`), the de-facto reference; the
//! formal definition is ETG.1005.
//!
//! ## Layout
//!
//! ```text
//! EtherCAT frame header (2 bytes, LE): bits 0..=10 length, 11 reserved, 12..=15 type
//!   type == 4 (NV) for published network variables
//! NV header (12 bytes): u8[6] publisher, u16 count, u16 cycle_index, u16 reserved
//! per variable (8-byte header + data):
//!   u16 id, u16 hash, u16 length, u16 quality, then `length` data bytes
//! ```
//!
//! A subscriber matches variables by the numeric [`NetworkVariable::id`]; the
//! [`hash`](NetworkVariable::hash) is an opaque data-type/version fingerprint.
//!
//! ## Quick start
//!
//! ```no_run
//! # fn handle(udp_payload: &[u8]) -> Result<(), eap::EapError> {
//! let telegram = eap::PublisherTelegram::decode(udp_payload)?;
//! for var in &telegram.variables {
//!     if let Some(pos) = var.as_f64_le() {
//!         println!("nv {} = {} (quality {:#06x})", var.id, pos, var.quality);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod encode;
pub mod value;

#[cfg(feature = "net")]
pub mod net;

/// EtherType for EAP over raw Ethernet (`0x88A4`).
pub const ETHERTYPE: u16 = 0x88A4;

/// UDP port for EAP over IP (`34980`, i.e. `0x88A4`).
pub const UDP_PORT: u16 = 34980;

const FRAME_HEADER_LEN: usize = 2;
const NV_HEADER_LEN: usize = 12;
const VAR_HEADER_LEN: usize = 8;

/// The EtherCAT frame-header `Type` field set to Network Variables (4), shifted
/// into bits 12..=15 — i.e. `0x4000`. Used by the encoder.
pub(crate) const FRAME_TYPE_NV_BITS: u16 = 4 << 12;

/// EtherCAT frame `Type` field values (bits 12..=15 of the frame header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// EtherCAT command (cyclic fieldbus). Code 1.
    EtherCatCommand,
    /// ADS. Code 2.
    Ads,
    /// Raw I/O. Code 3.
    RawIo,
    /// Network Variables (publisher/subscriber). Code 4.
    NetworkVariables,
    /// Mailbox. Code 5.
    Mailbox,
    /// Any other / unknown type code.
    Other(u8),
}

impl FrameType {
    fn from_code(code: u8) -> Self {
        match code {
            1 => FrameType::EtherCatCommand,
            2 => FrameType::Ads,
            3 => FrameType::RawIo,
            4 => FrameType::NetworkVariables,
            5 => FrameType::Mailbox,
            other => FrameType::Other(other),
        }
    }
}

/// Errors produced while decoding an EAP packet.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EapError {
    /// The buffer ended before a field could be fully read.
    #[error("unexpected end of buffer: needed {needed} more byte(s) at offset {offset}")]
    UnexpectedEof {
        /// Offset of the attempted read.
        offset: usize,
        /// Additional bytes required.
        needed: usize,
    },

    /// The EtherCAT frame `Type` was not Network Variables (4).
    #[error("frame is type {0:?}, not Network Variables")]
    NotNetworkVariables(FrameType),

    /// A variable's declared length ran past the end of the buffer.
    #[error("variable {id} declares {len} data byte(s) but only {available} remain")]
    VariableOverrun {
        /// The variable's id.
        id: u16,
        /// Declared data length.
        len: usize,
        /// Bytes available.
        available: usize,
    },
}

/// The parsed 2-byte EtherCAT frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Length of the datagram payload that follows the header.
    pub length: u16,
    /// Datagram type.
    pub frame_type: FrameType,
}

impl FrameHeader {
    /// Parse the frame header from the first two bytes of `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self, EapError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(EapError::UnexpectedEof {
                offset: 0,
                needed: FRAME_HEADER_LEN - buf.len(),
            });
        }
        let word = u16::from_le_bytes([buf[0], buf[1]]);
        Ok(Self {
            length: word & 0x07FF,
            frame_type: FrameType::from_code(((word >> 12) & 0x0F) as u8),
        })
    }
}

/// A single published network variable (borrows its data from the datagram).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkVariable<'a> {
    /// Numeric variable id; the subscriber matches on this.
    pub id: u16,
    /// Opaque data-type/version hash (must match the subscriber's expectation).
    pub hash: u16,
    /// Quality flag.
    pub quality: u16,
    /// Raw variable data, little-endian.
    pub data: &'a [u8],
}

impl NetworkVariable<'_> {
    /// Interpret the first 8 data bytes as a little-endian `f64`.
    pub fn as_f64_le(&self) -> Option<f64> {
        self.data.get(..8).map(|b| f64::from_le_bytes(b.try_into().unwrap()))
    }
    /// Interpret the first 4 data bytes as a little-endian `f32`.
    pub fn as_f32_le(&self) -> Option<f32> {
        self.data.get(..4).map(|b| f32::from_le_bytes(b.try_into().unwrap()))
    }
    /// Interpret the first 4 data bytes as a little-endian `i32`.
    pub fn as_i32_le(&self) -> Option<i32> {
        self.data.get(..4).map(|b| i32::from_le_bytes(b.try_into().unwrap()))
    }
    /// Interpret the first 4 data bytes as a little-endian `u32`.
    pub fn as_u32_le(&self) -> Option<u32> {
        self.data.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }
    /// Interpret the first 2 data bytes as a little-endian `i16`.
    pub fn as_i16_le(&self) -> Option<i16> {
        self.data.get(..2).map(|b| i16::from_le_bytes(b.try_into().unwrap()))
    }
    /// Interpret the first data byte as a boolean (non-zero == true).
    pub fn as_bool(&self) -> Option<bool> {
        self.data.first().map(|&b| b != 0)
    }
}

/// A decoded EAP Network Variables publisher telegram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherTelegram<'a> {
    /// Publisher identifier (MAC-address-shaped, 6 bytes).
    pub publisher: [u8; 6],
    /// Cycle counter / index from the publisher.
    pub cycle_index: u16,
    /// The published variables.
    pub variables: Vec<NetworkVariable<'a>>,
}

impl<'a> PublisherTelegram<'a> {
    /// Decode an EAP datagram starting at the EtherCAT frame header (i.e. the
    /// UDP payload, or the bytes after the 14-byte Ethernet header for raw L2).
    pub fn decode(buf: &'a [u8]) -> Result<Self, EapError> {
        let header = FrameHeader::parse(buf)?;
        if header.frame_type != FrameType::NetworkVariables {
            return Err(EapError::NotNetworkVariables(header.frame_type));
        }
        let nv = &buf[FRAME_HEADER_LEN..];
        Self::decode_nv(nv)
    }

    /// Decode the NV payload (the bytes after the 2-byte frame header).
    pub fn decode_nv(nv: &'a [u8]) -> Result<Self, EapError> {
        if nv.len() < NV_HEADER_LEN {
            return Err(EapError::UnexpectedEof {
                offset: 0,
                needed: NV_HEADER_LEN - nv.len(),
            });
        }
        let mut publisher = [0u8; 6];
        publisher.copy_from_slice(&nv[0..6]);
        let count = u16::from_le_bytes([nv[6], nv[7]]);
        let cycle_index = u16::from_le_bytes([nv[8], nv[9]]);
        // nv[10..12] is reserved; the first variable starts at offset 12.

        let mut variables = Vec::with_capacity(count as usize);
        let mut pos = NV_HEADER_LEN;
        for _ in 0..count {
            if pos + VAR_HEADER_LEN > nv.len() {
                return Err(EapError::UnexpectedEof {
                    offset: pos,
                    needed: pos + VAR_HEADER_LEN - nv.len(),
                });
            }
            let id = u16::from_le_bytes([nv[pos], nv[pos + 1]]);
            let hash = u16::from_le_bytes([nv[pos + 2], nv[pos + 3]]);
            let length = u16::from_le_bytes([nv[pos + 4], nv[pos + 5]]) as usize;
            let quality = u16::from_le_bytes([nv[pos + 6], nv[pos + 7]]);
            let data_start = pos + VAR_HEADER_LEN;
            let data_end = data_start + length;
            if data_end > nv.len() {
                return Err(EapError::VariableOverrun {
                    id,
                    len: length,
                    available: nv.len() - data_start,
                });
            }
            variables.push(NetworkVariable {
                id,
                hash,
                quality,
                data: &nv[data_start..data_end],
            });
            pos = data_end;
        }
        Ok(Self { publisher, cycle_index, variables })
    }
}
