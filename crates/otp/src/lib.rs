//! # OTP — Object Transform Protocol (ANSI E1.59)
//!
//! A decoder for [OTP](https://www.esta.org/), the ESTA standard for streaming
//! object transform data (position, rotation, scale, velocity, acceleration)
//! over UDP multicast. OTP is layered like ACN/sACN and is **big-endian**.
//!
//! This crate is **receive-only**. The wire format was reconstructed from the
//! public reference implementations ([OTPLib] and its Wireshark dissector); the
//! ANSI E1.59 standard itself is paywalled. Field offsets and units are
//! documented per module in [`modules`].
//!
//! [OTPLib]: https://github.com/marcusbirkin/OTPLib
//!
//! ## Quick start
//!
//! ```no_run
//! use otp::{Packet, Message};
//!
//! # fn handle(buf: &[u8]) -> Result<(), otp::OtpError> {
//! let packet = Packet::decode(buf)?;
//! if let Message::Transform(t) = &packet.message {
//!     for point in &t.points {
//!         if let Some(pos) = point.position {
//!             println!("{} at {:?} m", point.address, pos);
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod advertisement;
pub mod modules;
pub mod pdu;
mod read;
pub mod transform;

#[cfg(feature = "net")]
pub mod net;

pub use advertisement::AdvertisementMessage;
pub use modules::Address;
pub use transform::{Point, TransformMessage};

use std::net::Ipv4Addr;

use read::{fixed_name, Cursor};

/// The 12-octet OTP packet identifier: `"OTP-E1.59"` + three NUL bytes.
pub const PACKET_IDENT: &[u8; 12] = b"OTP-E1.59\0\0\0";

/// OTP UDP port (`5568`, shared with sACN).
pub const PORT: u16 = 5568;

/// Fixed IPv4 multicast group for the advertisement message (`239.159.2.1`).
pub const ADVERTISEMENT_MULTICAST: Ipv4Addr = Ipv4Addr::new(239, 159, 2, 1);

/// IPv4 multicast group carrying transform messages for `system` (1..=200):
/// `239.159.1.<system>`.
pub const fn transform_multicast(system: u8) -> Ipv4Addr {
    Ipv4Addr::new(239, 159, 1, system)
}

const COMPONENT_NAME_LEN: usize = 32;

/// Vector (base layer) selecting a transform message.
pub const VECTOR_TRANSFORM_MESSAGE: u16 = transform::VECTOR_TRANSFORM;
/// Vector (base layer) selecting an advertisement message.
pub const VECTOR_ADVERTISEMENT_MESSAGE: u16 = advertisement::VECTOR_ADVERTISEMENT;

/// Errors produced while decoding an OTP packet.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OtpError {
    /// The buffer ended before a field could be fully read.
    #[error("unexpected end of buffer: needed {needed} more byte(s) at offset {offset}")]
    UnexpectedEof {
        /// Offset of the attempted read.
        offset: usize,
        /// Additional bytes required.
        needed: usize,
    },

    /// A PDU declared a length running past its parent.
    #[error("PDU at offset {offset} declares length {len} but only {available} byte(s) remain")]
    PduOverrun {
        /// Offset of the PDU header.
        offset: usize,
        /// Declared length.
        len: usize,
        /// Bytes available.
        available: usize,
    },

    /// The 12-byte packet identifier did not match [`PACKET_IDENT`].
    #[error("bad OTP packet identifier")]
    BadIdentifier,

    /// The base-layer vector was neither transform nor advertisement.
    #[error("unknown base vector {0:#06x}")]
    UnknownVector(u16),

    /// The packet was too short to contain even the base-layer header.
    #[error("packet too short: {0} byte(s)")]
    TooShort(usize),
}

/// The OTP base-layer header, shared by every packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpLayer {
    /// Component identifier (a 16-octet UUID), identifying the sender.
    pub cid: [u8; 16],
    /// Folio number; increments per logical message (may span pages).
    pub folio: u32,
    /// Current page within the folio.
    pub page: u16,
    /// Last page index of the folio (0-based, so single-page == 0).
    pub last_page: u16,
    /// Sender's component name.
    pub component_name: String,
}

/// The body of an OTP packet, selected by the base-layer vector.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A transform message (live point transforms).
    Transform(TransformMessage),
    /// An advertisement message (discovery).
    Advertisement(AdvertisementMessage),
}

/// A fully decoded OTP packet: base-layer metadata plus a message.
#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    /// Base-layer header (sender identity, paging).
    pub layer: OtpLayer,
    /// The decoded message.
    pub message: Message,
}

impl Packet {
    /// Decode a single OTP datagram.
    pub fn decode(buf: &[u8]) -> Result<Self, OtpError> {
        if buf.len() < PACKET_IDENT.len() {
            return Err(OtpError::TooShort(buf.len()));
        }
        if &buf[..PACKET_IDENT.len()] != PACKET_IDENT.as_slice() {
            return Err(OtpError::BadIdentifier);
        }

        // The base layer is a PDU starting right after the identifier. Its
        // body holds the base-layer fields followed by the message sub-layer.
        let base = pdu::read_one(&buf[PACKET_IDENT.len()..])?
            .ok_or(OtpError::TooShort(buf.len()))?;
        let base_vector = base.vector;
        let body = base.body;

        // Base-layer fields (the 63 octets between the Length field and the
        // start of the message sub-layer).
        let mut c = Cursor::new(body);
        c.skip(1)?; // footer options
        c.skip(1)?; // footer length
        let cid: [u8; 16] = c.take(16)?.try_into().unwrap();
        let folio = c.u32()?;
        let page = c.u16()?;
        let last_page = c.u16()?;
        c.skip(1)?; // options
        c.skip(4)?; // reserved
        let component_name = fixed_name(c.take(COMPONENT_NAME_LEN)?);

        let layer = OtpLayer { cid, folio, page, last_page, component_name };

        let sub = pdu::read_one(&body[c.position()..])?
            .ok_or(OtpError::TooShort(buf.len()))?;

        let message = match base_vector {
            VECTOR_TRANSFORM_MESSAGE => Message::Transform(TransformMessage::decode(sub.body)?),
            VECTOR_ADVERTISEMENT_MESSAGE => {
                Message::Advertisement(AdvertisementMessage::decode(sub.body)?)
            }
            other => return Err(OtpError::UnknownVector(other)),
        };

        Ok(Packet { layer, message })
    }
}

/// A 3-component `f64` vector. Units depend on the field (see [`modules`]).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Vec3 {
    /// X component.
    pub x: f64,
    /// Y component.
    pub y: f64,
    /// Z component.
    pub z: f64,
}

impl Vec3 {
    /// Construct a vector from components.
    pub const fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }
}

impl From<Vec3> for [f64; 3] {
    fn from(v: Vec3) -> Self {
        [v.x, v.y, v.z]
    }
}
