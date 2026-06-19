//! Advertisement-message layer: discovery of modules, point names, and systems.
//!
//! Per ANSI E1.59-2021 §11-§14 (and the worked examples in Appendix B.2-B.4),
//! an OTP advertisement message nests **two** PDUs below the OTP base layer:
//!
//! ```text
//! OTP Base Layer            (octets 0-78, base Vector 12-13 = 0x0002)
//!   OTP Advertisement Layer (octets 79-86)
//!     Vector (79-80)  = 0x0001 Module / 0x0002 Name / 0x0003 System  ← the KIND
//!     Length (81-82)
//!     Reserved (83-86, 4 octets)
//!     Inner ..._LIST Layer  (octets 87+)
//!       Vector (87-88) = 0x0001 (the *_LIST vector; same value for all kinds)
//!       Length (89-90)
//!       [Options (1 octet, bit7 = Request/Response)  — Name & System only]
//!       Reserved (4 octets)
//!       entries:
//!         Module:  {u16 manufacturer, u16 module}        (4 octets each)
//!         Name:    {u8 sys, u16 grp, u32 pt, name(32)}   (39 octets each)
//!         System:  {u8 system}                           (1 octet each)
//! ```

use crate::modules::Address;
use crate::pdu::read_one;
use crate::read::{fixed_name, Cursor};
use crate::OtpError;

/// OTP Advertisement Layer vector (octets 79-80) selecting a Module advertisement.
pub const VECTOR_ADV_MODULE: u16 = 0x0001;
/// OTP Advertisement Layer vector (octets 79-80) selecting a Name advertisement.
pub const VECTOR_ADV_NAME: u16 = 0x0002;
/// OTP Advertisement Layer vector (octets 79-80) selecting a System advertisement.
pub const VECTOR_ADV_SYSTEM: u16 = 0x0003;

/// Inner advertisement-list layer vector (octets 87-88). The same value
/// (`VECTOR_OTP_ADVERTISEMENT_*_LIST`) is used for Module, Name, and System.
pub const VECTOR_LIST: u16 = 0x0001;

const NAME_FIELD_LEN: usize = 32;

/// A manufacturer + module pair, as advertised in a Module Advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleIdent {
    /// Manufacturer ID (ESTA = `0x0000`).
    pub manufacturer: u16,
    /// Module number.
    pub module: u16,
}

/// A point's advertised name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointName {
    /// Point address.
    pub address: Address,
    /// Human-readable name (NUL-trimmed UTF-8).
    pub name: String,
}

/// A decoded advertisement message.
#[derive(Debug, Clone, PartialEq)]
pub enum AdvertisementMessage {
    /// List of supported modules.
    Module(Vec<ModuleIdent>),
    /// Point-name advertisement.
    Name {
        /// `true` if this is a response (vs. a request).
        is_response: bool,
        /// Advertised point names.
        names: Vec<PointName>,
    },
    /// List of advertised system numbers.
    System {
        /// `true` if this is a response (vs. a request).
        is_response: bool,
        /// Advertised system numbers.
        systems: Vec<u8>,
    },
    /// An advertisement layer we don't decode; carries its raw vector.
    Unknown(u16),
}

impl AdvertisementMessage {
    /// Decode an OTP Advertisement Layer.
    ///
    /// `kind` is the OTP Advertisement Layer vector (octets 79-80,
    /// [`VECTOR_ADV_MODULE`] / [`VECTOR_ADV_NAME`] / [`VECTOR_ADV_SYSTEM`]);
    /// `body` is that layer's body (the bytes after its Length field, i.e.
    /// Reserved(4) followed by the inner `..._LIST` PDU).
    pub fn decode(kind: u16, body: &[u8]) -> Result<Self, OtpError> {
        let mut c = Cursor::new(body);
        c.skip(4)?; // OTP Advertisement Layer reserved (octets 83-86)

        let inner = match read_one(&body[c.position()..])? {
            Some(pdu) => pdu,
            None => return Ok(AdvertisementMessage::Unknown(kind)),
        };
        // The inner *_LIST layer vector must be VECTOR_LIST for every kind
        // (§12.1/§13.1/§14.1); anything else is treated as undecodable.
        if inner.vector != VECTOR_LIST {
            return Ok(AdvertisementMessage::Unknown(kind));
        }

        match kind {
            VECTOR_ADV_MODULE => Self::decode_module(inner.body),
            VECTOR_ADV_NAME => Self::decode_name(inner.body),
            VECTOR_ADV_SYSTEM => Self::decode_system(inner.body),
            other => Ok(AdvertisementMessage::Unknown(other)),
        }
    }

    fn decode_module(body: &[u8]) -> Result<Self, OtpError> {
        let mut c = Cursor::new(body);
        c.skip(4)?; // reserved (no options octet for Module)
        let mut mods = Vec::new();
        while c.position() + 4 <= body.len() {
            mods.push(ModuleIdent {
                manufacturer: c.u16()?,
                module: c.u16()?,
            });
        }
        Ok(AdvertisementMessage::Module(mods))
    }

    fn decode_name(body: &[u8]) -> Result<Self, OtpError> {
        let mut c = Cursor::new(body);
        let options = c.u8()?;
        c.skip(4)?; // reserved
        let is_response = options & 0x80 != 0;
        let entry_len = 1 + 2 + 4 + NAME_FIELD_LEN; // 39
        let mut names = Vec::new();
        while c.position() + entry_len <= body.len() {
            let system = c.u8()?;
            let group = c.u16()?;
            let point = c.u32()?;
            let name = fixed_name(c.take(NAME_FIELD_LEN)?);
            names.push(PointName {
                address: Address { system, group, point },
                name,
            });
        }
        Ok(AdvertisementMessage::Name { is_response, names })
    }

    fn decode_system(body: &[u8]) -> Result<Self, OtpError> {
        let mut c = Cursor::new(body);
        let options = c.u8()?;
        c.skip(4)?; // reserved
        let is_response = options & 0x80 != 0;
        let mut systems = Vec::new();
        while c.position() < body.len() {
            systems.push(c.u8()?);
        }
        Ok(AdvertisementMessage::System { is_response, systems })
    }
}
