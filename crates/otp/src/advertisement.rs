//! Advertisement-message layer: discovery of modules, point names, and systems.
//!
//! ```text
//! Advertisement Layer  (base Vector = 0x0002)
//!   u32 reserved
//!   └─ one sub-PDU:
//!        Module Advertisement (Vector 0x0001):  reserved(4), then [u16 mfr, u16 module]*
//!        Name   Advertisement (Vector 0x0002):  options(1,bit7=response), reserved(4),
//!                                                then [u8 sys, u16 grp, u32 pt, name(32)]*
//!        System Advertisement (Vector 0x0003):  options(1), reserved(4), then [u8 system]*
//! ```

use crate::modules::Address;
use crate::pdu::read_one;
use crate::read::{fixed_name, Cursor};
use crate::OtpError;

/// Vector (base layer) selecting the advertisement message.
pub const VECTOR_ADVERTISEMENT: u16 = 0x0002;

const VECTOR_MODULE_ADV: u16 = 0x0001;
const VECTOR_NAME_ADV: u16 = 0x0002;
const VECTOR_SYSTEM_ADV: u16 = 0x0003;

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
    System(Vec<u8>),
    /// An advertisement sub-layer we don't decode; carries its raw vector.
    Unknown(u16),
}

impl AdvertisementMessage {
    /// Decode an advertisement-layer body (bytes inside the advertisement PDU).
    pub fn decode(body: &[u8]) -> Result<Self, OtpError> {
        let mut c = Cursor::new(body);
        c.skip(4)?; // reserved
        let sub = match read_one(&body[c.position()..])? {
            Some(pdu) => pdu,
            None => return Ok(AdvertisementMessage::Unknown(0)),
        };
        match sub.vector {
            VECTOR_MODULE_ADV => Ok(Self::decode_module(sub.body)?),
            VECTOR_NAME_ADV => Ok(Self::decode_name(sub.body)?),
            VECTOR_SYSTEM_ADV => Ok(Self::decode_system(sub.body)?),
            other => Ok(AdvertisementMessage::Unknown(other)),
        }
    }

    fn decode_module(body: &[u8]) -> Result<Self, OtpError> {
        let mut c = Cursor::new(body);
        c.skip(4)?; // reserved
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
        let _options = c.u8()?;
        c.skip(4)?; // reserved
        let mut systems = Vec::new();
        while c.position() < body.len() {
            systems.push(c.u8()?);
        }
        Ok(AdvertisementMessage::System(systems))
    }
}
