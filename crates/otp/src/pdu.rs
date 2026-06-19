//! Generic OTP PDU framing.
//!
//! Every OTP layer below the packet identifier shares the same shape:
//!
//! ```text
//! u16 vector      (in the Module layer this slot is the Manufacturer ID)
//! u16 length      number of octets that FOLLOW this length field, to the
//!                 end of this PDU — i.e. the PDU's own fixed header fields
//!                 plus all of its child PDUs
//! [length bytes]  body: this PDU's fields, then nested child PDUs
//! ```
//!
//! So the total on-wire size of a PDU is `length + 4` (the vector and length
//! fields themselves are not counted by `length`). [`PduReader`] walks a
//! sequence of sibling PDUs using exactly this rule.

use crate::OtpError;

/// A single PDU: its leading 16-bit tag (vector / manufacturer id) and its body.
#[derive(Debug, Clone, Copy)]
pub struct Pdu<'a> {
    /// The PDU's vector, or — for a Module layer — its Manufacturer ID.
    pub vector: u16,
    /// The body: fixed fields for this layer followed by any child PDUs.
    pub body: &'a [u8],
}

/// Forward iterator over sibling PDUs packed in a slice.
#[derive(Debug, Clone)]
pub struct PduReader<'a> {
    buf: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> PduReader<'a> {
    /// Create a reader over a buffer of zero or more sibling PDUs.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0, done: false }
    }
}

impl<'a> Iterator for PduReader<'a> {
    type Item = Result<Pdu<'a>, OtpError>;

    fn next(&mut self) -> Option<Self::Item> {
        // A trailing remainder smaller than a 4-byte header is treated as
        // padding and ends iteration cleanly.
        if self.done || self.pos + 4 > self.buf.len() {
            return None;
        }
        let vector = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        let length = u16::from_be_bytes([self.buf[self.pos + 2], self.buf[self.pos + 3]]) as usize;
        let body_start = self.pos + 4;
        let body_end = body_start + length;
        if body_end > self.buf.len() {
            self.done = true;
            return Some(Err(OtpError::PduOverrun {
                offset: self.pos,
                len: length,
                available: self.buf.len() - body_start,
            }));
        }
        self.pos = body_end;
        Some(Ok(Pdu {
            vector,
            body: &self.buf[body_start..body_end],
        }))
    }
}

/// Read exactly one PDU at the start of `buf`, returning it and the remaining
/// bytes after it. Used for the singleton Transform/Advertisement layer that
/// follows the base-layer header fields.
pub fn read_one(buf: &[u8]) -> Result<Option<Pdu<'_>>, OtpError> {
    PduReader::new(buf).next().transpose()
}
