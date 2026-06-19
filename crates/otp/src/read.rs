//! Minimal big-endian (network-order) read cursor.
//!
//! OTP, unlike PSN, is big-endian throughout.

use crate::OtpError;

pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], OtpError> {
        let end = self.pos + n;
        if end > self.buf.len() {
            return Err(OtpError::UnexpectedEof {
                offset: self.pos,
                needed: end - self.buf.len(),
            });
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, OtpError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, OtpError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, OtpError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub(crate) fn i32(&mut self) -> Result<i32, OtpError> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, OtpError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// Skip `n` bytes (e.g. reserved fields).
    pub(crate) fn skip(&mut self, n: usize) -> Result<(), OtpError> {
        self.take(n).map(|_| ())
    }
}

/// Decode a fixed-length, NUL-padded UTF-8 name field (lossy on bad UTF-8,
/// since OTP names are operator-entered and we'd rather show replacement
/// characters than drop the whole packet).
pub(crate) fn fixed_name(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}
