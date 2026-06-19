//! Minimal little-endian read cursor over a byte slice.

use crate::{PsnError, Vec3};

pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    /// Absolute base offset for error reporting.
    base: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0, base: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], PsnError> {
        let end = self.pos + n;
        if end > self.buf.len() {
            return Err(PsnError::UnexpectedEof {
                offset: self.base + self.pos,
                needed: end - self.buf.len(),
            });
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, PsnError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u64(&mut self) -> Result<u64, PsnError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    pub(crate) fn f32(&mut self) -> Result<f32, PsnError> {
        let b = self.take(4)?;
        Ok(f32::from_le_bytes(b.try_into().unwrap()))
    }

    pub(crate) fn vec3(&mut self) -> Result<Vec3, PsnError> {
        Ok(Vec3::new(self.f32()?, self.f32()?, self.f32()?))
    }
}

/// Decode a UTF-8 string occupying the entire slice (PSN strings are not
/// null-terminated; the length comes from the chunk header).
pub(crate) fn utf8_string(data: &[u8]) -> Result<String, PsnError> {
    core::str::from_utf8(data)
        .map(|s| s.to_owned())
        .map_err(|_| PsnError::InvalidUtf8 { offset: 0 })
}
