//! PSN chunk framing.
//!
//! Every PSN packet is a tree of *chunks*. Each chunk begins with a 4-byte,
//! little-endian header:
//!
//! ```text
//! offset  size  field
//!   0      2    id            (u16, LE)
//!   2      2    packed        (u16, LE): bits 0..=14 = data_len,
//!                                        bit 15      = has_subchunks
//! ```
//!
//! The `data_len` bytes that follow are either raw field data or, when
//! `has_subchunks` is set, a sequence of nested chunks. Chunks are padded to
//! nothing (no alignment) — the next chunk begins immediately after the
//! previous chunk's data.

use crate::PsnError;

/// A parsed 4-byte chunk header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    /// Chunk identifier. Its meaning is contextual (top-level packet type,
    /// field id, or — inside tracker lists — the tracker id itself).
    pub id: u16,
    /// Length in bytes of this chunk's data (excluding the 4-byte header).
    pub data_len: u16,
    /// Whether the data is itself a sequence of chunks.
    pub has_subchunks: bool,
}

impl ChunkHeader {
    const SIZE: usize = 4;
    const DATA_LEN_MASK: u16 = 0x7FFF;
    const SUBCHUNK_BIT: u16 = 0x8000;

    fn parse(buf: &[u8], offset: usize) -> Result<Self, PsnError> {
        if buf.len() < Self::SIZE {
            return Err(PsnError::UnexpectedEof {
                offset,
                needed: Self::SIZE - buf.len(),
            });
        }
        let id = u16::from_le_bytes([buf[0], buf[1]]);
        let packed = u16::from_le_bytes([buf[2], buf[3]]);
        Ok(Self {
            id,
            data_len: packed & Self::DATA_LEN_MASK,
            has_subchunks: packed & Self::SUBCHUNK_BIT != 0,
        })
    }
}

/// A chunk: its header plus a borrowed slice of its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk<'a> {
    /// The parsed header.
    pub header: ChunkHeader,
    /// The chunk's data bytes (length == `header.data_len`).
    pub data: &'a [u8],
}

impl<'a> Chunk<'a> {
    /// Iterate over this chunk's sub-chunks. Meaningful only when
    /// [`ChunkHeader::has_subchunks`] is set, but always safe to call.
    pub fn children(&self) -> ChunkReader<'a> {
        ChunkReader::new(self.data)
    }
}

/// A forward iterator over the chunks in a byte slice.
///
/// Yields `Result<Chunk, PsnError>`; the first malformed chunk produces an
/// error and ends iteration so a single bad packet can't loop forever.
#[derive(Debug, Clone)]
pub struct ChunkReader<'a> {
    buf: &'a [u8],
    /// Absolute offset of `buf[0]` within the original datagram, for diagnostics.
    base: usize,
    pos: usize,
    done: bool,
}

impl<'a> ChunkReader<'a> {
    /// Create a reader over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, base: 0, pos: 0, done: false }
    }

    /// Create a reader whose offsets are reported relative to `base` (used so
    /// nested errors carry datagram-absolute offsets). Mostly internal.
    pub fn with_base(buf: &'a [u8], base: usize) -> Self {
        Self { buf, base, pos: 0, done: false }
    }
}

impl<'a> Iterator for ChunkReader<'a> {
    type Item = Result<Chunk<'a>, PsnError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.pos >= self.buf.len() {
            return None;
        }
        let abs = self.base + self.pos;
        let header = match ChunkHeader::parse(&self.buf[self.pos..], abs) {
            Ok(h) => h,
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };
        let data_start = self.pos + ChunkHeader::SIZE;
        let data_end = data_start + header.data_len as usize;
        if data_end > self.buf.len() {
            self.done = true;
            return Some(Err(PsnError::ChunkOverrun {
                offset: abs,
                len: header.data_len as usize,
                available: self.buf.len() - data_start,
            }));
        }
        self.pos = data_end;
        Some(Ok(Chunk {
            header,
            data: &self.buf[data_start..data_end],
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flat_header() {
        // id = 0x0001, data_len = 4, has_subchunks = 0
        let buf = [0x01, 0x00, 0x04, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let mut r = ChunkReader::new(&buf);
        let c = r.next().unwrap().unwrap();
        assert_eq!(c.header.id, 1);
        assert_eq!(c.header.data_len, 4);
        assert!(!c.header.has_subchunks);
        assert_eq!(c.data, &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(r.next().is_none());
    }

    #[test]
    fn detects_subchunk_bit() {
        // packed = 0x8000 | 0 => has_subchunks, data_len 0
        let buf = [0x02, 0x00, 0x00, 0x80];
        let c = ChunkReader::new(&buf).next().unwrap().unwrap();
        assert!(c.header.has_subchunks);
        assert_eq!(c.header.data_len, 0);
    }

    #[test]
    fn errors_on_overrun() {
        // declares 16 bytes of data but only 1 present
        let buf = [0x01, 0x00, 0x10, 0x00, 0xAA];
        let err = ChunkReader::new(&buf).next().unwrap().unwrap_err();
        assert!(matches!(err, PsnError::ChunkOverrun { .. }));
    }
}
