//! EAP encoder: build a Network Variables publisher datagram from a
//! [`PublisherTelegram`]. The inverse of [`PublisherTelegram::decode`].

use crate::{PublisherTelegram, FRAME_TYPE_NV_BITS};

impl PublisherTelegram<'_> {
    /// Encode this telegram into a UDP datagram beginning with the EtherCAT
    /// frame header (type = NV). Variable data is taken verbatim from each
    /// [`NetworkVariable::data`](crate::NetworkVariable::data) slice (little-endian;
    /// see [`crate::value`] for builders).
    pub fn encode(&self) -> Vec<u8> {
        // NV payload (everything after the 2-byte frame header).
        let mut nv = Vec::new();
        nv.extend_from_slice(&self.publisher);
        nv.extend_from_slice(&(self.variables.len() as u16).to_le_bytes());
        nv.extend_from_slice(&self.cycle_index.to_le_bytes());
        nv.extend_from_slice(&0u16.to_le_bytes()); // reserved
        for v in &self.variables {
            nv.extend_from_slice(&v.id.to_le_bytes());
            nv.extend_from_slice(&v.hash.to_le_bytes());
            nv.extend_from_slice(&(v.data.len() as u16).to_le_bytes());
            nv.extend_from_slice(&v.quality.to_le_bytes());
            nv.extend_from_slice(v.data);
        }

        debug_assert!(nv.len() <= 0x07FF, "EAP NV payload exceeds 11-bit length field");
        // EtherCAT frame header: type = NV (bits 12..=15), length = NV bytes.
        let word: u16 = FRAME_TYPE_NV_BITS | ((nv.len() as u16) & 0x07FF);

        let mut out = Vec::with_capacity(2 + nv.len());
        out.extend_from_slice(&word.to_le_bytes());
        out.extend_from_slice(&nv);
        out
    }
}
