//! PSN encoders: build `PSN_DATA` / `PSN_INFO` datagrams from the typed
//! structs. The inverse of [`crate::data`] / [`crate::info`].
//!
//! These produce a single datagram. PSN allows a frame to be split across
//! several UDP packets (via `frame_packet_count`); splitting very large tracker
//! lists is left to the caller — set the header fields accordingly.

use crate::data::{DataHeader, DataPacket};
use crate::info::InfoPacket;
use crate::Vec3;

/// Append a PSN chunk (little-endian header + data) to `out`.
fn write_chunk(out: &mut Vec<u8>, id: u16, has_subchunks: bool, data: &[u8]) {
    debug_assert!(data.len() <= 0x7FFF, "PSN chunk data exceeds 15-bit length");
    out.extend_from_slice(&id.to_le_bytes());
    let mut packed = (data.len() as u16) & 0x7FFF;
    if has_subchunks {
        packed |= 0x8000;
    }
    out.extend_from_slice(&packed.to_le_bytes());
    out.extend_from_slice(data);
}

fn vec3_bytes(v: Vec3) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&v.x.to_le_bytes());
    b[4..8].copy_from_slice(&v.y.to_le_bytes());
    b[8..12].copy_from_slice(&v.z.to_le_bytes());
    b
}

fn header_bytes(h: &DataHeader) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    v.extend_from_slice(&h.timestamp_us.to_le_bytes());
    v.push(h.version_high);
    v.push(h.version_low);
    v.push(h.frame_id);
    v.push(h.frame_packet_count);
    v
}

/// Default header for PSN v2 (`version 2.0`, single-packet frame).
fn default_header() -> DataHeader {
    DataHeader {
        timestamp_us: 0,
        version_high: 2,
        version_low: 0,
        frame_id: 0,
        frame_packet_count: 1,
    }
}

impl DataPacket {
    /// Encode this packet into a single `PSN_DATA` datagram. If `header` is
    /// `None`, a default PSN v2 header is synthesized.
    pub fn encode(&self) -> Vec<u8> {
        let header = self.header.unwrap_or_else(default_header);
        let mut header_chunk = Vec::new();
        write_chunk(&mut header_chunk, 0x0000, false, &header_bytes(&header));

        let mut list = Vec::new();
        for t in &self.trackers {
            let mut body = Vec::new();
            if let Some(p) = t.position {
                write_chunk(&mut body, 0x0000, false, &vec3_bytes(p));
            }
            if let Some(s) = t.speed {
                write_chunk(&mut body, 0x0001, false, &vec3_bytes(s));
            }
            if let Some(o) = t.orientation {
                write_chunk(&mut body, 0x0002, false, &vec3_bytes(o));
            }
            if let Some(st) = t.status {
                write_chunk(&mut body, 0x0003, false, &st.to_le_bytes());
            }
            if let Some(a) = t.acceleration {
                write_chunk(&mut body, 0x0004, false, &vec3_bytes(a));
            }
            if let Some(tp) = t.target_position {
                write_chunk(&mut body, 0x0005, false, &vec3_bytes(tp));
            }
            if let Some(ts) = t.timestamp_us {
                write_chunk(&mut body, 0x0006, false, &ts.to_le_bytes());
            }
            write_chunk(&mut list, t.id, true, &body);
        }
        let mut list_chunk = Vec::new();
        write_chunk(&mut list_chunk, 0x0001, true, &list);

        let mut packet_body = header_chunk;
        packet_body.extend(list_chunk);
        let mut out = Vec::new();
        write_chunk(&mut out, crate::PSN_DATA_PACKET, true, &packet_body);
        out
    }
}

impl InfoPacket {
    /// Encode this packet into a single `PSN_INFO` datagram.
    pub fn encode(&self) -> Vec<u8> {
        let mut packet_body = Vec::new();

        if let Some(h) = self.header {
            // Info and data headers share a layout.
            let dh = DataHeader {
                timestamp_us: h.timestamp_us,
                version_high: h.version_high,
                version_low: h.version_low,
                frame_id: h.frame_id,
                frame_packet_count: h.frame_packet_count,
            };
            write_chunk(&mut packet_body, 0x0000, false, &header_bytes(&dh));
        }
        if let Some(name) = &self.system_name {
            write_chunk(&mut packet_body, 0x0001, false, name.as_bytes());
        }

        let mut list = Vec::new();
        for t in &self.trackers {
            let mut body = Vec::new();
            if let Some(name) = &t.name {
                write_chunk(&mut body, 0x0000, false, name.as_bytes());
            }
            write_chunk(&mut list, t.id, true, &body);
        }
        let mut list_chunk = Vec::new();
        write_chunk(&mut list_chunk, 0x0002, true, &list);
        packet_body.extend(list_chunk);

        let mut out = Vec::new();
        write_chunk(&mut out, crate::PSN_INFO_PACKET, true, &packet_body);
        out
    }
}
