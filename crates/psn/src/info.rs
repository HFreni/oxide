//! `PSN_INFO` packet: system name and tracker names.
//!
//! Sent at a low rate alongside `PSN_DATA` so receivers can label trackers.
//!
//! ```text
//! PSN_INFO_PACKET (0x6756) [subchunks]
//! ├─ PSN_INFO_PACKET_HEADER (0x0000)   (same layout as the data header)
//! ├─ PSN_INFO_SYSTEM_NAME   (0x0001)   UTF-8 string
//! └─ PSN_INFO_TRACKER_LIST  (0x0002) [subchunks]
//!    └─ <tracker_id> [subchunks]
//!       └─ PSN_INFO_TRACKER_NAME (0x0000)  UTF-8 string
//! ```

use crate::chunk::ChunkReader;
use crate::read::{utf8_string, Cursor};
use crate::PsnError;

const INFO_PACKET_HEADER: u16 = 0x0000;
const INFO_SYSTEM_NAME: u16 = 0x0001;
const INFO_TRACKER_LIST: u16 = 0x0002;

const INFO_TRACKER_NAME: u16 = 0x0000;

/// The `PSN_INFO_PACKET_HEADER`, identical in layout to the data header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InfoHeader {
    /// Server send timestamp, microseconds.
    pub timestamp_us: u64,
    /// High byte of the protocol version.
    pub version_high: u8,
    /// Low byte of the protocol version.
    pub version_low: u8,
    /// Frame id.
    pub frame_id: u8,
    /// Number of UDP packets in this info frame.
    pub frame_packet_count: u8,
}

impl InfoHeader {
    fn decode(data: &[u8]) -> Result<Self, PsnError> {
        let mut c = Cursor::new(data);
        Ok(Self {
            timestamp_us: c.u64()?,
            version_high: c.u8()?,
            version_low: c.u8()?,
            frame_id: c.u8()?,
            frame_packet_count: c.u8()?,
        })
    }
}

/// A tracker's advertised name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerInfo {
    /// Tracker id (the sub-chunk id within the tracker list).
    pub id: u16,
    /// Human-readable tracker name, if present.
    pub name: Option<String>,
}

/// A fully decoded `PSN_INFO` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct InfoPacket {
    /// Packet header, if present.
    pub header: Option<InfoHeader>,
    /// The system / server name, if present.
    pub system_name: Option<String>,
    /// Per-tracker name advertisements.
    pub trackers: Vec<TrackerInfo>,
}

impl InfoPacket {
    /// Decode the body of a `PSN_INFO_PACKET` (the bytes *inside* the root
    /// chunk).
    pub fn decode(body: &[u8]) -> Result<Self, PsnError> {
        let mut header = None;
        let mut system_name = None;
        let mut trackers = Vec::new();
        for chunk in ChunkReader::new(body) {
            let chunk = chunk?;
            match chunk.header.id {
                INFO_PACKET_HEADER => header = Some(InfoHeader::decode(chunk.data)?),
                INFO_SYSTEM_NAME => system_name = Some(utf8_string(chunk.data)?),
                INFO_TRACKER_LIST => {
                    for tracker_chunk in chunk.children() {
                        let tc = tracker_chunk?;
                        let mut name = None;
                        for field in tc.children() {
                            let field = field?;
                            if field.header.id == INFO_TRACKER_NAME {
                                name = Some(utf8_string(field.data)?);
                            }
                        }
                        trackers.push(TrackerInfo { id: tc.header.id, name });
                    }
                }
                _ => {}
            }
        }
        Ok(Self { header, system_name, trackers })
    }
}
