//! `PSN_DATA` packet: live tracker transforms.
//!
//! ```text
//! PSN_DATA_PACKET (0x6755) [subchunks]
//! ├─ PSN_DATA_PACKET_HEADER (0x0000)
//! │    u64 timestamp_us, u8 version_high, u8 version_low, u8 frame_id, u8 frame_packet_count
//! └─ PSN_DATA_TRACKER_LIST (0x0001) [subchunks]
//!    └─ <tracker_id> [subchunks]
//!       ├─ POS       (0x0000)  Vec3 metres
//!       ├─ SPEED     (0x0001)  Vec3 m/s
//!       ├─ ORI       (0x0002)  Vec3 radians
//!       ├─ STATUS    (0x0003)  f32 validity 0..1
//!       ├─ ACCEL     (0x0004)  Vec3 m/s²
//!       ├─ TRGTPOS   (0x0005)  Vec3 metres
//!       └─ TIMESTAMP (0x0006)  u64 microseconds
//! ```

use crate::chunk::ChunkReader;
use crate::read::Cursor;
use crate::{PsnError, Vec3};

const DATA_PACKET_HEADER: u16 = 0x0000;
const DATA_TRACKER_LIST: u16 = 0x0001;

const TRACKER_POS: u16 = 0x0000;
const TRACKER_SPEED: u16 = 0x0001;
const TRACKER_ORI: u16 = 0x0002;
const TRACKER_STATUS: u16 = 0x0003;
const TRACKER_ACCEL: u16 = 0x0004;
const TRACKER_TRGTPOS: u16 = 0x0005;
const TRACKER_TIMESTAMP: u16 = 0x0006;

/// The `PSN_DATA_PACKET_HEADER` fields shared by every datagram in a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeader {
    /// Server send timestamp, in microseconds.
    pub timestamp_us: u64,
    /// High byte of the protocol version (2 for PSN v2).
    pub version_high: u8,
    /// Low byte of the protocol version.
    pub version_low: u8,
    /// Frame id; increments once per full frame of tracker data.
    pub frame_id: u8,
    /// Number of UDP packets that make up this frame (frames may be split).
    pub frame_packet_count: u8,
}

impl DataHeader {
    fn decode(data: &[u8]) -> Result<Self, PsnError> {
        let mut c = Cursor::new(data);
        let timestamp_us = c.u64()?;
        Ok(Self {
            timestamp_us,
            version_high: c.u8()?,
            version_low: c.u8()?,
            frame_id: c.u8()?,
            frame_packet_count: c.u8()?,
        })
    }
}

/// One tracker's transform within a [`DataPacket`]. Every field is optional
/// because a sender transmits only the modules it has data for.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Tracker {
    /// Tracker id (the sub-chunk id within the tracker list).
    pub id: u16,
    /// Absolute position, metres.
    pub position: Option<Vec3>,
    /// Linear velocity, m/s.
    pub speed: Option<Vec3>,
    /// Orientation as rotation about each axis, radians.
    pub orientation: Option<Vec3>,
    /// Validity / tracking confidence, `0.0..=1.0`.
    pub status: Option<f32>,
    /// Linear acceleration, m/s².
    pub acceleration: Option<Vec3>,
    /// Target position, metres (where the object is heading).
    pub target_position: Option<Vec3>,
    /// Per-tracker capture timestamp, microseconds.
    pub timestamp_us: Option<u64>,
}

impl Tracker {
    fn decode(id: u16, data: &[u8]) -> Result<Self, PsnError> {
        let mut t = Tracker { id, ..Default::default() };
        for chunk in ChunkReader::new(data) {
            let chunk = chunk?;
            let mut c = Cursor::new(chunk.data);
            match chunk.header.id {
                TRACKER_POS => t.position = Some(c.vec3()?),
                TRACKER_SPEED => t.speed = Some(c.vec3()?),
                TRACKER_ORI => t.orientation = Some(c.vec3()?),
                TRACKER_STATUS => t.status = Some(c.f32()?),
                TRACKER_ACCEL => t.acceleration = Some(c.vec3()?),
                TRACKER_TRGTPOS => t.target_position = Some(c.vec3()?),
                TRACKER_TIMESTAMP => t.timestamp_us = Some(c.u64()?),
                // Unknown future sub-chunks are skipped, not fatal.
                _ => {}
            }
        }
        Ok(t)
    }
}

/// A fully decoded `PSN_DATA` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct DataPacket {
    /// Packet header (may be absent on malformed senders; required by spec).
    pub header: Option<DataHeader>,
    /// Trackers present in this datagram.
    pub trackers: Vec<Tracker>,
}

impl DataPacket {
    /// Decode the body of a `PSN_DATA_PACKET` (the bytes *inside* the root
    /// chunk).
    pub fn decode(body: &[u8]) -> Result<Self, PsnError> {
        let mut header = None;
        let mut trackers = Vec::new();
        for chunk in ChunkReader::new(body) {
            let chunk = chunk?;
            match chunk.header.id {
                DATA_PACKET_HEADER => header = Some(DataHeader::decode(chunk.data)?),
                DATA_TRACKER_LIST => {
                    for tracker_chunk in chunk.children() {
                        let tc = tracker_chunk?;
                        trackers.push(Tracker::decode(tc.header.id, tc.data)?);
                    }
                }
                _ => {}
            }
        }
        Ok(Self { header, trackers })
    }
}
