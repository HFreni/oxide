//! Transform-message layer: systems → points → modules.
//!
//! ```text
//! Transform Layer  (base Vector = 0x0001)
//!   u8  system          u64 timestamp   u8 options(bit7 = full point set)  u32 reserved
//!   └─ Point PDU (Vector 0x0001), repeated:
//!        u8 priority   u16 group   u32 point   u64 timestamp   u8 options   u32 reserved
//!        └─ Module PDU (vector = manufacturer id), repeated:
//!             u16 module_number   <module data>
//! ```

use crate::modules::{self, Address};
use crate::pdu::PduReader;
use crate::read::Cursor;
use crate::{OtpError, Vec3};

/// Vector value (in the base layer) selecting the transform message.
pub const VECTOR_TRANSFORM: u16 = 0x0001;
/// Vector value selecting a Point PDU inside the transform / a Module PDU
/// inside a point.
pub const VECTOR_POINT: u16 = 0x0001;

/// One point's accumulated transform. Module fields are optional because a
/// sender includes only the modules it has data for.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Point {
    /// Full system/group/point address.
    pub address: Address,
    /// Transmission priority (0..=200; higher wins on merge).
    pub priority: u8,
    /// Point timestamp, microseconds.
    pub timestamp_us: u64,
    /// Position, metres.
    pub position: Option<Vec3>,
    /// Linear velocity, m/s.
    pub velocity: Option<Vec3>,
    /// Linear acceleration, m/s².
    pub acceleration: Option<Vec3>,
    /// Rotation (Euler ZYX intrinsic), degrees.
    pub rotation: Option<Vec3>,
    /// Rotation velocity, deg/s.
    pub rotation_velocity: Option<Vec3>,
    /// Rotation acceleration, deg/s².
    pub rotation_acceleration: Option<Vec3>,
    /// Scale, unitless (1.0 = reference size).
    pub scale: Option<Vec3>,
    /// Reference-frame address this point's transform is relative to.
    pub reference_frame: Option<Address>,
}

/// A decoded transform message for a single OTP system.
#[derive(Debug, Clone, PartialEq)]
pub struct TransformMessage {
    /// System number this message describes.
    pub system: u8,
    /// Message timestamp, microseconds.
    pub timestamp_us: u64,
    /// Whether this message is a full snapshot of the system's points (vs. a
    /// partial update).
    pub full_point_set: bool,
    /// Points carried in this message.
    pub points: Vec<Point>,
}

impl TransformMessage {
    /// Decode a transform-layer body (the bytes inside the transform PDU).
    pub fn decode(body: &[u8]) -> Result<Self, OtpError> {
        let mut c = Cursor::new(body);
        let system = c.u8()?;
        let timestamp_us = c.u64()?;
        let options = c.u8()?;
        c.skip(4)?; // reserved
        let full_point_set = options & 0x80 != 0;

        let points_buf = &body[c.position()..];
        let mut points = Vec::new();
        for point_pdu in PduReader::new(points_buf) {
            let point_pdu = point_pdu?;
            if point_pdu.vector != VECTOR_POINT {
                continue;
            }
            points.push(decode_point(system, point_pdu.body)?);
        }
        Ok(Self { system, timestamp_us, full_point_set, points })
    }
}

fn decode_point(system: u8, body: &[u8]) -> Result<Point, OtpError> {
    let mut c = Cursor::new(body);
    let priority = c.u8()?;
    let group = c.u16()?;
    let point_num = c.u32()?;
    let timestamp_us = c.u64()?;
    let _options = c.u8()?;
    c.skip(4)?; // reserved

    let mut point = Point {
        address: Address { system, group, point: point_num },
        priority,
        timestamp_us,
        ..Default::default()
    };

    let modules_buf = &body[c.position()..];
    for module_pdu in PduReader::new(modules_buf) {
        let module_pdu = module_pdu?;
        // module_pdu.vector is the Manufacturer ID.
        if module_pdu.vector != modules::MANUFACTURER_ESTA {
            continue; // skip manufacturer-specific modules
        }
        let mut mc = Cursor::new(module_pdu.body);
        let module_number = mc.u16()?;
        let data = &module_pdu.body[mc.position()..];
        apply_module(&mut point, module_number, data)?;
    }
    Ok(point)
}

fn apply_module(point: &mut Point, number: u16, data: &[u8]) -> Result<(), OtpError> {
    use modules::number::*;
    match number {
        POSITION => point.position = Some(modules::decode_position(data)?),
        POSITION_VEL_ACCEL => {
            let (v, a) = modules::decode_position_vel_accel(data)?;
            point.velocity = Some(v);
            point.acceleration = Some(a);
        }
        ROTATION => point.rotation = Some(modules::decode_rotation(data)?),
        ROTATION_VEL_ACCEL => {
            let (v, a) = modules::decode_rotation_vel_accel(data)?;
            point.rotation_velocity = Some(v);
            point.rotation_acceleration = Some(a);
        }
        SCALE => point.scale = Some(modules::decode_scale(data)?),
        REFERENCE_FRAME => point.reference_frame = Some(modules::decode_reference_frame(data)?),
        _ => {} // unknown standard module: ignore
    }
    Ok(())
}
