//! Standard ESTA modules (Manufacturer ID `0x0000`).
//!
//! Each module carries one aspect of a point's transform. On the wire, values
//! are scaled integers; this module converts them to SI-ish `f64`:
//!
//! | Module | # | Decoded as |
//! |--------|---|------------|
//! | Position | `0x0001` | metres (from µm or mm per a scaling bit) |
//! | Position Velocity/Accel | `0x0002` | m/s and m/s² (from µm) |
//! | Rotation | `0x0003` | degrees (from millionths of a degree) |
//! | Rotation Velocity/Accel | `0x0004` | deg/s and deg/s² (from thousandths) |
//! | Scale | `0x0005` | unitless, 1.0 = reference (from millionths) |
//! | Reference Frame | `0x0006` | system/group/point address |

use crate::read::Cursor;
use crate::{OtpError, Vec3};

/// ESTA standard manufacturer id.
pub const MANUFACTURER_ESTA: u16 = 0x0000;

/// Module numbers for the standard ESTA modules.
pub mod number {
    /// Position module.
    pub const POSITION: u16 = 0x0001;
    /// Position velocity/acceleration module.
    pub const POSITION_VEL_ACCEL: u16 = 0x0002;
    /// Rotation module.
    pub const ROTATION: u16 = 0x0003;
    /// Rotation velocity/acceleration module.
    pub const ROTATION_VEL_ACCEL: u16 = 0x0004;
    /// Scale module.
    pub const SCALE: u16 = 0x0005;
    /// Reference-frame module.
    pub const REFERENCE_FRAME: u16 = 0x0006;
}

/// An OTP point address: system, group, point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Address {
    /// System number (1..=200).
    pub system: u8,
    /// Group number.
    pub group: u16,
    /// Point number.
    pub point: u32,
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.system, self.group, self.point)
    }
}

/// Decode the Position module (`0x0001`), returning metres.
pub fn decode_position(data: &[u8]) -> Result<Vec3, OtpError> {
    let mut c = Cursor::new(data);
    let options = c.u8()?;
    // Bit 7: 0 => values are in µm, 1 => values are in mm.
    let scale = if options & 0x80 != 0 { 1e-3 } else { 1e-6 };
    Ok(Vec3 {
        x: c.i32()? as f64 * scale,
        y: c.i32()? as f64 * scale,
        z: c.i32()? as f64 * scale,
    })
}

/// Linear velocity (m/s) and acceleration (m/s²) from the Position
/// Velocity/Acceleration module (`0x0002`).
pub fn decode_position_vel_accel(data: &[u8]) -> Result<(Vec3, Vec3), OtpError> {
    let mut c = Cursor::new(data);
    let vel = Vec3 {
        x: c.i32()? as f64 * 1e-6,
        y: c.i32()? as f64 * 1e-6,
        z: c.i32()? as f64 * 1e-6,
    };
    let accel = Vec3 {
        x: c.i32()? as f64 * 1e-6,
        y: c.i32()? as f64 * 1e-6,
        z: c.i32()? as f64 * 1e-6,
    };
    Ok((vel, accel))
}

/// Decode the Rotation module (`0x0003`), returning degrees. Values are
/// unsigned millionths of a degree (0..360_000_000).
pub fn decode_rotation(data: &[u8]) -> Result<Vec3, OtpError> {
    let mut c = Cursor::new(data);
    Ok(Vec3 {
        x: c.u32()? as f64 * 1e-6,
        y: c.u32()? as f64 * 1e-6,
        z: c.u32()? as f64 * 1e-6,
    })
}

/// Rotation velocity (deg/s) and acceleration (deg/s²) from the Rotation
/// Velocity/Acceleration module (`0x0004`). Values are signed thousandths.
pub fn decode_rotation_vel_accel(data: &[u8]) -> Result<(Vec3, Vec3), OtpError> {
    let mut c = Cursor::new(data);
    let vel = Vec3 {
        x: c.i32()? as f64 * 1e-3,
        y: c.i32()? as f64 * 1e-3,
        z: c.i32()? as f64 * 1e-3,
    };
    let accel = Vec3 {
        x: c.i32()? as f64 * 1e-3,
        y: c.i32()? as f64 * 1e-3,
        z: c.i32()? as f64 * 1e-3,
    };
    Ok((vel, accel))
}

/// Decode the Scale module (`0x0005`); `1.0` is reference size. Values are
/// signed millionths.
pub fn decode_scale(data: &[u8]) -> Result<Vec3, OtpError> {
    let mut c = Cursor::new(data);
    Ok(Vec3 {
        x: c.i32()? as f64 * 1e-6,
        y: c.i32()? as f64 * 1e-6,
        z: c.i32()? as f64 * 1e-6,
    })
}

/// Decode the Reference Frame module (`0x0006`).
pub fn decode_reference_frame(data: &[u8]) -> Result<Address, OtpError> {
    let mut c = Cursor::new(data);
    Ok(Address {
        system: c.u8()?,
        group: c.u16()?,
        point: c.u32()?,
    })
}
