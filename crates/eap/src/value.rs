//! Helpers to build little-endian byte arrays for EAP variable data, mirroring
//! the `as_*_le` accessors on [`crate::NetworkVariable`].

/// Encode an `f64` (TwinCAT `LREAL`).
pub fn f64_le(v: f64) -> [u8; 8] {
    v.to_le_bytes()
}
/// Encode an `f32` (TwinCAT `REAL`).
pub fn f32_le(v: f32) -> [u8; 4] {
    v.to_le_bytes()
}
/// Encode an `i32` (TwinCAT `DINT`).
pub fn i32_le(v: i32) -> [u8; 4] {
    v.to_le_bytes()
}
/// Encode a `u32` (TwinCAT `UDINT`).
pub fn u32_le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}
/// Encode an `i16` (TwinCAT `INT`).
pub fn i16_le(v: i16) -> [u8; 2] {
    v.to_le_bytes()
}
/// Encode a `bool` (TwinCAT `BOOL`).
pub fn bool_byte(v: bool) -> [u8; 1] {
    [v as u8]
}
