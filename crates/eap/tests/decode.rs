//! Decode test built from hand-assembled EAP Network Variables bytes (LE).

use eap::PublisherTelegram;

#[test]
fn decodes_two_variables() {
    let mut payload = Vec::new();

    // EtherCAT frame header: type = 4 (NV) in bits 12..=15, length in 0..=10.
    // We set type=4; the length value is not strictly validated by the decoder.
    let frame_word: u16 = 0x4000 | 0x20;
    payload.extend_from_slice(&frame_word.to_le_bytes());

    // NV header (12 bytes): publisher[6], count, cycle_index, reserved.
    payload.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // publisher
    payload.extend_from_slice(&2u16.to_le_bytes()); // count
    payload.extend_from_slice(&77u16.to_le_bytes()); // cycle index
    payload.extend_from_slice(&0u16.to_le_bytes()); // reserved

    // Variable 1: id=1, f64 = 12.5
    payload.extend_from_slice(&1u16.to_le_bytes()); // id
    payload.extend_from_slice(&0x1234u16.to_le_bytes()); // hash
    payload.extend_from_slice(&8u16.to_le_bytes()); // length
    payload.extend_from_slice(&0u16.to_le_bytes()); // quality
    payload.extend_from_slice(&12.5f64.to_le_bytes()); // data

    // Variable 2: id=2, i32 = -7
    payload.extend_from_slice(&2u16.to_le_bytes()); // id
    payload.extend_from_slice(&0xABCDu16.to_le_bytes()); // hash
    payload.extend_from_slice(&4u16.to_le_bytes()); // length
    payload.extend_from_slice(&1u16.to_le_bytes()); // quality
    payload.extend_from_slice(&(-7i32).to_le_bytes()); // data

    let telegram = PublisherTelegram::decode(&payload).expect("decode");
    assert_eq!(telegram.publisher, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    assert_eq!(telegram.cycle_index, 77);
    assert_eq!(telegram.variables.len(), 2);

    let v1 = &telegram.variables[0];
    assert_eq!(v1.id, 1);
    assert_eq!(v1.hash, 0x1234);
    assert_eq!(v1.as_f64_le(), Some(12.5));

    let v2 = &telegram.variables[1];
    assert_eq!(v2.id, 2);
    assert_eq!(v2.quality, 1);
    assert_eq!(v2.as_i32_le(), Some(-7));
}

#[test]
fn rejects_non_nv_frame() {
    // type = 1 (EtherCAT command), not NV.
    let payload = 0x1000u16.to_le_bytes();
    assert!(PublisherTelegram::decode(&payload).is_err());
}
