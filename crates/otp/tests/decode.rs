//! Decode test built from hand-assembled OTP bytes (big-endian, layered PDUs).

use otp::{Message, Packet, PACKET_IDENT, VECTOR_TRANSFORM_MESSAGE};

/// Build a big-endian OTP PDU: vector(2) + length(2) + body.
fn pdu(vector: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&vector.to_be_bytes());
    v.extend_from_slice(&(body.len() as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

#[test]
fn decodes_transform_position() {
    // Position module (0x0001): options(1) + X,Y,Z i32 BE, µm when bit7 == 0.
    let mut module_body = Vec::new();
    module_body.extend_from_slice(&0x0001u16.to_be_bytes()); // module number
    module_body.push(0); // options: bit7 clear -> µm
    module_body.extend_from_slice(&1_500_000i32.to_be_bytes()); // 1.5 m
    module_body.extend_from_slice(&(-2_000_000i32).to_be_bytes()); // -2.0 m
    module_body.extend_from_slice(&3_250_000i32.to_be_bytes()); // 3.25 m
    let module = pdu(0x0000, &module_body); // manufacturer ESTA

    // Point layer body: priority + group + point + timestamp + options + reserved.
    let mut point_body = Vec::new();
    point_body.push(100); // priority
    point_body.extend_from_slice(&5u16.to_be_bytes()); // group
    point_body.extend_from_slice(&42u32.to_be_bytes()); // point
    point_body.extend_from_slice(&999u64.to_be_bytes()); // timestamp
    point_body.push(0); // options
    point_body.extend_from_slice(&0u32.to_be_bytes()); // reserved
    point_body.extend(module);
    let point = pdu(0x0001, &point_body);

    // Transform layer body: system + timestamp + options + reserved + points.
    let mut transform_body = Vec::new();
    transform_body.push(1); // system
    transform_body.extend_from_slice(&12345u64.to_be_bytes()); // timestamp
    transform_body.push(0x80); // options: full point set
    transform_body.extend_from_slice(&0u32.to_be_bytes()); // reserved
    transform_body.extend(point);
    let transform = pdu(VECTOR_TRANSFORM_MESSAGE, &transform_body);

    // Base-layer fields (63 octets) + the transform sub-layer PDU.
    let mut base_body = Vec::new();
    base_body.push(0); // footer options
    base_body.push(0); // footer length
    base_body.extend_from_slice(&[0u8; 16]); // CID
    base_body.extend_from_slice(&7u32.to_be_bytes()); // folio
    base_body.extend_from_slice(&0u16.to_be_bytes()); // page
    base_body.extend_from_slice(&0u16.to_be_bytes()); // last page
    base_body.push(0); // options
    base_body.extend_from_slice(&0u32.to_be_bytes()); // reserved
    let mut name = [0u8; 32];
    name[..6].copy_from_slice(b"trimtk");
    base_body.extend_from_slice(&name);
    base_body.extend(transform);

    let mut packet = Vec::new();
    packet.extend_from_slice(PACKET_IDENT);
    packet.extend(pdu(VECTOR_TRANSFORM_MESSAGE, &base_body));

    let decoded = Packet::decode(&packet).expect("decode");
    assert_eq!(decoded.layer.folio, 7);
    assert_eq!(decoded.layer.component_name, "trimtk");
    match decoded.message {
        Message::Transform(t) => {
            assert_eq!(t.system, 1);
            assert!(t.full_point_set);
            assert_eq!(t.points.len(), 1);
            let p = &t.points[0];
            assert_eq!(p.address.system, 1);
            assert_eq!(p.address.group, 5);
            assert_eq!(p.address.point, 42);
            assert_eq!(p.priority, 100);
            let pos = p.position.expect("position");
            assert!((pos.x - 1.5).abs() < 1e-9, "x = {}", pos.x);
            assert!((pos.y + 2.0).abs() < 1e-9, "y = {}", pos.y);
            assert!((pos.z - 3.25).abs() < 1e-9, "z = {}", pos.z);
        }
        other => panic!("expected transform, got {other:?}"),
    }
}
