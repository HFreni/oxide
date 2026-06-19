//! encode → decode round-trip for OTP.

use otp::modules::Address;
use otp::transform::Point;
use otp::{Message, OtpLayer, Packet, TransformMessage, Vec3};

#[test]
fn transform_roundtrip() {
    let original = Packet {
        layer: OtpLayer {
            cid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            folio: 42,
            page: 0,
            last_page: 0,
            component_name: "trimtrack".into(),
        },
        message: Message::Transform(TransformMessage {
            system: 3,
            timestamp_us: 1_000_000,
            full_point_set: true,
            points: vec![
                Point {
                    address: Address { system: 3, group: 1, point: 100 },
                    priority: 120,
                    timestamp_us: 555,
                    position: Some(Vec3::new(1.5, -2.0, 3.25)),
                    rotation: Some(Vec3::new(90.0, 180.0, 270.0)),
                    scale: Some(Vec3::new(1.0, 1.0, 2.0)),
                    ..Default::default()
                },
                Point {
                    address: Address { system: 3, group: 2, point: 7 },
                    priority: 100,
                    timestamp_us: 556,
                    position: Some(Vec3::new(0.0, 0.0, 0.0)),
                    // Values chosen to be exact through the integer-µm round-trip
                    // (OTP stores scaled integers, so arbitrary decimals like 0.1
                    // are not bit-exact after decode).
                    velocity: Some(Vec3::new(0.5, 0.0, 0.0)),
                    acceleration: Some(Vec3::new(0.25, 0.0, 0.0)),
                    reference_frame: Some(Address { system: 3, group: 1, point: 100 }),
                    ..Default::default()
                },
            ],
        }),
    };

    let bytes = original.encode();
    let decoded = Packet::decode(&bytes).expect("decode");
    assert_eq!(decoded, original);
}
