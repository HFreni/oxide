//! encode → decode round-trips for PSN.

use psn::data::DataHeader;
use psn::info::InfoHeader;
use psn::{DataPacket, InfoPacket, Packet, Tracker, TrackerInfo, Vec3};

#[test]
fn data_roundtrip() {
    let original = DataPacket {
        header: Some(DataHeader {
            timestamp_us: 987_654,
            version_high: 2,
            version_low: 0,
            frame_id: 9,
            frame_packet_count: 1,
        }),
        trackers: vec![
            Tracker {
                id: 1,
                position: Some(Vec3::new(1.0, 2.0, 3.0)),
                orientation: Some(Vec3::new(0.1, 0.2, 0.3)),
                status: Some(1.0),
                ..Default::default()
            },
            Tracker {
                id: 5,
                position: Some(Vec3::new(-4.5, 0.0, 9.25)),
                speed: Some(Vec3::new(0.5, 0.0, 0.0)),
                target_position: Some(Vec3::new(10.0, 0.0, 0.0)),
                timestamp_us: Some(123),
                ..Default::default()
            },
        ],
    };

    let bytes = original.encode();
    match Packet::decode(&bytes).unwrap() {
        Packet::Data(decoded) => assert_eq!(decoded, original),
        other => panic!("expected data, got {other:?}"),
    }
}

#[test]
fn info_roundtrip() {
    let original = InfoPacket {
        header: Some(InfoHeader {
            timestamp_us: 42,
            version_high: 2,
            version_low: 0,
            frame_id: 0,
            frame_packet_count: 1,
        }),
        system_name: Some("trimtrack test".into()),
        trackers: vec![
            TrackerInfo { id: 1, name: Some("Performer".into()) },
            TrackerInfo { id: 5, name: Some("Deck".into()) },
        ],
    };

    let bytes = original.encode();
    match Packet::decode(&bytes).unwrap() {
        Packet::Info(decoded) => assert_eq!(decoded, original),
        other => panic!("expected info, got {other:?}"),
    }
}
