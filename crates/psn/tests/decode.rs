//! Round-trip-style decode tests built from hand-assembled PSN bytes.

use psn::{Packet, Vec3};

/// Build a little-endian PSN chunk: id(2) + packed(2) + data.
fn chunk(id: u16, subchunks: bool, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&id.to_le_bytes());
    let mut packed = (data.len() as u16) & 0x7FFF;
    if subchunks {
        packed |= 0x8000;
    }
    v.extend_from_slice(&packed.to_le_bytes());
    v.extend_from_slice(data);
    v
}

fn f32s(values: [f32; 3]) -> Vec<u8> {
    values.iter().flat_map(|f| f.to_le_bytes()).collect()
}

#[test]
fn decodes_data_packet() {
    // PSN_DATA_PACKET_HEADER: u64 timestamp + 4 bytes (vhi, vlo, frame_id, fpc)
    let mut header = Vec::new();
    header.extend_from_slice(&123_456u64.to_le_bytes());
    header.extend_from_slice(&[2, 0, 5, 1]);
    let header_chunk = chunk(0x0000, false, &header);

    // Tracker 7 with position + orientation.
    let pos = chunk(0x0000, false, &f32s([1.0, 2.0, 3.0]));
    let ori = chunk(0x0002, false, &f32s([0.1, 0.2, 0.3]));
    let mut tracker_data = pos.clone();
    tracker_data.extend(ori);
    let tracker = chunk(7, true, &tracker_data);
    let tracker_list = chunk(0x0001, true, &tracker);

    let mut body = header_chunk;
    body.extend(tracker_list);
    let packet = chunk(0x6755, true, &body);

    match Packet::decode(&packet).unwrap() {
        Packet::Data(d) => {
            let h = d.header.expect("header present");
            assert_eq!(h.version_high, 2);
            assert_eq!(h.frame_id, 5);
            assert_eq!(d.trackers.len(), 1);
            let t = &d.trackers[0];
            assert_eq!(t.id, 7);
            assert_eq!(t.position, Some(Vec3::new(1.0, 2.0, 3.0)));
            assert_eq!(t.orientation, Some(Vec3::new(0.1, 0.2, 0.3)));
            assert_eq!(t.speed, None);
        }
        other => panic!("expected data packet, got {other:?}"),
    }
}

#[test]
fn decodes_info_packet() {
    let name = chunk(0x0000, false, b"Tracker A");
    let tracker = chunk(3, true, &name);
    let tracker_list = chunk(0x0002, true, &tracker);
    let system_name = chunk(0x0001, false, b"My PSN Server");

    let mut body = system_name;
    body.extend(tracker_list);
    let packet = chunk(0x6756, true, &body);

    match Packet::decode(&packet).unwrap() {
        Packet::Info(info) => {
            assert_eq!(info.system_name.as_deref(), Some("My PSN Server"));
            assert_eq!(info.trackers.len(), 1);
            assert_eq!(info.trackers[0].id, 3);
            assert_eq!(info.trackers[0].name.as_deref(), Some("Tracker A"));
        }
        other => panic!("expected info packet, got {other:?}"),
    }
}
