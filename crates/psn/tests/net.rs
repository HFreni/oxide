//! End-to-end networking tests for the PSN `net` helpers, plus decoder
//! robustness tests against hostile/truncated input.
//!
//! The round-trip test encodes a `PSN_DATA` packet, sends it over a real UDP
//! multicast socket built by [`psn::net::sender`], and receives it on a socket
//! built by [`psn::net::join_multicast`]. It runs by default because multicast
//! loopback works in this environment; if you observe a recv timeout in a
//! sandbox/CI that blocks multicast loopback, re-add `#[ignore]` to this test.

use std::net::Ipv4Addr;
use std::time::Duration;

use psn::net::{join_multicast, sender, MulticastConfig, SenderConfig};
use psn::{DataPacket, Packet, PsnError, Tracker, Vec3, DEFAULT_MULTICAST_ADDR};

/// Round-trip a real PSN `DataPacket` over loopback multicast.
///
/// `loop_back: true` makes the local kernel deliver the multicast datagram back
/// to sockets on this host. This is honored locally; some CI/sandbox network
/// stacks drop looped-back multicast, in which case the `recv_from` below would
/// time out (2s) — gate this test with `#[ignore]` there.
#[test]
fn data_packet_round_trip_over_multicast() {
    const PORT: u16 = 51010;

    let rx = join_multicast(&MulticastConfig {
        group: DEFAULT_MULTICAST_ADDR,
        port: PORT,
        interface: Ipv4Addr::LOCALHOST,
    })
    .expect("join_multicast");
    rx.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set_read_timeout");

    let tx = sender(&SenderConfig {
        group: DEFAULT_MULTICAST_ADDR,
        port: PORT,
        interface: Ipv4Addr::LOCALHOST,
        ttl: 0,
        loop_back: true,
    })
    .expect("sender");

    let sent = DataPacket {
        header: None,
        trackers: vec![Tracker {
            id: 7,
            position: Some(Vec3::new(1.5, -2.25, 3.75)),
            ..Default::default()
        }],
    };
    let bytes = sent.encode();
    tx.send(&bytes).expect("send");

    let mut buf = [0u8; 1500];
    let (n, _from) = rx.recv_from(&mut buf).expect("recv_from (multicast loopback)");

    match Packet::decode(&buf[..n]).expect("decode") {
        Packet::Data(data) => {
            assert_eq!(data.trackers.len(), 1);
            let t = &data.trackers[0];
            assert_eq!(t.id, 7);
            assert_eq!(t.position, Some(Vec3::new(1.5, -2.25, 3.75)));
        }
        other => panic!("expected Data packet, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Decoder robustness: hostile / malformed input must yield Err, never panic.
// ---------------------------------------------------------------------------

#[test]
fn decode_truncated_buffer_is_err() {
    // Shorter than a single 4-byte chunk header.
    let err = Packet::decode(&[0x55, 0x67]).unwrap_err();
    assert!(matches!(err, PsnError::UnexpectedEof { .. }), "got {err:?}");

    // Empty buffer too.
    assert!(Packet::decode(&[]).is_err());
}

#[test]
fn decode_garbage_root_chunk_is_err() {
    // Valid 4-byte chunk header but an unknown root id (0x1234), zero data.
    let buf = [0x34, 0x12, 0x00, 0x00];
    let err = Packet::decode(&buf).unwrap_err();
    assert!(matches!(err, PsnError::UnknownRootChunk(0x1234)), "got {err:?}");
}

#[test]
fn decode_chunk_overrun_is_err() {
    // Root chunk id = PSN_DATA (0x6755), has_subchunks set, declared data_len
    // = 0x10 (16) but no data bytes follow -> overrun.
    // packed = 0x8000 | 0x0010 = 0x8010 -> bytes 0x10, 0x80 (LE).
    let buf = [0x55, 0x67, 0x10, 0x80];
    let err = Packet::decode(&buf).unwrap_err();
    assert!(matches!(err, PsnError::ChunkOverrun { .. }), "got {err:?}");
}

#[test]
fn decode_nested_chunk_overrun_is_err() {
    // Well-formed root (PSN_DATA, subchunks) whose body is a single child chunk
    // that declares more data than the body actually contains.
    // Inner child: id=0x0000, packed=0x0010 (len 16, no subchunks), no data.
    let inner = [0x00u8, 0x00, 0x10, 0x00];
    let mut buf = Vec::new();
    buf.extend_from_slice(&psn::PSN_DATA_PACKET.to_le_bytes());
    let packed: u16 = 0x8000 | (inner.len() as u16);
    buf.extend_from_slice(&packed.to_le_bytes());
    buf.extend_from_slice(&inner);
    let err = Packet::decode(&buf).unwrap_err();
    assert!(matches!(err, PsnError::ChunkOverrun { .. }), "got {err:?}");
}
