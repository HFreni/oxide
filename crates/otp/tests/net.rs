//! End-to-end networking tests for the OTP `net` helpers, plus decoder
//! robustness tests against hostile/truncated input.
//!
//! The round-trip test encodes a transform `Packet`, sends it to the system-1
//! transform multicast group via [`otp::net::send_transform`], and receives it
//! on a socket built by [`otp::net::join_multicast`]. Multicast loopback can be
//! blocked in some sandboxes/CI; that test is `#[ignore]`d there (see its doc
//! comment), but it passes locally when multicast loopback is available.
//!
//! Note: OTP's `send_transform` always targets the fixed OTP `PORT` (5568) and
//! the per-system multicast group (`239.159.1.<system>`), so this test uses the
//! default port and isolates itself by using a dedicated system number.

use std::net::Ipv4Addr;
use std::time::Duration;

use otp::net::{join_multicast, send_transform, sender, MulticastConfig, SenderConfig};
use otp::{Address, Message, OtpError, OtpLayer, Packet, Point, TransformMessage, Vec3, PACKET_IDENT};

const TEST_SYSTEM: u8 = 1;

fn sample_packet() -> Packet {
    Packet {
        layer: OtpLayer {
            cid: [0xAB; 16],
            folio: 42,
            page: 0,
            last_page: 0,
            component_name: "oxide-test".to_string(),
        },
        message: Message::Transform(TransformMessage {
            system: TEST_SYSTEM,
            timestamp_us: 1_234_567,
            full_point_set: true,
            points: vec![Point {
                address: Address { system: TEST_SYSTEM, group: 5, point: 9 },
                priority: 100,
                timestamp_us: 7_654_321,
                position: Some(Vec3::new(1.0, 2.0, 3.0)),
                ..Default::default()
            }],
        }),
    }
}

/// Round-trip a real OTP transform `Packet` over loopback multicast.
///
/// `loop_back: true` makes the kernel deliver the multicast datagram back to
/// sockets on this host. This is honored locally; some CI/sandbox network
/// stacks drop looped-back multicast, in which case the `recv_from` below would
/// time out (2s) — gate this test with `#[ignore]` there.
#[test]
fn transform_round_trip_over_multicast() {
    let rx = join_multicast(&MulticastConfig {
        systems: vec![TEST_SYSTEM],
        join_advertisement: false,
        port: otp::PORT,
        interface: Ipv4Addr::LOCALHOST,
    })
    .expect("join_multicast");
    rx.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set_read_timeout");

    let tx = sender(&SenderConfig {
        interface: Ipv4Addr::LOCALHOST,
        ttl: 0,
        loop_back: true,
    })
    .expect("sender");

    let sent = sample_packet();
    let bytes = sent.encode();
    send_transform(&tx, TEST_SYSTEM, &bytes).expect("send_transform");

    let mut buf = [0u8; 1500];
    let (n, _from) = rx.recv_from(&mut buf).expect("recv_from (multicast loopback)");

    let decoded = Packet::decode(&buf[..n]).expect("decode");
    assert_eq!(decoded.layer.cid, [0xAB; 16]);
    assert_eq!(decoded.layer.folio, 42);
    assert_eq!(decoded.layer.component_name, "oxide-test");
    match decoded.message {
        Message::Transform(t) => {
            assert_eq!(t.system, TEST_SYSTEM);
            assert_eq!(t.points.len(), 1);
            let p = &t.points[0];
            assert_eq!(p.address, Address { system: TEST_SYSTEM, group: 5, point: 9 });
            assert_eq!(p.priority, 100);
            let pos = p.position.expect("position present");
            // Position round-trips through µm-scaled i32; allow rounding slack.
            assert!((pos.x - 1.0).abs() < 1e-6, "x = {}", pos.x);
            assert!((pos.y - 2.0).abs() < 1e-6, "y = {}", pos.y);
            assert!((pos.z - 3.0).abs() < 1e-6, "z = {}", pos.z);
        }
        other => panic!("expected Transform message, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Decoder robustness: hostile / malformed input must yield Err, never panic.
// ---------------------------------------------------------------------------

#[test]
fn decode_truncated_buffer_is_err() {
    // Shorter than the 12-byte packet identifier.
    let err = Packet::decode(&[0x4F, 0x54, 0x50]).unwrap_err();
    assert!(matches!(err, OtpError::TooShort(3)), "got {err:?}");

    assert!(Packet::decode(&[]).is_err());
}

#[test]
fn decode_bad_identifier_is_err() {
    // 12 bytes of the wrong identifier, plus some filler.
    let mut buf = vec![0u8; 32];
    buf[..12].copy_from_slice(b"NOT-OTP\0\0\0\0\0");
    let err = Packet::decode(&buf).unwrap_err();
    assert_eq!(err, OtpError::BadIdentifier);
}

#[test]
fn decode_base_pdu_overrun_is_err() {
    // Correct identifier, then a base PDU whose declared length overruns.
    let mut buf = Vec::new();
    buf.extend_from_slice(PACKET_IDENT);
    buf.extend_from_slice(&otp::VECTOR_TRANSFORM_MESSAGE.to_be_bytes()); // vector
    buf.extend_from_slice(&0xFFFFu16.to_be_bytes()); // length way past buffer
    // no body bytes follow
    let err = Packet::decode(&buf).unwrap_err();
    assert!(matches!(err, OtpError::PduOverrun { .. }), "got {err:?}");
}

#[test]
fn decode_unknown_vector_is_err() {
    // Build a minimal but well-formed base PDU with an unknown base vector so
    // the decoder reaches the vector dispatch and reports UnknownVector.
    // Base body = 1(footer opt)+1(footer len)+16(cid)+4(folio)+2(page)+
    //             2(last_page)+1(opt)+4(reserved)+32(name) = 63 bytes, then a
    //             4-byte empty sub-PDU.
    let mut base_body = Vec::new();
    base_body.push(0); // footer options
    base_body.push(0); // footer length
    base_body.extend_from_slice(&[0u8; 16]); // cid
    base_body.extend_from_slice(&0u32.to_be_bytes()); // folio
    base_body.extend_from_slice(&0u16.to_be_bytes()); // page
    base_body.extend_from_slice(&0u16.to_be_bytes()); // last_page
    base_body.push(0); // options
    base_body.extend_from_slice(&0u32.to_be_bytes()); // reserved
    base_body.extend_from_slice(&[0u8; 32]); // component name
    // empty sub-PDU: vector 0x0000, length 0
    base_body.extend_from_slice(&0u16.to_be_bytes());
    base_body.extend_from_slice(&0u16.to_be_bytes());

    let mut buf = Vec::new();
    buf.extend_from_slice(PACKET_IDENT);
    buf.extend_from_slice(&0x4242u16.to_be_bytes()); // unknown base vector
    buf.extend_from_slice(&(base_body.len() as u16).to_be_bytes());
    buf.extend_from_slice(&base_body);

    let err = Packet::decode(&buf).unwrap_err();
    assert_eq!(err, OtpError::UnknownVector(0x4242));
}
