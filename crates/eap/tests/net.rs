//! End-to-end networking tests for the EAP `net` helpers, plus decoder
//! robustness tests against hostile/truncated input.
//!
//! The round-trip test encodes a `PublisherTelegram`, sends it over a real UDP
//! socket built by [`eap::net::sender`] to a unicast loopback target, and
//! receives it on a socket built by [`eap::net::bind`]. Unicast loopback is the
//! most reliable local path, so this test runs unconditionally (no `#[ignore]`).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use eap::net::{bind, sender, BindConfig};
use eap::value::f64_le;
use eap::{EapError, FrameType, NetworkVariable, PublisherTelegram};

#[test]
fn publisher_telegram_round_trip_over_unicast_loopback() {
    const PORT: u16 = 51030;

    let rx = bind(&BindConfig {
        port: PORT,
        multicast_group: None,
        interface: Ipv4Addr::LOCALHOST,
        broadcast: false,
    })
    .expect("bind");
    rx.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set_read_timeout");

    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, PORT));
    let tx = sender(target).expect("sender");

    let value = 42.5_f64;
    let data = f64_le(value);
    let sent = PublisherTelegram {
        publisher: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        cycle_index: 9,
        variables: vec![NetworkVariable {
            id: 1000,
            hash: 0xBEEF,
            quality: 0,
            data: &data,
        }],
    };
    let bytes = sent.encode();
    tx.send(&bytes).expect("send");

    let mut buf = [0u8; 1500];
    let (n, _from) = rx.recv_from(&mut buf).expect("recv_from (unicast loopback)");

    let decoded = PublisherTelegram::decode(&buf[..n]).expect("decode");
    assert_eq!(decoded.publisher, [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    assert_eq!(decoded.cycle_index, 9);
    assert_eq!(decoded.variables.len(), 1);
    let var = &decoded.variables[0];
    assert_eq!(var.id, 1000);
    assert_eq!(var.hash, 0xBEEF);
    assert_eq!(var.as_f64_le(), Some(value));
}

// ---------------------------------------------------------------------------
// Decoder robustness: hostile / malformed input must yield Err, never panic.
// ---------------------------------------------------------------------------

#[test]
fn decode_truncated_buffer_is_err() {
    // Fewer than the 2-byte frame header.
    let err = PublisherTelegram::decode(&[0x00]).unwrap_err();
    assert!(matches!(err, EapError::UnexpectedEof { .. }), "got {err:?}");

    assert!(PublisherTelegram::decode(&[]).is_err());
}

#[test]
fn decode_short_nv_header_is_err() {
    // Valid NV-type frame header (type 4 in bits 12..=15) but the NV header is
    // truncated (needs 12 bytes; provide only a few).
    let word: u16 = 4 << 12;
    let mut buf = word.to_le_bytes().to_vec();
    buf.extend_from_slice(&[0u8; 3]); // far short of the 12-byte NV header
    let err = PublisherTelegram::decode(&buf).unwrap_err();
    assert!(matches!(err, EapError::UnexpectedEof { .. }), "got {err:?}");
}

#[test]
fn decode_wrong_frame_type_is_err() {
    // Frame type 1 (EtherCAT command), not Network Variables.
    let word: u16 = 1 << 12;
    let mut buf = word.to_le_bytes().to_vec();
    buf.extend_from_slice(&[0u8; 12]);
    let err = PublisherTelegram::decode(&buf).unwrap_err();
    assert_eq!(err, EapError::NotNetworkVariables(FrameType::EtherCatCommand));
}

#[test]
fn decode_variable_overrun_is_err() {
    // Well-formed NV header declaring one variable whose length overruns.
    let word: u16 = 4 << 12;
    let mut buf = word.to_le_bytes().to_vec();
    buf.extend_from_slice(&[0u8; 6]); // publisher
    buf.extend_from_slice(&1u16.to_le_bytes()); // count = 1
    buf.extend_from_slice(&0u16.to_le_bytes()); // cycle_index
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    // variable header: id, hash, length(huge), quality; no data follows
    buf.extend_from_slice(&7u16.to_le_bytes()); // id
    buf.extend_from_slice(&0u16.to_le_bytes()); // hash
    buf.extend_from_slice(&0x00FFu16.to_le_bytes()); // length 255, but no data
    buf.extend_from_slice(&0u16.to_le_bytes()); // quality
    let err = PublisherTelegram::decode(&buf).unwrap_err();
    assert!(matches!(err, EapError::VariableOverrun { id: 7, .. }), "got {err:?}");
}
