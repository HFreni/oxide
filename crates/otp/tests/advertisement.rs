//! encode → decode round-trips for the OTP advertisement message layers,
//! verifying the two-level PDU nesting required by ANSI E1.59-2021 §11-§14
//! (worked examples in Appendix B.2-B.4).

use otp::advertisement::{ModuleIdent, PointName};
use otp::modules::Address;
use otp::{AdvertisementMessage, Message, OtpLayer, Packet, PACKET_IDENT};

fn wrap(message: AdvertisementMessage) -> Packet {
    Packet {
        layer: OtpLayer {
            cid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            folio: 7,
            page: 1,
            last_page: 1,
            component_name: "trimtrack".into(),
        },
        message: Message::Advertisement(message),
    }
}

fn roundtrip(message: AdvertisementMessage) {
    let original = wrap(message);
    let bytes = original.encode();
    let decoded = Packet::decode(&bytes).expect("decode");
    assert_eq!(decoded, original);
}

#[test]
fn module_roundtrip() {
    roundtrip(AdvertisementMessage::Module(vec![
        ModuleIdent { manufacturer: 0x0000, module: 0x0001 },
        ModuleIdent { manufacturer: 0x0000, module: 0x0003 },
    ]));
}

#[test]
fn name_request_roundtrip() {
    roundtrip(AdvertisementMessage::Name {
        is_response: false,
        names: vec![],
    });
}

#[test]
fn name_response_roundtrip() {
    roundtrip(AdvertisementMessage::Name {
        is_response: true,
        names: vec![
            PointName {
                address: Address { system: 1, group: 1000, point: 1 },
                name: "Slider B".into(),
            },
            PointName {
                address: Address { system: 5, group: 1, point: 1001 },
                name: "Audience Lift A".into(),
            },
        ],
    });
}

#[test]
fn system_request_roundtrip() {
    roundtrip(AdvertisementMessage::System {
        is_response: false,
        systems: vec![],
    });
}

#[test]
fn system_response_roundtrip() {
    roundtrip(AdvertisementMessage::System {
        is_response: true,
        systems: vec![1, 5],
    });
}

/// Structural guard against regressing to a single-nesting layout: the OTP
/// Advertisement Layer vector (octets 79-80) must equal the advertisement
/// kind, and the inner *_LIST layer vector (octets 87-88) must be 0x0001.
#[test]
fn wire_structure_two_level_nesting() {
    // Module advertisement: kind = 0x0001, inner list vector = 0x0001.
    let bytes = wrap(AdvertisementMessage::Module(vec![ModuleIdent {
        manufacturer: 0,
        module: 1,
    }]))
    .encode();
    assert_eq!(&bytes[..PACKET_IDENT.len()], PACKET_IDENT.as_slice());
    // Base-layer vector (octets 12-13) is VECTOR_OTP_ADVERTISEMENT_MESSAGE.
    assert_eq!(u16::from_be_bytes([bytes[12], bytes[13]]), 0x0002);
    // OTP Advertisement Layer vector (octets 79-80) = kind = Module.
    assert_eq!(u16::from_be_bytes([bytes[79], bytes[80]]), 0x0001);
    // Inner *_LIST layer vector (octets 87-88) = VECTOR_LIST.
    assert_eq!(u16::from_be_bytes([bytes[87], bytes[88]]), 0x0001);

    // Name advertisement: kind = 0x0002 at octets 79-80.
    let bytes = wrap(AdvertisementMessage::Name {
        is_response: true,
        names: vec![],
    })
    .encode();
    assert_eq!(u16::from_be_bytes([bytes[79], bytes[80]]), 0x0002);
    assert_eq!(u16::from_be_bytes([bytes[87], bytes[88]]), 0x0001);

    // System advertisement: kind = 0x0003 at octets 79-80.
    let bytes = wrap(AdvertisementMessage::System {
        is_response: true,
        systems: vec![1, 5],
    })
    .encode();
    assert_eq!(u16::from_be_bytes([bytes[79], bytes[80]]), 0x0003);
    assert_eq!(u16::from_be_bytes([bytes[87], bytes[88]]), 0x0001);
}
