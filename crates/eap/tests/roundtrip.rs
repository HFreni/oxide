//! encode → decode round-trip for EAP Network Variables.

use eap::value;
use eap::{NetworkVariable, PublisherTelegram};

#[test]
fn telegram_roundtrip() {
    let pos = value::f64_le(12.5);
    let state = value::bool_byte(true);
    let count = value::i32_le(-7);

    let original = PublisherTelegram {
        publisher: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        cycle_index: 77,
        variables: vec![
            NetworkVariable { id: 1, hash: 0x1234, quality: 0, data: &pos },
            NetworkVariable { id: 2, hash: 0xABCD, quality: 1, data: &state },
            NetworkVariable { id: 3, hash: 0x0001, quality: 0, data: &count },
        ],
    };

    let bytes = original.encode();
    let decoded = PublisherTelegram::decode(&bytes).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.variables[0].as_f64_le(), Some(12.5));
    assert_eq!(decoded.variables[1].as_bool(), Some(true));
    assert_eq!(decoded.variables[2].as_i32_le(), Some(-7));
}
