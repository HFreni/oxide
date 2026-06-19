<img src="../../assets/otp-oxide.svg" align="right" width="96" height="96" alt="otp-oxide logo">

# otp-oxide

An [OTP (Object Transform Protocol, ANSI E1.59)](https://www.esta.org/) decoder
for Rust.

OTP is the ESTA standard for streaming object transform data — position,
rotation, scale, velocity, and acceleration — over UDP multicast. It is layered
like ACN/sACN and is big-endian. `otp-oxide` decodes transform messages and
advertisement (discovery) messages, with unit conversion to SI.

- **Decode and encode** (receive and transmit), zero `unsafe`.
- Pure codec; optional `net` feature for multicast receiver/sender helpers
  (per-system transform groups `239.159.1.<system>` plus the advertisement group).

```rust
use otp::{Packet, Message};

let packet = otp::Packet::decode(datagram)?;
if let Message::Transform(t) = packet.message {
    for point in &t.points {
        if let Some(pos) = point.position {
            println!("{} at {:?} m", point.address, pos); // metres
        }
    }
}
```

> **Provenance:** the wire format was reconstructed from the public reference
> implementations (Marcus Birkin's [OTPLib](https://github.com/marcusbirkin/OTPLib)
> and its Wireshark dissector) and has since been **audited field-by-field
> against ANSI E1.59-2021 (R2025)**, including the Appendix B worked examples.
> The transform/module path is byte-exact per the standard; the advertisement
> layer's two-level PDU nesting was corrected in 0.2.0.

## License

MIT OR Apache-2.0.
