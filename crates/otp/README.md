<img src="../../assets/otp-oxide.svg" align="right" width="96" height="96" alt="otp-oxide logo">

# otp-oxide

An [OTP (Object Transform Protocol, ANSI E1.59)](https://www.esta.org/) decoder
for Rust.

OTP is the ESTA standard for streaming object transform data — position,
rotation, scale, velocity, and acceleration — over UDP multicast. It is layered
like ACN/sACN and is big-endian. `otp-oxide` decodes transform messages and
advertisement (discovery) messages, with unit conversion to SI.

- **Receive-only**, zero `unsafe`.
- Pure decoder; optional `net` feature for a multicast helper that joins
  per-system transform groups (`239.159.1.<system>`) plus the advertisement group.

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

> **Provenance:** the ANSI E1.59 standard is paywalled. This crate's wire format
> was reconstructed from the public reference implementations — Marcus Birkin's
> [OTPLib](https://github.com/marcusbirkin/OTPLib) and its Wireshark dissector —
> and validated with round-trip tests. Field offsets and units are documented
> per module in the source. Cross-check against E1.59 for formal certainty.

## License

MIT OR Apache-2.0.
