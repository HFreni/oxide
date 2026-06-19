//! OTP encoders: build a transform or advertisement datagram from the typed
//! structs. The inverse of [`crate::Packet::decode`]. Big-endian throughout.
//!
//! Module values are encoded in the standard units (position in µm, rotation in
//! millionths of a degree, etc.) so they round-trip exactly with the decoders.
//! The position/velocity-acceleration and rotation/velocity-acceleration
//! modules each carry a velocity **and** an acceleration; they are emitted when
//! either field is present, defaulting the absent one to zero.

use crate::advertisement::AdvertisementMessage;
use crate::modules;
use crate::transform::{Point, TransformMessage, VECTOR_POINT, VECTOR_TRANSFORM};
use crate::{
    Message, Packet, Vec3, PACKET_IDENT, VECTOR_ADVERTISEMENT_MESSAGE, VECTOR_TRANSFORM_MESSAGE,
};

/// Wrap `body` in a PDU header: vector(2) + length(2) + body, big-endian.
fn pdu(vector: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    v.extend_from_slice(&vector.to_be_bytes());
    v.extend_from_slice(&(body.len() as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn push_i32_scaled(out: &mut Vec<u8>, value: f64, scale: f64) {
    out.extend_from_slice(&((value * scale).round() as i32).to_be_bytes());
}

fn push_u32_scaled(out: &mut Vec<u8>, value: f64, scale: f64) {
    out.extend_from_slice(&((value * scale).round() as u32).to_be_bytes());
}

fn push_vec3_i32(out: &mut Vec<u8>, v: Vec3, scale: f64) {
    push_i32_scaled(out, v.x, scale);
    push_i32_scaled(out, v.y, scale);
    push_i32_scaled(out, v.z, scale);
}

fn module(number: u16, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + data.len());
    body.extend_from_slice(&number.to_be_bytes());
    body.extend_from_slice(data);
    pdu(modules::MANUFACTURER_ESTA, &body)
}

fn encode_modules(p: &Point) -> Vec<u8> {
    use modules::number::*;
    let mut out = Vec::new();

    if let Some(pos) = p.position {
        let mut d = Vec::new();
        d.push(0); // scaling options: bit7 clear -> µm
        push_vec3_i32(&mut d, pos, 1e6);
        out.extend(module(POSITION, &d));
    }
    if p.velocity.is_some() || p.acceleration.is_some() {
        let mut d = Vec::new();
        push_vec3_i32(&mut d, p.velocity.unwrap_or_default(), 1e6); // µm/s
        push_vec3_i32(&mut d, p.acceleration.unwrap_or_default(), 1e6); // µm/s²
        out.extend(module(POSITION_VEL_ACCEL, &d));
    }
    if let Some(rot) = p.rotation {
        let mut d = Vec::new();
        push_u32_scaled(&mut d, rot.x, 1e6); // millionths of a degree
        push_u32_scaled(&mut d, rot.y, 1e6);
        push_u32_scaled(&mut d, rot.z, 1e6);
        out.extend(module(ROTATION, &d));
    }
    if p.rotation_velocity.is_some() || p.rotation_acceleration.is_some() {
        let mut d = Vec::new();
        push_vec3_i32(&mut d, p.rotation_velocity.unwrap_or_default(), 1e3); // thousandths deg/s
        push_vec3_i32(&mut d, p.rotation_acceleration.unwrap_or_default(), 1e3);
        out.extend(module(ROTATION_VEL_ACCEL, &d));
    }
    if let Some(scale) = p.scale {
        let mut d = Vec::new();
        push_vec3_i32(&mut d, scale, 1e6); // millionths, 1e6 == unity
        out.extend(module(SCALE, &d));
    }
    if let Some(rf) = p.reference_frame {
        let mut d = Vec::new();
        d.push(rf.system);
        d.extend_from_slice(&rf.group.to_be_bytes());
        d.extend_from_slice(&rf.point.to_be_bytes());
        out.extend(module(REFERENCE_FRAME, &d));
    }
    out
}

fn encode_point(p: &Point) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(p.priority);
    body.extend_from_slice(&p.address.group.to_be_bytes());
    body.extend_from_slice(&p.address.point.to_be_bytes());
    body.extend_from_slice(&p.timestamp_us.to_be_bytes());
    body.push(0); // options
    body.extend_from_slice(&0u32.to_be_bytes()); // reserved
    body.extend(encode_modules(p));
    pdu(VECTOR_POINT, &body)
}

fn encode_transform_body(t: &TransformMessage) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(t.system);
    body.extend_from_slice(&t.timestamp_us.to_be_bytes());
    body.push(if t.full_point_set { 0x80 } else { 0 }); // options
    body.extend_from_slice(&0u32.to_be_bytes()); // reserved
    for p in &t.points {
        body.extend(encode_point(p));
    }
    body
}

fn name_field(name: &str) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let b = name.as_bytes();
    let n = b.len().min(32);
    buf[..n].copy_from_slice(&b[..n]);
    buf
}

fn encode_advertisement_body(adv: &AdvertisementMessage) -> Vec<u8> {
    let sub = match adv {
        AdvertisementMessage::Module(mods) => {
            let mut b = Vec::new();
            b.extend_from_slice(&0u32.to_be_bytes()); // reserved
            for m in mods {
                b.extend_from_slice(&m.manufacturer.to_be_bytes());
                b.extend_from_slice(&m.module.to_be_bytes());
            }
            pdu(0x0001, &b)
        }
        AdvertisementMessage::Name { is_response, names } => {
            let mut b = Vec::new();
            b.push(if *is_response { 0x80 } else { 0 }); // options
            b.extend_from_slice(&0u32.to_be_bytes()); // reserved
            for pn in names {
                b.push(pn.address.system);
                b.extend_from_slice(&pn.address.group.to_be_bytes());
                b.extend_from_slice(&pn.address.point.to_be_bytes());
                b.extend_from_slice(&name_field(&pn.name));
            }
            pdu(0x0002, &b)
        }
        AdvertisementMessage::System(systems) => {
            let mut b = Vec::new();
            b.push(0); // options
            b.extend_from_slice(&0u32.to_be_bytes()); // reserved
            b.extend_from_slice(systems);
            pdu(0x0003, &b)
        }
        AdvertisementMessage::Unknown(_) => Vec::new(),
    };
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes()); // reserved
    body.extend(sub);
    body
}

impl Packet {
    /// Encode this packet into a single OTP datagram.
    pub fn encode(&self) -> Vec<u8> {
        let (base_vector, sub) = match &self.message {
            Message::Transform(t) => (
                VECTOR_TRANSFORM_MESSAGE,
                pdu(VECTOR_TRANSFORM, &encode_transform_body(t)),
            ),
            Message::Advertisement(a) => (
                VECTOR_ADVERTISEMENT_MESSAGE,
                pdu(VECTOR_ADVERTISEMENT_MESSAGE, &encode_advertisement_body(a)),
            ),
        };

        // Base-layer fields (63 octets) followed by the message sub-layer.
        let mut base_body = Vec::new();
        base_body.push(0); // footer options
        base_body.push(0); // footer length
        base_body.extend_from_slice(&self.layer.cid);
        base_body.extend_from_slice(&self.layer.folio.to_be_bytes());
        base_body.extend_from_slice(&self.layer.page.to_be_bytes());
        base_body.extend_from_slice(&self.layer.last_page.to_be_bytes());
        base_body.push(0); // options
        base_body.extend_from_slice(&0u32.to_be_bytes()); // reserved
        base_body.extend_from_slice(&name_field(&self.layer.component_name));
        base_body.extend(sub);

        let mut out = Vec::with_capacity(PACKET_IDENT.len() + 4 + base_body.len());
        out.extend_from_slice(PACKET_IDENT);
        out.extend(pdu(base_vector, &base_body));
        out
    }
}
