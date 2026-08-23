use crate::hex::decode::decode_fixed;
use crate::hex::encode::encode;
use crate::hex::error::HexError;

pub const ED25519_PUBLIC_LEN: usize = 32;

const FIELD_ORDER: [u8; ED25519_PUBLIC_LEN] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519Public([u8; ED25519_PUBLIC_LEN]);

impl Ed25519Public {
    pub fn parse_hex(text: &str) -> Result<Self, HexError> {
        Ok(Ed25519Public(decode_fixed::<ED25519_PUBLIC_LEN>(text)?))
    }

    pub fn from_bytes(bytes: [u8; ED25519_PUBLIC_LEN]) -> Self {
        Ed25519Public(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        encode(&self.0)
    }

    pub fn is_canonical(&self) -> bool {
        let mut coordinate = self.0;
        coordinate[ED25519_PUBLIC_LEN - 1] &= 0x7f;
        for index in (0..ED25519_PUBLIC_LEN).rev() {
            match coordinate[index].cmp(&FIELD_ORDER[index]) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => continue,
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519Public, ED25519_PUBLIC_LEN};
    use crate::hex::error::HexError;

    #[test]
    fn an_identity_key_survives_a_round_trip() {
        let text = "1c".repeat(ED25519_PUBLIC_LEN);
        assert_eq!(Ed25519Public::parse_hex(&text).unwrap().to_hex(), text);
    }

    #[test]
    fn a_coordinate_below_the_field_order_is_canonical() {
        assert!(Ed25519Public::from_bytes([0u8; 32]).is_canonical());
        let mut largest = [0xffu8; 32];
        largest[0] = 0xec;
        largest[31] = 0x7f;
        assert!(Ed25519Public::from_bytes(largest).is_canonical());
        let mut above = largest;
        above[0] = 0xee;
        assert!(!Ed25519Public::from_bytes(above).is_canonical());
    }

    #[test]
    fn the_field_order_itself_and_everything_above_it_is_not_canonical() {
        let mut order = [0xffu8; 32];
        order[0] = 0xed;
        order[31] = 0x7f;
        assert!(!Ed25519Public::from_bytes(order).is_canonical());
        assert!(!Ed25519Public::from_bytes([0xff; 32]).is_canonical());
    }

    #[test]
    fn the_sign_bit_does_not_make_a_coordinate_non_canonical() {
        let mut signed = [0u8; 32];
        signed[31] = 0x80;
        assert!(Ed25519Public::from_bytes(signed).is_canonical());
    }

    #[test]
    fn a_longer_key_is_refused_by_length() {
        assert_eq!(
            Ed25519Public::parse_hex(&"1c".repeat(33)),
            Err(HexError::Length {
                expected: ED25519_PUBLIC_LEN,
                got: 33
            })
        );
    }
}
