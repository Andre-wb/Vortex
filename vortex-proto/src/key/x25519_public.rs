use crate::hex::decode::decode_fixed;
use crate::hex::encode::encode;
use crate::hex::error::HexError;

pub const X25519_PUBLIC_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519Public([u8; X25519_PUBLIC_LEN]);

impl X25519Public {
    pub fn parse_hex(text: &str) -> Result<Self, HexError> {
        Ok(X25519Public(decode_fixed::<X25519_PUBLIC_LEN>(text)?))
    }

    pub fn from_bytes(bytes: [u8; X25519_PUBLIC_LEN]) -> Self {
        X25519Public(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; X25519_PUBLIC_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        encode(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{X25519Public, X25519_PUBLIC_LEN};
    use crate::hex::error::HexError;

    #[test]
    fn a_public_key_survives_a_round_trip() {
        let text = "0b".repeat(X25519_PUBLIC_LEN);
        assert_eq!(X25519Public::parse_hex(&text).unwrap().to_hex(), text);
    }

    #[test]
    fn a_shorter_key_is_refused_by_length() {
        assert_eq!(
            X25519Public::parse_hex(&"0b".repeat(31)),
            Err(HexError::Length {
                expected: X25519_PUBLIC_LEN,
                got: 31
            })
        );
    }

    #[test]
    fn a_non_hex_key_is_refused_before_length() {
        assert_eq!(X25519Public::parse_hex("zz"), Err(HexError::NotHex));
    }
}
