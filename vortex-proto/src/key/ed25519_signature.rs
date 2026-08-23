use crate::hex::decode::decode_fixed;
use crate::hex::encode::encode;
use crate::hex::error::HexError;

pub const ED25519_SIGNATURE_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519Signature([u8; ED25519_SIGNATURE_LEN]);

impl Ed25519Signature {
    pub fn parse_hex(text: &str) -> Result<Self, HexError> {
        Ok(Ed25519Signature(decode_fixed::<ED25519_SIGNATURE_LEN>(
            text,
        )?))
    }

    pub fn from_bytes(bytes: [u8; ED25519_SIGNATURE_LEN]) -> Self {
        Ed25519Signature(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ED25519_SIGNATURE_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        encode(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519Signature, ED25519_SIGNATURE_LEN};
    use crate::hex::error::HexError;

    #[test]
    fn a_signature_survives_a_round_trip() {
        let text = "7f".repeat(ED25519_SIGNATURE_LEN);
        assert_eq!(Ed25519Signature::parse_hex(&text).unwrap().to_hex(), text);
    }

    #[test]
    fn a_key_sized_value_is_not_a_signature() {
        assert_eq!(
            Ed25519Signature::parse_hex(&"7f".repeat(32)),
            Err(HexError::Length {
                expected: ED25519_SIGNATURE_LEN,
                got: 32
            })
        );
    }
}
