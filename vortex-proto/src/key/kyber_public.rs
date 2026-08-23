use crate::hex::decode::decode_fixed;
use crate::hex::encode::encode;
use crate::hex::error::HexError;

pub const KYBER_PUBLIC_LEN: usize = 1184;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KyberPublic(Box<[u8; KYBER_PUBLIC_LEN]>);

impl KyberPublic {
    pub fn parse_hex(text: &str) -> Result<Self, HexError> {
        Ok(KyberPublic(Box::new(decode_fixed::<KYBER_PUBLIC_LEN>(
            text,
        )?)))
    }

    pub fn from_bytes(bytes: [u8; KYBER_PUBLIC_LEN]) -> Self {
        KyberPublic(Box::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; KYBER_PUBLIC_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        encode(self.0.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::{KyberPublic, KYBER_PUBLIC_LEN};
    use crate::hex::error::HexError;

    #[test]
    fn a_kyber_key_survives_a_round_trip() {
        let text = "2a".repeat(KYBER_PUBLIC_LEN);
        assert_eq!(KyberPublic::parse_hex(&text).unwrap().to_hex(), text);
    }

    #[test]
    fn an_x25519_sized_value_is_not_a_kyber_key() {
        assert_eq!(
            KyberPublic::parse_hex(&"2a".repeat(32)),
            Err(HexError::Length {
                expected: KYBER_PUBLIC_LEN,
                got: 32
            })
        );
    }
}
