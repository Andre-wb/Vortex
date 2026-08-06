use crate::error::{Result, TransportError};
use std::hash::{Hash, Hasher};
use subtle::ConstantTimeEq;

pub const SHORT_ID_HEX_LEN: usize = 8;
pub const SHORT_ID_LEN: usize = SHORT_ID_HEX_LEN / 2;

#[derive(Debug, Clone, Eq)]
pub struct ShortId {
    bytes: Vec<u8>,
}

impl ShortId {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        ShortId {
            bytes: bytes.into(),
        }
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        hex::decode(value)
            .map(ShortId::from_bytes)
            .map_err(|_| TransportError::ShortIdNotHex(value.to_owned()))
    }

    pub fn canonical(value: &str) -> Result<Self> {
        let parsed = ShortId::from_hex(value)?;
        if parsed.len() != SHORT_ID_LEN {
            return Err(TransportError::ShortIdLength {
                expected: SHORT_ID_LEN,
                got: parsed.len(),
            });
        }
        Ok(parsed)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl PartialEq for ShortId {
    fn eq(&self, other: &Self) -> bool {
        if self.bytes.len() != other.bytes.len() {
            return false;
        }
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Hash for ShortId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::{ShortId, SHORT_ID_LEN};
    use crate::error::TransportError;

    #[test]
    fn hex_round_trip_preserves_bytes() {
        let id = ShortId::from_hex("deadbeef").unwrap();
        assert_eq!(id.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(id.to_hex(), "deadbeef");
    }

    #[test]
    fn canonical_rejects_wrong_length() {
        assert_eq!(
            ShortId::canonical("dead"),
            Err(TransportError::ShortIdLength {
                expected: SHORT_ID_LEN,
                got: 2
            })
        );
    }

    #[test]
    fn canonical_rejects_non_hex() {
        assert!(matches!(
            ShortId::canonical("zzzzzzzz"),
            Err(TransportError::ShortIdNotHex(_))
        ));
    }

    #[test]
    fn equality_ignores_case_of_source_hex() {
        assert_eq!(
            ShortId::from_hex("DEADBEEF").unwrap(),
            ShortId::from_hex("deadbeef").unwrap()
        );
    }
}
