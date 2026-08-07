use crate::error::{BmpError, Result};

pub const SECRET_LEN: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct BmpSecret {
    bytes: [u8; SECRET_LEN],
}

impl BmpSecret {
    pub fn parse(secret_hex: &str) -> Result<Self> {
        let decoded = hex::decode(secret_hex).map_err(|_| BmpError::SecretNotHex)?;
        let bytes: [u8; SECRET_LEN] =
            decoded
                .as_slice()
                .try_into()
                .map_err(|_| BmpError::SecretLength {
                    expected: SECRET_LEN,
                    got: decoded.len(),
                })?;
        Ok(BmpSecret { bytes })
    }

    pub fn bytes(&self) -> &[u8; SECRET_LEN] {
        &self.bytes
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }
}

impl std::fmt::Debug for BmpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BmpSecret(<скрыт>)")
    }
}

#[cfg(test)]
mod tests {
    use super::{BmpSecret, SECRET_LEN};
    use crate::error::BmpError;

    #[test]
    fn a_thirty_two_byte_hex_secret_is_accepted() {
        let secret = BmpSecret::parse(&"ab".repeat(SECRET_LEN)).unwrap();
        assert_eq!(secret.bytes(), &[0xabu8; SECRET_LEN]);
    }

    #[test]
    fn the_hex_form_round_trips_in_lowercase() {
        let secret = BmpSecret::parse(&"AB".repeat(SECRET_LEN)).unwrap();
        assert_eq!(secret.to_hex(), "ab".repeat(SECRET_LEN));
    }

    #[test]
    fn a_non_hex_secret_is_refused_instead_of_silently_deriving_nothing() {
        assert_eq!(
            BmpSecret::parse(&"zz".repeat(SECRET_LEN)),
            Err(BmpError::SecretNotHex)
        );
        assert_eq!(
            BmpSecret::parse(&"a".repeat(SECRET_LEN * 2 - 1)),
            Err(BmpError::SecretNotHex)
        );
    }

    #[test]
    fn a_secret_of_the_wrong_length_is_refused() {
        assert_eq!(
            BmpSecret::parse("aabb"),
            Err(BmpError::SecretLength {
                expected: SECRET_LEN,
                got: 2
            })
        );
        assert_eq!(
            BmpSecret::parse(""),
            Err(BmpError::SecretLength {
                expected: SECRET_LEN,
                got: 0
            })
        );
    }

    #[test]
    fn the_secret_never_leaks_through_debug_output() {
        let secret = BmpSecret::parse(&"ab".repeat(SECRET_LEN)).unwrap();
        assert_eq!(format!("{secret:?}"), "BmpSecret(<скрыт>)");
    }
}
