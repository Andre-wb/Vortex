use subtle::ConstantTimeEq;

use crate::challenge::refusal::SecretRefusal;
use crate::ports::entropy::Entropy;

pub const MIN_BYTES: usize = 16;
pub const MAX_BYTES: usize = 128;
pub const DRAWN_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeSecret(Vec<u8>);

impl ChallengeSecret {
    pub fn of(raw: Vec<u8>) -> Result<Self, SecretRefusal> {
        if raw.len() < MIN_BYTES {
            return Err(SecretRefusal::TooShort {
                min: MIN_BYTES,
                got: raw.len(),
            });
        }
        if raw.len() > MAX_BYTES {
            return Err(SecretRefusal::TooLong {
                max: MAX_BYTES,
                got: raw.len(),
            });
        }
        Ok(ChallengeSecret(raw))
    }

    pub fn draw(entropy: &dyn Entropy) -> Self {
        let mut raw = vec![0u8; DRAWN_BYTES];
        entropy.fill(&mut raw);
        ChallengeSecret(raw)
    }

    pub fn parse_hex(value: &str) -> Result<Self, SecretRefusal> {
        let raw = hex::decode(value).map_err(|_| SecretRefusal::NotHex)?;
        ChallengeSecret::of(raw)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl ConstantTimeEq for ChallengeSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{ChallengeSecret, DRAWN_BYTES, MAX_BYTES, MIN_BYTES};
    use crate::challenge::refusal::SecretRefusal;
    use crate::random::fixed_entropy::FixedEntropy;

    #[test]
    fn a_drawn_secret_is_thirty_two_bytes() {
        let secret = ChallengeSecret::draw(&FixedEntropy::counting_from(0));
        assert_eq!(secret.as_bytes().len(), DRAWN_BYTES);
        assert_eq!(secret.to_hex().len(), DRAWN_BYTES * 2);
    }

    #[test]
    fn a_secret_survives_the_trip_through_hex() {
        let secret = ChallengeSecret::draw(&FixedEntropy::counting_from(3));
        let back = ChallengeSecret::parse_hex(&secret.to_hex()).unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn a_secret_too_small_to_be_unguessable_is_refused() {
        assert_eq!(
            ChallengeSecret::of(vec![0u8; MIN_BYTES - 1]).unwrap_err(),
            SecretRefusal::TooShort {
                min: MIN_BYTES,
                got: MIN_BYTES - 1
            }
        );
    }

    #[test]
    fn a_secret_larger_than_any_authenticator_asks_for_is_refused() {
        assert_eq!(
            ChallengeSecret::of(vec![0u8; MAX_BYTES + 1]).unwrap_err(),
            SecretRefusal::TooLong {
                max: MAX_BYTES,
                got: MAX_BYTES + 1
            }
        );
    }

    #[test]
    fn what_is_not_hex_is_not_a_secret() {
        assert_eq!(
            ChallengeSecret::parse_hex("не hex").unwrap_err(),
            SecretRefusal::NotHex
        );
    }
}
