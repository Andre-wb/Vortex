use crate::hex::decode::decode_fixed;
use crate::hex::encode::encode;

pub const CONTENT_DIGEST_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentDigest([u8; CONTENT_DIGEST_LEN]);

impl ContentDigest {
    pub fn of(content: &[u8]) -> Self {
        ContentDigest(*blake3::hash(content).as_bytes())
    }

    pub fn is_claimed_truthfully(&self, claim: &str) -> bool {
        decode_fixed::<CONTENT_DIGEST_LEN>(claim)
            .map(|bytes| bytes == self.0)
            .unwrap_or(false)
    }

    pub fn as_bytes(&self) -> &[u8; CONTENT_DIGEST_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        encode(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentDigest, CONTENT_DIGEST_LEN};

    #[test]
    fn the_digest_is_blake3_of_the_content() {
        let digest = ContentDigest::of(b"vortex");
        assert_eq!(digest.as_bytes(), blake3::hash(b"vortex").as_bytes());
        assert_eq!(digest.to_hex().len(), CONTENT_DIGEST_LEN * 2);
    }

    #[test]
    fn a_claim_that_matches_the_content_is_recognised() {
        let digest = ContentDigest::of(b"a message");
        assert!(digest.is_claimed_truthfully(&digest.to_hex()));
        assert!(digest.is_claimed_truthfully(&digest.to_hex().to_uppercase()));
    }

    #[test]
    fn a_claim_of_the_right_shape_but_the_wrong_value_is_not_believed() {
        let digest = ContentDigest::of(b"a message");
        assert!(!digest.is_claimed_truthfully(&"11".repeat(CONTENT_DIGEST_LEN)));
    }

    #[test]
    fn a_claim_that_is_not_a_digest_at_all_is_not_believed() {
        let digest = ContentDigest::of(b"a message");
        for claim in ["", "zz", "11", &"11".repeat(31), &"11 ".repeat(21)] {
            assert!(!digest.is_claimed_truthfully(claim));
        }
    }

    #[test]
    fn two_different_messages_do_not_share_a_digest() {
        assert_ne!(ContentDigest::of(b"one"), ContentDigest::of(b"two"));
    }
}
