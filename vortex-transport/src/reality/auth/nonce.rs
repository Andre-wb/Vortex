use crate::reality::auth::salt::Salt;
use sha2::{Digest, Sha256};

pub const NONCE_LEN: usize = 12;

pub fn derive(salt: &Salt, ephemeral_public: &[u8]) -> [u8; NONCE_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(ephemeral_public);
    let digest = hasher.finalize();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest[..NONCE_LEN]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::derive;

    #[test]
    fn matches_the_python_reference_vector() {
        assert_eq!(
            hex::encode(derive(&[0x01; 7], &[0xAAu8; 32])),
            "7f1e2073cffeb163357bcd02"
        );
    }

    #[test]
    fn the_salt_alone_changes_the_nonce() {
        let ephemeral = [0xAAu8; 32];
        assert_ne!(
            derive(&[0x01; 7], &ephemeral),
            derive(&[0x02; 7], &ephemeral)
        );
    }

    #[test]
    fn the_ephemeral_key_alone_changes_the_nonce() {
        let salt = [0x01u8; 7];
        assert_ne!(derive(&salt, &[0x01u8; 32]), derive(&salt, &[0x02u8; 32]));
    }
}
