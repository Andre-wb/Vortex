use sha2::{Digest, Sha256};

pub const NONCE_LEN: usize = 12;

pub fn for_ephemeral(ephemeral_public: &[u8]) -> [u8; NONCE_LEN] {
    let digest = Sha256::digest(ephemeral_public);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest[..NONCE_LEN]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::for_ephemeral;

    #[test]
    fn matches_the_python_reference_vector() {
        assert_eq!(
            hex::encode(for_ephemeral(&[0xAAu8; 32])),
            "e0e77a507412b120f6ede61f"
        );
    }

    #[test]
    fn different_keys_give_different_nonces() {
        assert_ne!(for_ephemeral(&[0x01u8; 32]), for_ephemeral(&[0x02u8; 32]));
    }
}
