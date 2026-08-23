pub const CIPHERTEXT_MIN_BYTES: usize = 12;

pub const KYBER_CIPHERTEXT_LEN: usize = 1088;

#[cfg(test)]
mod tests {
    use super::{CIPHERTEXT_MIN_BYTES, KYBER_CIPHERTEXT_LEN};

    #[test]
    fn the_shortest_ciphertext_is_a_bare_nonce() {
        assert_eq!(CIPHERTEXT_MIN_BYTES * 2, 24);
    }

    #[test]
    fn the_kyber_ciphertext_is_the_ml_kem_768_size() {
        assert_eq!(KYBER_CIPHERTEXT_LEN * 2, 2176);
    }
}
