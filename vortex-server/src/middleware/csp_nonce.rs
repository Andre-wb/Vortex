use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;

pub const BYTES: usize = 16;

pub fn new_nonce() -> String {
    let mut raw = [0u8; BYTES];
    rand::thread_rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

#[cfg(test)]
mod tests {
    use super::new_nonce;

    #[test]
    fn a_nonce_is_url_safe_base64_of_sixteen_bytes_without_padding() {
        let nonce = new_nonce();
        assert_eq!(nonce.len(), 22);
        assert!(!nonce.contains('='));
        assert!(nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
    }

    #[test]
    fn two_nonces_differ() {
        assert_ne!(new_nonce(), new_nonce());
    }
}
