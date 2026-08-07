use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::secret::value::BmpSecret;

const JITTER_LABEL: &[u8] = b"jitter";

pub fn pair_jitter(secret: &BmpSecret, jitter_secs: u16) -> u16 {
    if jitter_secs == 0 {
        return 0;
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.bytes()).expect("HMAC принимает любой ключ");
    mac.update(JITTER_LABEL);
    let signature = mac.finalize().into_bytes();
    ((u16::from(signature[0]) << 8) | u16::from(signature[1])) % jitter_secs
}

#[cfg(test)]
mod tests {
    use super::pair_jitter;
    use crate::config::rotation::DEFAULT_ROTATION_JITTER_SECS;
    use crate::secret::value::BmpSecret;

    fn secret(byte: &str) -> BmpSecret {
        BmpSecret::parse(&byte.repeat(32)).unwrap()
    }

    #[test]
    fn the_same_secret_always_rotates_at_the_same_offset() {
        let secret = secret("ab");
        assert_eq!(
            pair_jitter(&secret, DEFAULT_ROTATION_JITTER_SECS),
            pair_jitter(&secret, DEFAULT_ROTATION_JITTER_SECS)
        );
    }

    #[test]
    fn the_offset_stays_inside_the_configured_range() {
        for byte in ["00", "ab", "cd", "ef", "ff"] {
            assert!(pair_jitter(&secret(byte), DEFAULT_ROTATION_JITTER_SECS) < 600);
        }
    }

    #[test]
    fn different_pairs_rotate_at_different_offsets() {
        assert_ne!(
            pair_jitter(&secret("ab"), DEFAULT_ROTATION_JITTER_SECS),
            pair_jitter(&secret("cd"), DEFAULT_ROTATION_JITTER_SECS)
        );
    }

    #[test]
    fn a_disabled_jitter_range_shifts_nothing() {
        assert_eq!(pair_jitter(&secret("ab"), 0), 0);
    }
}
