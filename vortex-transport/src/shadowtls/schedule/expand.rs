use crate::shadowtls::secret::password_key::PasswordKey;
use hkdf::Hkdf;
use sha2::Sha256;

pub fn expand<const N: usize>(key: &PasswordKey, salt: &[u8], info: &[u8]) -> [u8; N] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), key);
    let mut out = [0u8; N];
    hkdf.expand(info, &mut out)
        .expect("вывод короче 8160 байт всегда помещается в HKDF-SHA256");
    out
}

#[cfg(test)]
mod tests {
    use super::expand;

    #[test]
    fn the_label_alone_changes_the_output() {
        let key = [0x07u8; 32];
        let one: [u8; 32] = expand(&key, b"salt", b"one");
        let other: [u8; 32] = expand(&key, b"salt", b"two");
        assert_ne!(one, other);
    }

    #[test]
    fn the_salt_alone_changes_the_output() {
        let key = [0x07u8; 32];
        let one: [u8; 32] = expand(&key, b"salt-a", b"label");
        let other: [u8; 32] = expand(&key, b"salt-b", b"label");
        assert_ne!(one, other);
    }

    #[test]
    fn a_short_output_is_the_prefix_of_a_long_one() {
        let key = [0x07u8; 32];
        let short: [u8; 8] = expand(&key, b"salt", b"label");
        let long: [u8; 32] = expand(&key, b"salt", b"label");
        assert_eq!(short, long[..8]);
    }
}
