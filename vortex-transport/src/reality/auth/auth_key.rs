use hkdf::Hkdf;
use sha2::Sha256;

pub const AUTH_INFO: &[u8] = b"vortex-reality";
pub const AUTH_KEY_LEN: usize = 16;

pub fn derive(shared_secret: &[u8]) -> [u8; AUTH_KEY_LEN] {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; AUTH_KEY_LEN];
    hkdf.expand(AUTH_INFO, &mut key)
        .expect("16 байт всегда помещаются в вывод HKDF-SHA256");
    key
}

#[cfg(test)]
mod tests {
    use super::derive;

    #[test]
    fn matches_the_python_reference_vector() {
        let shared = [0x42u8; 32];
        assert_eq!(
            hex::encode(derive(&shared)),
            "e8ee200db292c9da17300fafb65fa625"
        );
    }

    #[test]
    fn different_secrets_give_different_keys() {
        assert_ne!(derive(&[0x01; 32]), derive(&[0x02; 32]));
    }
}
