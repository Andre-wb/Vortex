use hkdf::Hkdf;
use sha2::Sha256;

pub const PASSWORD_KEY_LEN: usize = 32;
pub const PASSWORD_INFO: &[u8] = b"shadowtls-password-v2";

pub type PasswordKey = [u8; PASSWORD_KEY_LEN];

pub fn derive(password: &[u8]) -> Option<PasswordKey> {
    if password.is_empty() {
        return None;
    }
    let hkdf = Hkdf::<Sha256>::new(None, password);
    let mut key = [0u8; PASSWORD_KEY_LEN];
    hkdf.expand(PASSWORD_INFO, &mut key)
        .expect("32 байта всегда помещаются в вывод HKDF-SHA256");
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::{derive, PASSWORD_KEY_LEN};

    #[test]
    fn an_empty_password_yields_no_key_at_all() {
        assert_eq!(derive(b""), None);
    }

    #[test]
    fn different_passwords_give_different_keys() {
        assert_ne!(derive(b"one"), derive(b"two"));
        assert_eq!(derive(b"one").unwrap().len(), PASSWORD_KEY_LEN);
    }

    #[test]
    fn derivation_is_frozen() {
        assert_eq!(
            hex::encode(derive(b"testpass").unwrap()),
            "fac4856b18ae93e7e13e51b537ee409fe2629cdd81ac7c1f66be71768bdd055d"
        );
    }
}
