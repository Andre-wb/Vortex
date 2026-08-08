use hkdf::Hkdf;
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};

pub const PASSWORD_KEY_LEN: usize = 32;
pub const PASSWORD_INFO: &[u8] = b"vortex-shadowsocks-password-v2";

#[derive(Clone, Copy, Eq)]
pub struct PasswordKey([u8; PASSWORD_KEY_LEN]);

impl PasswordKey {
    pub fn derive(password: &[u8]) -> Option<Self> {
        if password.is_empty() {
            return None;
        }
        let hkdf = Hkdf::<Sha256>::new(None, password);
        let mut key = [0u8; PASSWORD_KEY_LEN];
        hkdf.expand(PASSWORD_INFO, &mut key)
            .expect("32 байта всегда помещаются в HKDF-SHA256");
        Some(PasswordKey(key))
    }

    pub fn as_bytes(&self) -> &[u8; PASSWORD_KEY_LEN] {
        &self.0
    }

    pub fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for PasswordKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl std::fmt::Debug for PasswordKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordKey(<скрыт>)")
    }
}

#[cfg(test)]
mod tests {
    use super::{PasswordKey, PASSWORD_KEY_LEN};

    #[test]
    fn an_empty_password_yields_no_key_at_all() {
        assert!(PasswordKey::derive(b"").is_none());
    }

    #[test]
    fn the_same_password_always_gives_the_same_key() {
        let one = PasswordKey::derive(b"test_password").unwrap();
        let other = PasswordKey::derive(b"test_password").unwrap();
        assert_eq!(one, other);
        assert_eq!(one.as_bytes().len(), PASSWORD_KEY_LEN);
    }

    #[test]
    fn a_different_password_gives_a_different_key() {
        let one = PasswordKey::derive(b"test_password").unwrap();
        let other = PasswordKey::derive(b"test_password ").unwrap();
        assert_ne!(one, other);
    }

    #[test]
    fn the_derivation_is_frozen() {
        let key = PasswordKey::derive(b"test_password").unwrap();
        assert_eq!(
            hex::encode(key.as_bytes()),
            "736b5385daffe2007b28a6e922f51955fb7d0bab88021c7a5db8af19736bc2b1"
        );
    }
}
