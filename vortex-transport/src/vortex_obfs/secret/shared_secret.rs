use hkdf::Hkdf;
use sha2::Sha256;

pub const SECRET_LEN: usize = 32;
pub const SECRET_INFO: &[u8] = b"vortex-obfs-secret-v2";

#[derive(Clone)]
pub struct SharedSecret([u8; SECRET_LEN]);

impl SharedSecret {
    pub fn derive(secret: &[u8]) -> Option<Self> {
        if secret.is_empty() {
            return None;
        }
        let hkdf = Hkdf::<Sha256>::new(None, secret);
        let mut key = [0u8; SECRET_LEN];
        hkdf.expand(SECRET_INFO, &mut key)
            .expect("32 байта всегда помещаются в HKDF-SHA256");
        Some(SharedSecret(key))
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{SharedSecret, SECRET_LEN};

    #[test]
    fn an_absent_secret_is_not_a_secret() {
        assert!(SharedSecret::derive(b"").is_none());
    }

    #[test]
    fn the_same_secret_always_gives_the_same_key() {
        let one = SharedSecret::derive(b"shared").unwrap();
        let other = SharedSecret::derive(b"shared").unwrap();
        assert_eq!(one.as_bytes(), other.as_bytes());
        assert_eq!(one.as_bytes().len(), SECRET_LEN);
    }

    #[test]
    fn a_different_secret_gives_a_different_key() {
        let one = SharedSecret::derive(b"shared").unwrap();
        let other = SharedSecret::derive(b"shared ").unwrap();
        assert_ne!(one.as_bytes(), other.as_bytes());
    }

    #[test]
    fn the_derivation_is_frozen() {
        let key = SharedSecret::derive(b"testsecret").unwrap();
        assert_eq!(
            hex::encode(key.as_bytes()),
            "ec5a58010b95a48a780d9f0500ab83985d9938a48b10dd02a60f9ccdbcf4721a"
        );
    }
}
