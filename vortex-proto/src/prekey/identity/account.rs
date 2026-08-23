use crate::key::ed25519_public::Ed25519Public;
use crate::key::ed25519_signature::Ed25519Signature;
use crate::key::x25519_public::X25519Public;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountIdentity {
    pub identity_key: X25519Public,
    pub signed_prekey: X25519Public,
    pub signed_prekey_sig: Ed25519Signature,
    pub signed_prekey_id: i64,
    pub identity_key_ed: Option<Ed25519Public>,
    pub identity_key_sig: Option<Ed25519Signature>,
}

impl AccountIdentity {
    pub fn signs_with_ed25519(&self) -> bool {
        self.identity_key_ed.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::AccountIdentity;
    use crate::key::ed25519_public::Ed25519Public;
    use crate::key::ed25519_signature::Ed25519Signature;
    use crate::key::x25519_public::X25519Public;

    fn identity(with_ed: bool) -> AccountIdentity {
        AccountIdentity {
            identity_key: X25519Public::from_bytes([1u8; 32]),
            signed_prekey: X25519Public::from_bytes([2u8; 32]),
            signed_prekey_sig: Ed25519Signature::from_bytes([3u8; 64]),
            signed_prekey_id: 0,
            identity_key_ed: with_ed.then(|| Ed25519Public::from_bytes([4u8; 32])),
            identity_key_sig: None,
        }
    }

    #[test]
    fn an_account_without_an_ed25519_key_has_nothing_to_verify_against() {
        assert!(!identity(false).signs_with_ed25519());
        assert!(identity(true).signs_with_ed25519());
    }
}
