use crate::key::ed25519_signature::Ed25519Signature;
use crate::key::kyber_public::KyberPublic;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceKyberPreKey {
    pub public: Option<KyberPublic>,
    pub signature: Option<Ed25519Signature>,
    pub id: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::DeviceKyberPreKey;

    #[test]
    fn a_publish_without_a_kyber_prekey_carries_nothing() {
        let kyber = DeviceKyberPreKey::default();
        assert!(kyber.public.is_none());
        assert!(kyber.signature.is_none());
        assert!(kyber.id.is_none());
    }
}
