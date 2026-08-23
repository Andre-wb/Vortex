use crate::key::ed25519_public::Ed25519Public;
use crate::key::ed25519_signature::Ed25519Signature;
use crate::key::x25519_public::X25519Public;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub x3dh_pub: Option<X25519Public>,
    pub sign_pub: Option<Ed25519Public>,
    pub cert_sig: Option<Ed25519Signature>,
}

#[cfg(test)]
mod tests {
    use super::DeviceIdentity;

    #[test]
    fn a_publish_without_device_identity_carries_nothing() {
        let device = DeviceIdentity::default();
        assert!(device.x3dh_pub.is_none());
        assert!(device.sign_pub.is_none());
        assert!(device.cert_sig.is_none());
    }
}
