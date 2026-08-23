use ed25519_dalek::{Signature, VerifyingKey};

use crate::key::ed25519_public::Ed25519Public;
use crate::key::ed25519_signature::Ed25519Signature;
use crate::verify::verifier::SignatureVerifier;

#[derive(Debug, Clone, Copy, Default)]
pub struct DalekVerifier;

impl SignatureVerifier for DalekVerifier {
    fn usable(&self, key: &Ed25519Public) -> bool {
        if !key.is_canonical() {
            return false;
        }
        match VerifyingKey::from_bytes(key.as_bytes()) {
            Ok(verifying) => !verifying.is_weak(),
            Err(_) => false,
        }
    }

    fn verify(&self, key: &Ed25519Public, message: &[u8], signature: &Ed25519Signature) -> bool {
        let verifying = match VerifyingKey::from_bytes(key.as_bytes()) {
            Ok(value) => value,
            Err(_) => return false,
        };
        verifying
            .verify_strict(message, &Signature::from_bytes(signature.as_bytes()))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::DalekVerifier;
    use crate::key::ed25519_public::Ed25519Public;
    use crate::key::ed25519_signature::Ed25519Signature;
    use crate::verify::verifier::SignatureVerifier;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn a_signature_of_the_message_is_accepted() {
        let signer = signing_key();
        let message = b"signed pre-key";
        let signature = Ed25519Signature::from_bytes(signer.sign(message).to_bytes());
        let key = Ed25519Public::from_bytes(signer.verifying_key().to_bytes());
        assert!(DalekVerifier.verify(&key, message, &signature));
    }

    #[test]
    fn a_signature_of_another_message_is_refused() {
        let signer = signing_key();
        let signature = Ed25519Signature::from_bytes(signer.sign(b"one").to_bytes());
        let key = Ed25519Public::from_bytes(signer.verifying_key().to_bytes());
        assert!(!DalekVerifier.verify(&key, b"another", &signature));
    }

    #[test]
    fn a_key_that_is_not_a_curve_point_refuses_everything() {
        let signer = signing_key();
        let signature = Ed25519Signature::from_bytes(signer.sign(b"one").to_bytes());
        let key = Ed25519Public::from_bytes([0xff; 32]);
        assert!(!DalekVerifier.verify(&key, b"one", &signature));
    }

    #[test]
    fn a_real_key_is_usable_and_a_degenerate_one_is_not() {
        let signer = signing_key();
        assert!(DalekVerifier.usable(&Ed25519Public::from_bytes(
            signer.verifying_key().to_bytes()
        )));
        assert!(!DalekVerifier.usable(&Ed25519Public::from_bytes([0u8; 32])));
        assert!(!DalekVerifier.usable(&Ed25519Public::from_bytes([0xff; 32])));
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(!DalekVerifier.usable(&Ed25519Public::from_bytes(identity)));
    }

    #[test]
    fn a_key_of_small_order_cannot_sign_anything_at_all() {
        let key = Ed25519Public::from_bytes([0u8; 32]);
        let signature = Ed25519Signature::from_bytes([0u8; 64]);
        let mut message = [0u8; 32];
        for last in 0u8..64 {
            message[31] = last;
            assert!(!DalekVerifier.verify(&key, &message, &signature));
        }
    }
}
