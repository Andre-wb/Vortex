use crate::key::ed25519_public::Ed25519Public;
use crate::key::ed25519_signature::Ed25519Signature;

pub trait SignatureVerifier: Send + Sync {
    fn usable(&self, key: &Ed25519Public) -> bool;

    fn verify(&self, key: &Ed25519Public, message: &[u8], signature: &Ed25519Signature) -> bool;
}
