use crate::stealth::KEY_LEN;
use sha2::{Digest, Sha256};

pub fn derive_key(network_key: &[u8]) -> [u8; KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(network_key);
    hasher.finalize().into()
}
