use serde::Deserialize;

use crate::key::x25519_public::X25519Public;

#[derive(Debug, Clone, Deserialize)]
pub struct OneTimeUpload {
    pub key_id: i64,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimePreKey {
    pub key_id: i64,
    pub public: X25519Public,
}
