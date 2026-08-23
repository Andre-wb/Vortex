use serde::Deserialize;

use crate::key::kyber_public::KyberPublic;

#[derive(Debug, Clone, Deserialize)]
pub struct OneTimeKyberUpload {
    pub key_id: i64,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimeKyberPreKey {
    pub key_id: i64,
    pub public: KyberPublic,
}
