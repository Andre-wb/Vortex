pub const X25519_KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAuth {
    pub ephemeral_public: [u8; X25519_KEY_LEN],
    pub session_id: Vec<u8>,
}
