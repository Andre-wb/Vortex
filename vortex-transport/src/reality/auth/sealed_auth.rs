use crate::reality::auth::envelope::ENVELOPE_LEN;
use crate::reality::auth::salt::SALT_LEN;

pub const X25519_KEY_LEN: usize = 32;
pub const GCM_TAG_LEN: usize = 16;

pub const SESSION_ID_LEN: usize = SALT_LEN + ENVELOPE_LEN + GCM_TAG_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAuth {
    pub ephemeral_public: [u8; X25519_KEY_LEN],
    pub session_id: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::SESSION_ID_LEN;

    #[test]
    fn a_session_id_fills_the_tls_field_exactly() {
        assert_eq!(SESSION_ID_LEN, 32);
    }
}
