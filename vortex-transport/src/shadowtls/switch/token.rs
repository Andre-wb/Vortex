use crate::shadowtls::schedule::{expand, salt};
use crate::shadowtls::secret::password_key::PasswordKey;
use crate::shadowtls::switch::session_id::SessionId;
use crate::tls::server_hello::ServerRandom;
use subtle::ConstantTimeEq;

pub const SWITCH_TOKEN_LEN: usize = 8;
pub const SWITCH_INFO: &[u8] = b"shadowtls switch v2";

pub type SwitchToken = [u8; SWITCH_TOKEN_LEN];

pub fn derive(
    key: &PasswordKey,
    server_random: &ServerRandom,
    session_id: &SessionId,
) -> SwitchToken {
    expand::expand(key, &salt::build(server_random, session_id), SWITCH_INFO)
}

pub fn verify(
    key: &PasswordKey,
    server_random: &ServerRandom,
    session_id: &SessionId,
    candidate: &[u8],
) -> bool {
    let expected = derive(key, server_random, session_id);
    candidate.ct_eq(&expected).into()
}

#[cfg(test)]
mod tests {
    use super::{derive, verify, SWITCH_TOKEN_LEN};
    use crate::shadowtls::secret::password_key;
    use crate::shadowtls::switch::session_id::SessionId;

    fn key() -> [u8; 32] {
        password_key::derive(b"testpass").unwrap()
    }

    #[test]
    fn what_is_derived_verifies() {
        let session_id = SessionId::from_bytes([0x02; 16]);
        let token = derive(&key(), &[0x01; 32], &session_id);
        assert_eq!(token.len(), SWITCH_TOKEN_LEN);
        assert!(verify(&key(), &[0x01; 32], &session_id, &token));
    }

    #[test]
    fn the_donor_random_binds_the_token_to_one_connection() {
        let session_id = SessionId::from_bytes([0x02; 16]);
        let token = derive(&key(), &[0x01; 32], &session_id);
        assert!(!verify(&key(), &[0x09; 32], &session_id, &token));
    }

    #[test]
    fn another_session_id_does_not_verify() {
        let token = derive(&key(), &[0x01; 32], &SessionId::from_bytes([0x02; 16]));
        assert!(!verify(
            &key(),
            &[0x01; 32],
            &SessionId::from_bytes([0x03; 16]),
            &token
        ));
    }

    #[test]
    fn another_password_does_not_verify() {
        let session_id = SessionId::from_bytes([0x02; 16]);
        let token = derive(&key(), &[0x01; 32], &session_id);
        let stranger = password_key::derive(b"otherpass").unwrap();
        assert!(!verify(&stranger, &[0x01; 32], &session_id, &token));
    }

    #[test]
    fn a_candidate_of_the_wrong_length_never_verifies() {
        let session_id = SessionId::from_bytes([0x02; 16]);
        let token = derive(&key(), &[0x01; 32], &session_id);
        assert!(!verify(&key(), &[0x01; 32], &session_id, &token[..7]));
        assert!(!verify(&key(), &[0x01; 32], &session_id, &[]));
    }

    #[test]
    fn derivation_is_frozen() {
        assert_eq!(
            hex::encode(derive(
                &key(),
                &[0x01; 32],
                &SessionId::from_bytes([0x02; 16])
            )),
            "ddcbc0217e286990"
        );
    }
}
