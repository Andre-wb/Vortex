use crate::shadowtls::switch::session_id::{SessionId, SESSION_ID_LEN};
use crate::tls::server_hello::{ServerRandom, SERVER_RANDOM_LEN};

pub const SALT_LEN: usize = SERVER_RANDOM_LEN + SESSION_ID_LEN;

pub fn build(server_random: &ServerRandom, session_id: &SessionId) -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    salt[..SERVER_RANDOM_LEN].copy_from_slice(server_random);
    salt[SERVER_RANDOM_LEN..].copy_from_slice(session_id.as_bytes());
    salt
}

#[cfg(test)]
mod tests {
    use super::{build, SALT_LEN};
    use crate::shadowtls::switch::session_id::SessionId;

    #[test]
    fn carries_the_donor_random_before_the_client_session_id() {
        let session_id = SessionId::from_bytes([0x02; 16]);
        let salt = build(&[0x01; 32], &session_id);
        assert_eq!(salt.len(), SALT_LEN);
        assert_eq!(&salt[..32], &[0x01u8; 32]);
        assert_eq!(&salt[32..], &[0x02u8; 16]);
    }

    #[test]
    fn either_half_alone_changes_the_salt() {
        let one = SessionId::from_bytes([0x02; 16]);
        let other = SessionId::from_bytes([0x03; 16]);
        assert_ne!(build(&[0x01; 32], &one), build(&[0x01; 32], &other));
        assert_ne!(build(&[0x01; 32], &one), build(&[0x04; 32], &one));
    }
}
