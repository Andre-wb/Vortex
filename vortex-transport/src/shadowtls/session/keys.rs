use crate::shadowtls::schedule::{expand, salt};
use crate::shadowtls::secret::password_key::PasswordKey;
use crate::shadowtls::session::role::{Direction, Role};
use crate::shadowtls::switch::session_id::SessionId;
use crate::tls::server_hello::ServerRandom;

pub const SESSION_KEY_LEN: usize = 32;

pub type SessionKey = [u8; SESSION_KEY_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeys {
    pub send: SessionKey,
    pub recv: SessionKey,
}

pub fn directional(
    key: &PasswordKey,
    server_random: &ServerRandom,
    session_id: &SessionId,
    direction: Direction,
) -> SessionKey {
    expand::expand(
        key,
        &salt::build(server_random, session_id),
        direction.info(),
    )
}

pub fn derive(
    key: &PasswordKey,
    server_random: &ServerRandom,
    session_id: &SessionId,
    role: Role,
) -> SessionKeys {
    SessionKeys {
        send: directional(key, server_random, session_id, role.sending()),
        recv: directional(key, server_random, session_id, role.receiving()),
    }
}

#[cfg(test)]
mod tests {
    use super::{derive, directional};
    use crate::shadowtls::secret::password_key;
    use crate::shadowtls::session::role::{Direction, Role};
    use crate::shadowtls::switch::session_id::SessionId;

    fn key() -> [u8; 32] {
        password_key::derive(b"testpass").unwrap()
    }

    fn session_id() -> SessionId {
        SessionId::from_bytes([0x02; 16])
    }

    #[test]
    fn the_two_sides_agree_on_both_directions() {
        let server = derive(&key(), &[0x01; 32], &session_id(), Role::Server);
        let client = derive(&key(), &[0x01; 32], &session_id(), Role::Client);
        assert_eq!(server.send, client.recv);
        assert_eq!(server.recv, client.send);
        assert_ne!(server.send, server.recv);
    }

    #[test]
    fn a_repeated_session_id_on_a_new_connection_yields_new_keys() {
        let first = derive(&key(), &[0x01; 32], &session_id(), Role::Server);
        let second = derive(&key(), &[0x02; 32], &session_id(), Role::Server);
        assert_ne!(first.send, second.send);
        assert_ne!(first.recv, second.recv);
    }

    #[test]
    fn derivation_is_frozen() {
        assert_eq!(
            hex::encode(directional(
                &key(),
                &[0x01; 32],
                &session_id(),
                Direction::ClientToServer
            )),
            "096b46bcdb18708d8cfbd1caea095b97dc350a128856ef8d8d5a5074d24ccd30"
        );
        assert_eq!(
            hex::encode(directional(
                &key(),
                &[0x01; 32],
                &session_id(),
                Direction::ServerToClient
            )),
            "67441230a3a41f2bc5cf7c92e764626ba3aff9b5ed1ed6559f3a4433ea91985b"
        );
    }
}
