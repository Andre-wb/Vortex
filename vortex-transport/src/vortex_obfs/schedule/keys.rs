use crate::vortex_obfs::schedule::role::Role;
use crate::vortex_obfs::schedule::salt::SessionSalt;
use crate::vortex_obfs::secret::shared_secret::SharedSecret;
use hkdf::Hkdf;
use sha2::Sha256;

pub const DIRECTION_KEY_LEN: usize = 32;

pub type DirectionKey = [u8; DIRECTION_KEY_LEN];

#[derive(Clone)]
pub struct SessionKeys {
    pub send: DirectionKey,
    pub recv: DirectionKey,
    pub send_length: DirectionKey,
    pub recv_length: DirectionKey,
}

pub fn derive(secret: &SharedSecret, salt: &SessionSalt, role: Role) -> SessionKeys {
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), secret.as_bytes());
    SessionKeys {
        send: expand(&hkdf, role.send_data_label()),
        recv: expand(&hkdf, role.recv_data_label()),
        send_length: expand(&hkdf, role.send_length_label()),
        recv_length: expand(&hkdf, role.recv_length_label()),
    }
}

fn expand(hkdf: &Hkdf<Sha256>, label: &[u8]) -> DirectionKey {
    let mut key = [0u8; DIRECTION_KEY_LEN];
    hkdf.expand(label, &mut key)
        .expect("32 байта всегда помещаются в HKDF-SHA256");
    key
}

#[cfg(test)]
mod tests {
    use super::derive;
    use crate::vortex_obfs::schedule::role::Role;
    use crate::vortex_obfs::schedule::salt::SessionSalt;
    use crate::vortex_obfs::secret::shared_secret::SharedSecret;

    fn secret() -> SharedSecret {
        SharedSecret::derive(b"testsecret").unwrap()
    }

    #[test]
    fn the_two_sides_agree_on_both_directions() {
        let salt = SessionSalt::from_bytes([0x11; 16]);
        let initiator = derive(&secret(), &salt, Role::Initiator);
        let responder = derive(&secret(), &salt, Role::Responder);
        assert_eq!(initiator.send, responder.recv);
        assert_eq!(responder.send, initiator.recv);
        assert_eq!(initiator.send_length, responder.recv_length);
    }

    #[test]
    fn no_two_keys_of_one_session_are_the_same() {
        let salt = SessionSalt::from_bytes([0x11; 16]);
        let keys = derive(&secret(), &salt, Role::Initiator);
        let mut all = vec![keys.send, keys.recv, keys.send_length, keys.recv_length];
        all.sort_unstable();
        let count = all.len();
        all.dedup();
        assert_eq!(all.len(), count);
    }

    #[test]
    fn a_new_salt_gives_a_new_key_schedule() {
        let one = derive(
            &secret(),
            &SessionSalt::from_bytes([0x11; 16]),
            Role::Initiator,
        );
        let other = derive(
            &secret(),
            &SessionSalt::from_bytes([0x12; 16]),
            Role::Initiator,
        );
        assert_ne!(one.send, other.send);
        assert_ne!(one.send_length, other.send_length);
    }

    #[test]
    fn a_different_secret_gives_a_different_key_schedule() {
        let salt = SessionSalt::from_bytes([0x11; 16]);
        let one = derive(&secret(), &salt, Role::Initiator);
        let other = derive(
            &SharedSecret::derive(b"othersecret").unwrap(),
            &salt,
            Role::Initiator,
        );
        assert_ne!(one.send, other.send);
    }

    #[test]
    fn the_schedule_is_frozen() {
        let keys = derive(
            &secret(),
            &SessionSalt::from_bytes([0x11; 16]),
            Role::Initiator,
        );
        assert_eq!(
            hex::encode(keys.send),
            "066182d8068c555d74b9fceb79122d71d9ba2cddde66f28e7895c2f318144202"
        );
    }
}
