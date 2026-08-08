use crate::shadowsocks::schedule::role::Role;
use crate::shadowsocks::schedule::salt::SessionSalt;
use crate::shadowsocks::secret::password_key::PasswordKey;
use hkdf::Hkdf;
use sha2::Sha256;

pub const DIRECTION_KEY_LEN: usize = 32;

pub type DirectionKey = [u8; DIRECTION_KEY_LEN];

#[derive(Clone)]
pub struct SessionKeys {
    pub send: DirectionKey,
    pub recv: DirectionKey,
}

pub fn derive(key: &PasswordKey, salt: &SessionSalt, role: Role) -> SessionKeys {
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), key.as_bytes());
    SessionKeys {
        send: expand(&hkdf, role.send_label()),
        recv: expand(&hkdf, role.recv_label()),
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
    use crate::shadowsocks::schedule::role::Role;
    use crate::shadowsocks::schedule::salt::SessionSalt;
    use crate::shadowsocks::secret::password_key::PasswordKey;

    fn password() -> PasswordKey {
        PasswordKey::derive(b"test_password").unwrap()
    }

    fn salt() -> SessionSalt {
        SessionSalt::from_bytes([0x11; 32])
    }

    #[test]
    fn the_two_sides_agree_on_both_directions() {
        let client = derive(&password(), &salt(), Role::Client);
        let server = derive(&password(), &salt(), Role::Server);
        assert_eq!(client.send, server.recv);
        assert_eq!(server.send, client.recv);
    }

    #[test]
    fn the_two_directions_never_share_a_key() {
        let keys = derive(&password(), &salt(), Role::Client);
        assert_ne!(keys.send, keys.recv);
    }

    #[test]
    fn a_new_salt_gives_a_new_key_schedule() {
        let one = derive(&password(), &salt(), Role::Client);
        let other = derive(
            &password(),
            &SessionSalt::from_bytes([0x12; 32]),
            Role::Client,
        );
        assert_ne!(one.send, other.send);
    }

    #[test]
    fn a_different_password_gives_a_different_key_schedule() {
        let one = derive(&password(), &salt(), Role::Client);
        let other = derive(
            &PasswordKey::derive(b"other_password").unwrap(),
            &salt(),
            Role::Client,
        );
        assert_ne!(one.send, other.send);
    }

    #[test]
    fn the_schedule_is_frozen() {
        let keys = derive(&password(), &salt(), Role::Client);
        assert_eq!(
            hex::encode(keys.send),
            "d02aaa65dc39e0607d40074b6cf510e0b2bf5c4e20e528da6ebe74b894276c00"
        );
    }
}
