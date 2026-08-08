use crate::shadowsocks::schedule::salt::SessionSalt;
use crate::shadowsocks::session::Session;

pub struct Handshake {
    pub salt: SessionSalt,
    pub session: Session,
    pub request: Vec<u8>,
}

impl Handshake {
    pub fn new(salt: SessionSalt, session: Session, request: Vec<u8>) -> Self {
        Handshake {
            salt,
            session,
            request,
        }
    }

    pub fn prologue(&self) -> &[u8] {
        self.salt.as_bytes()
    }

    pub fn stream(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.prologue().len() + self.request.len());
        out.extend_from_slice(self.prologue());
        out.extend_from_slice(&self.request);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::Handshake;
    use crate::shadowsocks::schedule::keys;
    use crate::shadowsocks::schedule::role::Role;
    use crate::shadowsocks::schedule::salt::{SessionSalt, SALT_LEN};
    use crate::shadowsocks::secret::password_key::PasswordKey;
    use crate::shadowsocks::session::Session;

    fn handshake() -> Handshake {
        let password = PasswordKey::derive(b"test_password").unwrap();
        let salt = SessionSalt::from_bytes([0x11; SALT_LEN]);
        let session = Session::new(&keys::derive(&password, &salt, Role::Client));
        Handshake::new(salt, session, b"sealed".to_vec())
    }

    #[test]
    fn the_prologue_is_the_salt_and_nothing_else() {
        let handshake = handshake();
        assert_eq!(handshake.prologue(), &[0x11; SALT_LEN]);
    }

    #[test]
    fn the_stream_is_the_prologue_followed_by_the_request() {
        let handshake = handshake();
        let stream = handshake.stream();
        assert_eq!(&stream[..SALT_LEN], handshake.prologue());
        assert_eq!(&stream[SALT_LEN..], b"sealed");
    }
}
