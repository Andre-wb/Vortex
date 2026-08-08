use crate::shadowsocks::session::Session;
use crate::socks::destination::Destination;

pub struct Accepted {
    pub session: Session,
    pub destination: Destination,
    pub payload: Vec<u8>,
    pub consumed: usize,
}

impl Accepted {
    pub fn new(
        session: Session,
        destination: Destination,
        payload: Vec<u8>,
        consumed: usize,
    ) -> Self {
        Accepted {
            session,
            destination,
            payload,
            consumed,
        }
    }

    pub fn host(&self) -> String {
        self.destination.host()
    }

    pub fn port(&self) -> u16 {
        self.destination.port
    }
}

#[cfg(test)]
mod tests {
    use super::Accepted;
    use crate::shadowsocks::schedule::keys;
    use crate::shadowsocks::schedule::role::Role;
    use crate::shadowsocks::schedule::salt::SessionSalt;
    use crate::shadowsocks::secret::password_key::PasswordKey;
    use crate::shadowsocks::session::Session;
    use crate::socks::destination::Destination;

    #[test]
    fn an_accepted_request_reports_where_it_wants_to_go() {
        let password = PasswordKey::derive(b"test_password").unwrap();
        let salt = SessionSalt::from_bytes([0x11; 32]);
        let session = Session::new(&keys::derive(&password, &salt, Role::Server));
        let accepted = Accepted::new(
            session,
            Destination::resolve("www.example.com", 9000).unwrap(),
            b"hello".to_vec(),
            77,
        );
        assert_eq!(accepted.host(), "www.example.com");
        assert_eq!(accepted.port(), 9000);
        assert_eq!(accepted.payload, b"hello");
        assert_eq!(accepted.consumed, 77);
    }
}
