use crate::shadowsocks::frame::opener::Opener;
use crate::shadowsocks::frame::sealer::Sealer;
use crate::shadowsocks::frame::step::FrameStep;
use crate::shadowsocks::schedule::keys::SessionKeys;

pub struct Session {
    sealer: Sealer,
    opener: Opener,
}

impl Session {
    pub fn new(keys: &SessionKeys) -> Self {
        Session {
            sealer: Sealer::new(keys),
            opener: Opener::new(keys),
        }
    }

    pub fn from_parts(sealer: Sealer, opener: Opener) -> Self {
        Session { sealer, opener }
    }

    pub fn seal(&mut self, data: &[u8]) -> Vec<u8> {
        self.sealer.seal(data)
    }

    pub fn seal_one(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        self.sealer.seal_one(body)
    }

    pub fn step(&mut self, buffer: &[u8]) -> FrameStep {
        self.opener.step(buffer)
    }

    pub fn open(&mut self, buffer: &[u8]) -> Option<Vec<u8>> {
        self.opener.open(buffer)
    }

    pub fn drain(&mut self, buffer: &[u8]) -> Option<(usize, Vec<u8>)> {
        self.opener.drain(buffer)
    }

    pub fn sealed_frames(&self) -> u64 {
        self.sealer.sealed_frames()
    }

    pub fn opened_frames(&self) -> u64 {
        self.opener.opened_frames()
    }
}

#[cfg(test)]
mod tests {
    use super::Session;
    use crate::shadowsocks::schedule::keys;
    use crate::shadowsocks::schedule::role::Role;
    use crate::shadowsocks::schedule::salt::SessionSalt;
    use crate::shadowsocks::secret::password_key::PasswordKey;

    fn pair() -> (Session, Session) {
        let password = PasswordKey::derive(b"test_password").unwrap();
        let salt = SessionSalt::from_bytes([0x11; 32]);
        (
            Session::new(&keys::derive(&password, &salt, Role::Client)),
            Session::new(&keys::derive(&password, &salt, Role::Server)),
        )
    }

    #[test]
    fn the_two_sides_talk_in_both_directions() {
        let (mut client, mut server) = pair();
        let there = client.seal(b"ping");
        assert_eq!(server.open(&there), Some(b"ping".to_vec()));
        let back = server.seal(b"pong");
        assert_eq!(client.open(&back), Some(b"pong".to_vec()));
    }

    #[test]
    fn a_side_cannot_open_what_it_sealed_itself() {
        let (mut client, _) = pair();
        let frame = client.seal(b"ping");
        assert_eq!(client.open(&frame), None);
    }

    #[test]
    fn a_read_that_ends_mid_frame_leaves_the_session_where_it_was() {
        let (mut client, mut server) = pair();
        let stream = client.seal(b"ping");
        assert_eq!(server.open(&stream[..stream.len() - 1]), None);
        assert_eq!(server.opened_frames(), 0);
        assert_eq!(server.open(&stream), Some(b"ping".to_vec()));
    }

    #[test]
    fn a_partial_read_is_drained_up_to_the_last_whole_frame() {
        let (mut client, mut server) = pair();
        let mut stream = client.seal(b"ping");
        let first_len = stream.len();
        stream.extend_from_slice(&client.seal(b"pong"));
        let (consumed, data) = server.drain(&stream[..stream.len() - 1]).unwrap();
        assert_eq!(consumed, first_len);
        assert_eq!(data, b"ping".to_vec());
        let (rest, tail) = server.drain(&stream[consumed..]).unwrap();
        assert_eq!(rest, stream.len() - consumed);
        assert_eq!(tail, b"pong".to_vec());
    }

    #[test]
    fn the_two_directions_count_separately() {
        let (mut client, mut server) = pair();
        let there = client.seal(b"ping");
        server.open(&there).unwrap();
        assert_eq!(client.sealed_frames(), 1);
        assert_eq!(client.opened_frames(), 0);
        assert_eq!(server.opened_frames(), 1);
        assert_eq!(server.sealed_frames(), 0);
    }
}
