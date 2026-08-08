use crate::ports::random_source::RandomSource;
use crate::vortex_obfs::config::VortexObfsConfig;
use crate::vortex_obfs::frame::opener::Opener;
use crate::vortex_obfs::frame::sealer::Sealer;
use crate::vortex_obfs::frame::step::FrameStep;
use crate::vortex_obfs::schedule::keys::SessionKeys;

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

    pub fn wrap(
        &mut self,
        data: &[u8],
        config: &VortexObfsConfig,
        random: &dyn RandomSource,
    ) -> Vec<u8> {
        self.sealer.wrap(data, config, random)
    }

    pub fn wrap_one(&mut self, data: &[u8], padding: &[u8]) -> Option<Vec<u8>> {
        self.sealer.wrap_one(data, padding)
    }

    pub fn step(&mut self, buffer: &[u8]) -> FrameStep {
        self.opener.step(buffer)
    }

    pub fn unwrap(&mut self, buffer: &[u8]) -> Option<Vec<u8>> {
        self.opener.open(buffer)
    }

    pub fn drain(&mut self, buffer: &[u8]) -> Option<(usize, Vec<u8>)> {
        self.opener.drain(buffer)
    }

    pub fn sealed_frames(&self) -> u64 {
        self.sealer.counter()
    }

    pub fn opened_frames(&self) -> u64 {
        self.opener.counter()
    }
}

#[cfg(test)]
mod tests {
    use super::Session;
    use crate::random::os_random::OsRandom;
    use crate::vortex_obfs::config::VortexObfsConfig;
    use crate::vortex_obfs::schedule::keys;
    use crate::vortex_obfs::schedule::role::Role;
    use crate::vortex_obfs::schedule::salt::SessionSalt;
    use crate::vortex_obfs::secret::shared_secret::SharedSecret;

    fn pair() -> (Session, Session) {
        let secret = SharedSecret::derive(b"testsecret").unwrap();
        let salt = SessionSalt::from_bytes([0x11; 16]);
        (
            Session::new(&keys::derive(&secret, &salt, Role::Initiator)),
            Session::new(&keys::derive(&secret, &salt, Role::Responder)),
        )
    }

    #[test]
    fn the_two_sides_talk_in_both_directions() {
        let (mut initiator, mut responder) = pair();
        let config = VortexObfsConfig::default();
        let random = OsRandom::new();
        let there = initiator.wrap(b"ping", &config, &random);
        assert_eq!(responder.unwrap(&there), Some(b"ping".to_vec()));
        let back = responder.wrap(b"pong", &config, &random);
        assert_eq!(initiator.unwrap(&back), Some(b"pong".to_vec()));
    }

    #[test]
    fn a_side_cannot_open_what_it_sealed_itself() {
        let (mut initiator, _) = pair();
        let config = VortexObfsConfig::default();
        let random = OsRandom::new();
        let frame = initiator.wrap(b"ping", &config, &random);
        assert_eq!(initiator.unwrap(&frame), None);
    }

    #[test]
    fn a_read_that_ends_mid_frame_leaves_the_session_where_it_was() {
        let (mut initiator, mut responder) = pair();
        let config = VortexObfsConfig::default();
        let random = OsRandom::new();
        let stream = initiator.wrap(b"ping", &config, &random);
        assert_eq!(responder.unwrap(&stream[..stream.len() - 1]), None);
        assert_eq!(responder.opened_frames(), 0);
        assert_eq!(responder.unwrap(&stream), Some(b"ping".to_vec()));
    }

    #[test]
    fn a_partial_read_is_drained_up_to_the_last_whole_frame() {
        let (mut initiator, mut responder) = pair();
        let config = VortexObfsConfig::default();
        let random = OsRandom::new();
        let mut stream = initiator.wrap(b"ping", &config, &random);
        let first_len = stream.len();
        stream.extend_from_slice(&initiator.wrap(b"pong", &config, &random));
        let (consumed, data) = responder.drain(&stream[..stream.len() - 1]).unwrap();
        assert_eq!(consumed, first_len);
        assert_eq!(data, b"ping".to_vec());
        let (rest, tail) = responder.drain(&stream[consumed..]).unwrap();
        assert_eq!(rest, stream.len() - consumed);
        assert_eq!(tail, b"pong".to_vec());
    }

    #[test]
    fn the_two_directions_count_separately() {
        let (mut initiator, mut responder) = pair();
        let config = VortexObfsConfig::default();
        let random = OsRandom::new();
        let there = initiator.wrap(b"ping", &config, &random);
        responder.unwrap(&there).unwrap();
        assert_eq!(initiator.sealed_frames(), 1);
        assert_eq!(initiator.opened_frames(), 0);
        assert_eq!(responder.opened_frames(), 1);
        assert_eq!(responder.sealed_frames(), 0);
    }
}
