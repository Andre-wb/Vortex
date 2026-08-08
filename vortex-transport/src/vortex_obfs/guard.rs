use crate::ports::random_source::RandomSource;
use crate::vortex_obfs::config::VortexObfsConfig;
use crate::vortex_obfs::handshake::Handshake;
use crate::vortex_obfs::schedule::keys;
use crate::vortex_obfs::schedule::role::Role;
use crate::vortex_obfs::schedule::salt::SessionSalt;
use crate::vortex_obfs::secret::shared_secret::SharedSecret;
use crate::vortex_obfs::session::Session;

pub struct VortexObfs {
    secret: Option<SharedSecret>,
    config: VortexObfsConfig,
}

impl Default for VortexObfs {
    fn default() -> Self {
        VortexObfs::new(b"")
    }
}

impl VortexObfs {
    pub fn new(secret: &[u8]) -> Self {
        VortexObfs {
            secret: SharedSecret::derive(secret),
            config: VortexObfsConfig::default(),
        }
    }

    pub fn with_config(mut self, config: VortexObfsConfig) -> Self {
        self.config = config;
        self
    }

    pub fn is_configured(&self) -> bool {
        self.secret.is_some()
    }

    pub fn config(&self) -> &VortexObfsConfig {
        &self.config
    }

    pub fn begin(&self, random: &dyn RandomSource) -> Option<Handshake> {
        self.begin_with_salt(SessionSalt::generate(random))
    }

    pub fn begin_with_salt(&self, salt: SessionSalt) -> Option<Handshake> {
        let session = self.session(&salt, Role::Initiator)?;
        Some(Handshake::new(salt, session))
    }

    pub fn accept(&self, prologue: &[u8]) -> Option<Session> {
        let salt = SessionSalt::parse(prologue)?;
        self.session(&salt, Role::Responder)
    }

    fn session(&self, salt: &SessionSalt, role: Role) -> Option<Session> {
        let secret = self.secret.as_ref()?;
        Some(Session::new(&keys::derive(secret, salt, role)))
    }
}

#[cfg(test)]
mod tests {
    use super::VortexObfs;
    use crate::random::os_random::OsRandom;
    use crate::vortex_obfs::config::VortexObfsConfig;
    use crate::vortex_obfs::schedule::salt::SALT_LEN;

    #[test]
    fn an_unconfigured_transport_accepts_nothing_and_seals_nothing() {
        let guard = VortexObfs::default();
        let random = OsRandom::new();
        assert!(!guard.is_configured());
        assert!(guard.begin(&random).is_none());
        assert!(guard.accept(&[0x00; SALT_LEN]).is_none());
    }

    #[test]
    fn an_empty_secret_is_not_a_secret() {
        assert!(!VortexObfs::new(b"").is_configured());
        assert!(VortexObfs::new(b"s").is_configured());
    }

    #[test]
    fn the_prologue_carries_the_salt_the_other_side_needs() {
        let guard = VortexObfs::new(b"testsecret");
        let random = OsRandom::new();
        let handshake = guard.begin(&random).unwrap();
        assert_eq!(handshake.prologue().len(), SALT_LEN);
        let mut responder = guard.accept(handshake.prologue()).unwrap();
        let mut initiator = handshake.session;
        let frame = initiator.wrap(b"ping", guard.config(), &random);
        assert_eq!(responder.unwrap(&frame), Some(b"ping".to_vec()));
    }

    #[test]
    fn a_prologue_of_the_wrong_length_starts_no_session() {
        let guard = VortexObfs::new(b"testsecret");
        assert!(guard.accept(&[0x00; SALT_LEN - 1]).is_none());
        assert!(guard.accept(&[]).is_none());
    }

    #[test]
    fn a_frame_from_one_session_does_not_open_in_another() {
        let guard = VortexObfs::new(b"testsecret");
        let random = OsRandom::new();
        let mut first = guard.begin(&random).unwrap();
        let frame = first.session.wrap(b"ping", guard.config(), &random);
        let second = guard.begin(&random).unwrap();
        let mut listener = guard.accept(second.prologue()).unwrap();
        assert!(listener.unwrap(&frame).is_none());
    }

    #[test]
    fn a_stranger_with_another_secret_opens_nothing() {
        let guard = VortexObfs::new(b"testsecret");
        let stranger = VortexObfs::new(b"othersecret");
        let random = OsRandom::new();
        let mut handshake = guard.begin(&random).unwrap();
        let frame = handshake.session.wrap(b"ping", guard.config(), &random);
        let mut listener = stranger.accept(handshake.prologue()).unwrap();
        assert!(listener.unwrap(&frame).is_none());
    }

    #[test]
    fn the_configuration_the_guard_was_given_is_the_one_it_hands_out() {
        let guard = VortexObfs::new(b"testsecret").with_config(VortexObfsConfig::new(8, 8));
        assert_eq!(guard.config().min_padding, 8);
    }
}
