use crate::error::{Result, TransportError};
use crate::ports::random_source::RandomSource;
use crate::shadowsocks::accepted::Accepted;
use crate::shadowsocks::client::profile::ClientProfile;
use crate::shadowsocks::config::ShadowsocksConfig;
use crate::shadowsocks::frame::limits::{LENGTH_CHUNK_LEN, MAX_PAYLOAD};
use crate::shadowsocks::frame::opener::Opener;
use crate::shadowsocks::frame::sealer::Sealer;
use crate::shadowsocks::frame::step::FrameStep;
use crate::shadowsocks::handshake::Handshake;
use crate::shadowsocks::request::header::RequestHeader;
use crate::shadowsocks::request::padding;
use crate::shadowsocks::schedule::keys::{self, SessionKeys};
use crate::shadowsocks::schedule::role::Role;
use crate::shadowsocks::schedule::salt::{SessionSalt, SALT_LEN};
use crate::shadowsocks::secret::keyring::Keyring;
use crate::shadowsocks::session::Session;
use crate::shadowsocks::verdict::Verdict;

pub struct Shadowsocks {
    keyring: Keyring,
    config: ShadowsocksConfig,
}

impl Default for Shadowsocks {
    fn default() -> Self {
        Shadowsocks::new(b"", b"")
    }
}

impl Shadowsocks {
    pub fn new(password: &[u8], previous: &[u8]) -> Self {
        Shadowsocks {
            keyring: Keyring::new(password, previous),
            config: ShadowsocksConfig::default(),
        }
    }

    pub fn with_config(mut self, config: ShadowsocksConfig) -> Self {
        self.config = config;
        self
    }

    pub fn config(&self) -> &ShadowsocksConfig {
        &self.config
    }

    pub fn is_configured(&self) -> bool {
        self.keyring.is_configured()
    }

    pub fn accepts_previous(&self) -> bool {
        self.keyring.accepts_previous()
    }

    pub fn accepted_count(&self) -> usize {
        self.keyring.accepted_count()
    }

    pub fn reload(&mut self, password: &[u8], previous: &[u8]) {
        self.keyring.reload(password, previous);
    }

    pub fn add_password(&mut self, password: &[u8]) -> bool {
        self.keyring.add(password)
    }

    pub fn client_profile(&self, server: &str, server_port: u16) -> ClientProfile {
        ClientProfile::new(server, server_port)
    }

    pub fn connect(
        &self,
        host: &str,
        port: u16,
        data: &[u8],
        random: &dyn RandomSource,
    ) -> Result<Handshake> {
        let salt = SessionSalt::generate(random);
        let padding = random.bytes(padding::length(&self.config, random));
        self.connect_with(host, port, data, salt, &padding)
    }

    pub fn connect_with(
        &self,
        host: &str,
        port: u16,
        data: &[u8],
        salt: SessionSalt,
        padding: &[u8],
    ) -> Result<Handshake> {
        let key = self
            .keyring
            .sealing_key()
            .ok_or(TransportError::ShadowsocksUnconfigured)?;
        let header = RequestHeader::resolve(host, port)
            .ok_or_else(|| TransportError::ShadowsocksAddress(host.to_owned()))?;
        if padding.len() > padding::MAX_PADDING {
            return Err(TransportError::ShadowsocksPadding {
                max: padding::MAX_PADDING,
                got: padding.len(),
            });
        }

        let mut session = Session::new(&keys::derive(key, &salt, Role::Client));
        let head = header
            .encode(padding, &[])
            .ok_or(TransportError::ShadowsocksPadding {
                max: padding::MAX_PADDING,
                got: padding.len(),
            })?;
        let taken = data.len().min(MAX_PAYLOAD.saturating_sub(head.len()));
        let mut first = head;
        first.extend_from_slice(&data[..taken]);

        let mut request = session
            .seal_one(&first)
            .ok_or(TransportError::ShadowsocksRequestTooLong)?;
        request.extend_from_slice(&session.seal(&data[taken..]));
        Ok(Handshake::new(salt, session, request))
    }

    pub fn accept(&self, stream: &[u8]) -> Verdict {
        if stream.len() < SALT_LEN {
            return Verdict::NeedMore;
        }
        let Some(salt) = SessionSalt::parse(&stream[..SALT_LEN]) else {
            return Verdict::Malformed;
        };
        let buffer = &stream[SALT_LEN..];
        if buffer.len() < LENGTH_CHUNK_LEN {
            return Verdict::NeedMore;
        }

        let mut winner: Option<(SessionKeys, Opener, usize, Vec<u8>)> = None;
        let mut incomplete = false;
        for key in self.keyring.accepted() {
            let schedule = keys::derive(key, &salt, Role::Server);
            let mut opener = Opener::new(&schedule);
            match opener.step(buffer) {
                FrameStep::Opened { consumed, body } => {
                    if winner.is_none() {
                        winner = Some((schedule, opener, consumed, body));
                    }
                }
                FrameStep::NeedMore => incomplete = true,
                FrameStep::Malformed => {}
            }
        }

        let Some((schedule, opener, consumed, body)) = winner else {
            return if incomplete {
                Verdict::NeedMore
            } else {
                Verdict::Unauthorized
            };
        };
        let Some((header, payload)) = RequestHeader::parse(&body) else {
            return Verdict::Malformed;
        };
        let sealer = Sealer::new(&schedule);
        Verdict::accept(Accepted::new(
            Session::from_parts(sealer, opener),
            header.destination,
            payload.to_vec(),
            SALT_LEN + consumed,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::Shadowsocks;
    use crate::error::TransportError;
    use crate::ports::random_source::RandomSource;
    use crate::random::os_random::OsRandom;
    use crate::shadowsocks::config::ShadowsocksConfig;
    use crate::shadowsocks::frame::limits::{LENGTH_CHUNK_LEN, MAX_FRAME, MAX_PAYLOAD};
    use crate::shadowsocks::request::padding::MAX_PADDING;
    use crate::shadowsocks::schedule::salt::{SessionSalt, SALT_LEN};

    fn guard() -> Shadowsocks {
        Shadowsocks::new(b"test_password", b"")
    }

    fn stream(guard: &Shadowsocks, host: &str, port: u16, data: &[u8]) -> Vec<u8> {
        let random = OsRandom::new();
        guard.connect(host, port, data, &random).unwrap().stream()
    }

    #[test]
    fn what_the_client_asked_for_is_what_the_server_reads() {
        let guard = guard();
        let accepted = guard
            .accept(&stream(&guard, "example.com", 9000, b"hello ss"))
            .accepted()
            .unwrap();
        assert_eq!(accepted.host(), "example.com");
        assert_eq!(accepted.port(), 9000);
        assert_eq!(accepted.payload, b"hello ss");
    }

    #[test]
    fn the_two_sides_keep_talking_after_the_request() {
        let guard = guard();
        let random = OsRandom::new();
        let mut handshake = guard.connect("example.com", 9000, b"", &random).unwrap();
        let mut accepted = guard.accept(&handshake.stream()).accepted().unwrap();
        let there = handshake.session.seal(b"ping");
        assert_eq!(accepted.session.open(&there), Some(b"ping".to_vec()));
        let back = accepted.session.seal(b"pong");
        assert_eq!(handshake.session.open(&back), Some(b"pong".to_vec()));
    }

    #[test]
    fn the_destination_never_appears_on_the_wire() {
        let guard = guard();
        let bytes = stream(&guard, "example.com", 9000, b"hello ss");
        assert!(!bytes.windows(11).any(|window| window == b"example.com"));
        assert!(!bytes.windows(8).any(|window| window == b"hello ss"));
    }

    #[test]
    fn an_unconfigured_transport_seals_nothing_and_accepts_nothing() {
        let deaf = Shadowsocks::default();
        let random = OsRandom::new();
        assert!(!deaf.is_configured());
        assert_eq!(deaf.accepted_count(), 0);
        assert!(matches!(
            deaf.connect("example.com", 9000, b"", &random),
            Err(TransportError::ShadowsocksUnconfigured)
        ));
        assert!(deaf
            .accept(&stream(&guard(), "example.com", 9000, b"x"))
            .is_unauthorized());
    }

    #[test]
    fn an_empty_password_is_not_a_password() {
        assert!(!Shadowsocks::new(b"", b"").is_configured());
        assert!(Shadowsocks::new(b"p", b"").is_configured());
    }

    #[test]
    fn a_stranger_with_another_password_is_refused() {
        let guard = guard();
        let stranger = Shadowsocks::new(b"other_password", b"");
        assert!(stranger
            .accept(&stream(&guard, "example.com", 9000, b"x"))
            .is_unauthorized());
    }

    #[test]
    fn the_previous_password_still_opens_a_request() {
        let mut guard = guard();
        let bytes = stream(&guard, "example.com", 9000, b"x");
        guard.reload(b"newer_password", b"test_password");
        assert!(guard.accept(&bytes).is_accepted());
    }

    #[test]
    fn an_extra_password_opens_a_request_too() {
        let mut server = Shadowsocks::new(b"server_password", b"");
        let client = Shadowsocks::new(b"extra_password", b"");
        let bytes = stream(&client, "example.com", 9000, b"x");
        assert!(server.accept(&bytes).is_unauthorized());
        assert!(server.add_password(b"extra_password"));
        assert!(server.accept(&bytes).is_accepted());
    }

    #[test]
    fn a_request_captured_from_another_connection_does_not_replay_into_the_same_session() {
        let guard = guard();
        let bytes = stream(&guard, "example.com", 9000, b"x");
        let first = guard.accept(&bytes).accepted().unwrap();
        let second = guard.accept(&bytes).accepted().unwrap();
        assert_eq!(first.payload, second.payload);
        let mut session = first.session;
        assert!(session.open(&bytes[SALT_LEN..]).is_none());
    }

    #[test]
    fn a_request_arriving_byte_by_byte_asks_for_more_until_it_is_whole() {
        let guard = guard();
        let bytes = stream(&guard, "example.com", 9000, b"hello ss");
        for taken in 0..bytes.len() {
            assert!(
                guard.accept(&bytes[..taken]).wants_more_bytes(),
                "префикс длиной {taken} должен был просить ещё"
            );
        }
        assert!(guard.accept(&bytes).is_accepted());
    }

    #[test]
    fn nothing_incomplete_is_ever_longer_than_the_biggest_frame() {
        let guard = guard();
        let bytes = stream(&guard, "example.com", 9000, &vec![0x41; MAX_PAYLOAD * 2]);
        for taken in (0..bytes.len()).step_by(101) {
            if guard.accept(&bytes[..taken]).wants_more_bytes() {
                assert!(
                    taken < SALT_LEN + MAX_FRAME,
                    "просит ещё, имея {taken} байт"
                );
            }
        }
    }

    #[test]
    fn a_prologue_of_random_bytes_is_refused_without_a_word_about_why() {
        let guard = guard();
        let random = OsRandom::new();
        let noise = random.bytes(SALT_LEN + 64);
        assert!(guard.accept(&noise).is_unauthorized());
    }

    #[test]
    fn the_payload_that_did_not_fit_the_request_arrives_in_the_frames_behind_it() {
        let guard = guard();
        let long = vec![0x41; MAX_PAYLOAD * 2 + 7];
        let bytes = stream(&guard, "example.com", 9000, &long);
        let mut accepted = guard.accept(&bytes).accepted().unwrap();
        let mut whole = accepted.payload.clone();
        whole.extend_from_slice(&accepted.session.open(&bytes[accepted.consumed..]).unwrap());
        assert_eq!(whole, long);
    }

    #[test]
    fn a_host_that_could_never_be_reached_is_refused_at_the_source() {
        let guard = guard();
        let random = OsRandom::new();
        for host in ["", "he re.com", "line\nbreak.com"] {
            assert!(matches!(
                guard.connect(host, 9000, b"", &random),
                Err(TransportError::ShadowsocksAddress(_))
            ));
        }
    }

    #[test]
    fn padding_past_the_ceiling_is_refused() {
        let guard = guard();
        let salt = SessionSalt::from_bytes([0x11; SALT_LEN]);
        assert!(matches!(
            guard.connect_with("example.com", 9000, b"", salt, &vec![0x00; MAX_PADDING + 1]),
            Err(TransportError::ShadowsocksPadding { .. })
        ));
    }

    #[test]
    fn a_dribble_of_bytes_never_reaches_the_keyring() {
        let deaf = Shadowsocks::default();
        let crowded = guard();
        let bytes = stream(&crowded, "example.com", 9000, b"x");
        for taken in 0..SALT_LEN + LENGTH_CHUNK_LEN {
            assert!(
                crowded.accept(&bytes[..taken]).wants_more_bytes(),
                "{taken}"
            );
            assert!(deaf.accept(&bytes[..taken]).wants_more_bytes(), "{taken}");
        }
        assert!(deaf
            .accept(&bytes[..SALT_LEN + LENGTH_CHUNK_LEN])
            .is_unauthorized());
    }

    #[test]
    fn the_biggest_request_the_format_allows_still_fits_one_frame() {
        let guard = guard();
        let salt = SessionSalt::from_bytes([0x11; SALT_LEN]);
        let longest = "a".repeat(253);
        let handshake = guard
            .connect_with(&longest, 65535, b"", salt, &vec![0x00; MAX_PADDING])
            .unwrap();
        assert!(handshake.request.len() <= MAX_FRAME);
        assert!(guard.accept(&handshake.stream()).is_accepted());
    }

    #[test]
    fn two_requests_to_the_same_host_never_look_alike() {
        let guard = guard();
        let one = stream(&guard, "example.com", 9000, b"x");
        let other = stream(&guard, "example.com", 9000, b"x");
        assert_ne!(one, other);
        let mut lengths: Vec<usize> = (0..64)
            .map(|_| stream(&guard, "example.com", 9000, b"x").len())
            .collect();
        lengths.sort_unstable();
        lengths.dedup();
        assert!(lengths.len() > 16, "длина запроса предсказуема");
    }

    #[test]
    fn a_request_is_never_sent_at_the_length_of_its_destination() {
        let guard = guard();
        let random = OsRandom::new();
        let bare = guard
            .connect_with(
                "example.com",
                9000,
                b"",
                SessionSalt::generate(&random),
                &[],
            )
            .unwrap();
        for _ in 0..64 {
            let padded = guard.connect("example.com", 9000, b"", &random).unwrap();
            assert!(padded.request.len() > bare.request.len());
        }
    }

    #[test]
    fn the_configuration_the_guard_was_given_is_the_one_it_uses() {
        let guard = guard().with_config(ShadowsocksConfig::new(8, 8));
        assert_eq!(guard.config().min_padding, 8);
        let random = OsRandom::new();
        let bare = guard
            .connect_with(
                "example.com",
                9000,
                b"",
                SessionSalt::generate(&random),
                &[],
            )
            .unwrap();
        let padded = guard.connect("example.com", 9000, b"", &random).unwrap();
        assert_eq!(padded.request.len(), bare.request.len() + 8);
    }

    #[test]
    fn a_frame_of_this_transport_never_opens_in_the_obfuscation_transport() {
        use crate::vortex_obfs::guard::VortexObfs;

        let secret = b"one secret for both transports";
        let guard = Shadowsocks::new(secret, b"");
        let obfs = VortexObfs::new(secret);
        let random = OsRandom::new();

        let bytes = stream(&guard, "example.com", 9000, b"payload");
        let mut listener = obfs
            .accept(&bytes[..crate::vortex_obfs::schedule::salt::SALT_LEN])
            .unwrap();
        assert!(listener
            .unwrap(&bytes[crate::vortex_obfs::schedule::salt::SALT_LEN..])
            .is_none());

        let mut handshake = obfs.begin(&random).unwrap();
        let frames = handshake.session.wrap(b"payload", obfs.config(), &random);
        let mut foreign = Vec::with_capacity(SALT_LEN + frames.len());
        foreign.extend_from_slice(handshake.prologue());
        foreign.extend_from_slice(&[0x00; SALT_LEN - crate::vortex_obfs::schedule::salt::SALT_LEN]);
        foreign.extend_from_slice(&frames);
        assert!(!guard.accept(&foreign).is_accepted());
    }
}
