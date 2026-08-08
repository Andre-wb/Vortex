use crate::ports::random_source::RandomSource;
use crate::random::sample::uniform;
use crate::vortex_obfs::config::VortexObfsConfig;
use crate::vortex_obfs::frame::limits::{
    aad, nonce, DATA_LEN_LEN, LENGTH_LEN, MAX_PADDING, MAX_PAYLOAD, TAG_LEN,
};
use crate::vortex_obfs::frame::mask;
use crate::vortex_obfs::schedule::keys::{DirectionKey, SessionKeys};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

pub struct Sealer {
    cipher: Aes256Gcm,
    length_key: DirectionKey,
    counter: u64,
}

impl Sealer {
    pub fn new(keys: &SessionKeys) -> Self {
        Sealer {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&keys.send)),
            length_key: keys.send_length,
            counter: 0,
        }
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn wrap(
        &mut self,
        data: &[u8],
        config: &VortexObfsConfig,
        random: &dyn RandomSource,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut offset = 0usize;
        loop {
            let end = data.len().min(offset + MAX_PAYLOAD);
            let padding = random.bytes(padding_len(config, random));
            let frame = self
                .wrap_one(&data[offset..end], &padding)
                .expect("кусок не длиннее предела кадра всегда запечатывается");
            out.extend_from_slice(&frame);
            offset = end;
            if offset >= data.len() {
                return out;
            }
        }
    }

    pub fn wrap_one(&mut self, data: &[u8], padding: &[u8]) -> Option<Vec<u8>> {
        if data.len() > MAX_PAYLOAD || padding.len() > MAX_PADDING {
            return None;
        }
        let mut plaintext = Vec::with_capacity(DATA_LEN_LEN + data.len() + padding.len());
        plaintext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(data);
        plaintext.extend_from_slice(padding);

        let body_len = (plaintext.len() + TAG_LEN) as u16;
        let wire_len = mask::hide(body_len, mask::of(&self.length_key, self.counter));
        let sealed = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce(self.counter)),
                Payload {
                    msg: &plaintext,
                    aad: &aad(wire_len, self.counter),
                },
            )
            .ok()?;
        self.counter += 1;

        let mut frame = Vec::with_capacity(LENGTH_LEN + sealed.len());
        frame.extend_from_slice(&wire_len);
        frame.extend_from_slice(&sealed);
        Some(frame)
    }
}

fn padding_len(config: &VortexObfsConfig, random: &dyn RandomSource) -> usize {
    if !config.is_usable() {
        return 0;
    }
    let span = (config.max_padding - config.min_padding) as u64 + 1;
    let drawn = config.min_padding + uniform::below(random, span) as usize;
    drawn.min(MAX_PADDING)
}

#[cfg(test)]
mod tests {
    use super::{padding_len, Sealer};
    use crate::random::os_random::OsRandom;
    use crate::vortex_obfs::config::VortexObfsConfig;
    use crate::vortex_obfs::frame::limits::{LENGTH_LEN, MAX_PADDING, MAX_PAYLOAD, TAG_LEN};
    use crate::vortex_obfs::schedule::keys::{self, SessionKeys};
    use crate::vortex_obfs::schedule::role::Role;
    use crate::vortex_obfs::schedule::salt::SessionSalt;
    use crate::vortex_obfs::secret::shared_secret::SharedSecret;

    fn session_keys() -> SessionKeys {
        keys::derive(
            &SharedSecret::derive(b"testsecret").unwrap(),
            &SessionSalt::from_bytes([0x11; 16]),
            Role::Initiator,
        )
    }

    #[test]
    fn the_length_on_the_wire_is_not_the_length_of_the_rest() {
        let mut sealer = Sealer::new(&session_keys());
        let frame = sealer.wrap_one(b"body", &[0x00; 64]).unwrap();
        let declared = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        assert_ne!(declared, frame.len() - LENGTH_LEN);
    }

    #[test]
    fn the_message_never_appears_on_the_wire() {
        let mut sealer = Sealer::new(&session_keys());
        let frame = sealer.wrap_one(b"secret-marker", &[0x00; 64]).unwrap();
        assert!(!frame.windows(13).any(|window| window == b"secret-marker"));
    }

    #[test]
    fn each_frame_advances_the_counter() {
        let mut sealer = Sealer::new(&session_keys());
        assert_eq!(sealer.counter(), 0);
        sealer.wrap_one(b"one", &[0x00; 64]).unwrap();
        sealer.wrap_one(b"two", &[0x00; 64]).unwrap();
        assert_eq!(sealer.counter(), 2);
    }

    #[test]
    fn the_same_message_twice_never_yields_the_same_bytes() {
        let mut sealer = Sealer::new(&session_keys());
        let first = sealer.wrap_one(b"body", &[0x00; 64]).unwrap();
        let second = sealer.wrap_one(b"body", &[0x00; 64]).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn a_message_larger_than_a_frame_is_refused_by_the_single_frame_path() {
        let mut sealer = Sealer::new(&session_keys());
        assert!(sealer
            .wrap_one(&vec![0x41; MAX_PAYLOAD + 1], &[0x00; 64])
            .is_none());
        assert!(sealer
            .wrap_one(b"body", &vec![0x00; MAX_PADDING + 1])
            .is_none());
    }

    #[test]
    fn a_message_larger_than_a_frame_is_split_by_the_stream_path() {
        let mut sealer = Sealer::new(&session_keys());
        let config = VortexObfsConfig::default();
        let random = OsRandom::new();
        sealer.wrap(&vec![0x41; MAX_PAYLOAD * 2 + 7], &config, &random);
        assert_eq!(sealer.counter(), 3);
    }

    #[test]
    fn an_empty_message_still_produces_one_frame() {
        let mut sealer = Sealer::new(&session_keys());
        let config = VortexObfsConfig::default();
        let random = OsRandom::new();
        let frames = sealer.wrap(b"", &config, &random);
        assert_eq!(sealer.counter(), 1);
        assert!(frames.len() >= LENGTH_LEN + 2 + TAG_LEN + config.min_padding);
    }

    #[test]
    fn a_short_message_is_never_sent_at_its_own_length() {
        let mut sealer = Sealer::new(&session_keys());
        let config = VortexObfsConfig::default();
        let random = OsRandom::new();
        for _ in 0..200 {
            let frame = sealer.wrap(b"hi", &config, &random);
            assert!(frame.len() >= LENGTH_LEN + 2 + 2 + TAG_LEN + config.min_padding);
        }
    }

    #[test]
    fn the_padding_length_varies_between_frames() {
        let config = VortexObfsConfig::default();
        let random = OsRandom::new();
        let mut seen: Vec<usize> = (0..200).map(|_| padding_len(&config, &random)).collect();
        seen.sort_unstable();
        seen.dedup();
        assert!(seen.len() > 50, "длина паддинга предсказуема");
        assert!(seen
            .iter()
            .all(|len| (config.min_padding..=config.max_padding).contains(len)));
    }

    #[test]
    fn a_padding_range_that_means_nothing_adds_no_padding() {
        let config = VortexObfsConfig::new(512, 64);
        let random = OsRandom::new();
        assert_eq!(padding_len(&config, &random), 0);
    }
}
