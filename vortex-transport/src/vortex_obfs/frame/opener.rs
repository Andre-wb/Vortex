use crate::vortex_obfs::frame::limits::{aad, nonce, DATA_LEN_LEN, LENGTH_LEN, MAX_BODY, MIN_BODY};
use crate::vortex_obfs::frame::mask;
use crate::vortex_obfs::frame::step::FrameStep;
use crate::vortex_obfs::schedule::keys::{DirectionKey, SessionKeys};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

pub struct Opener {
    cipher: Aes256Gcm,
    length_key: DirectionKey,
    counter: u64,
}

impl Opener {
    pub fn new(keys: &SessionKeys) -> Self {
        Opener {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&keys.recv)),
            length_key: keys.recv_length,
            counter: 0,
        }
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn step(&mut self, buffer: &[u8]) -> FrameStep {
        if buffer.len() < LENGTH_LEN {
            return FrameStep::NeedMore;
        }
        let wire_len = [buffer[0], buffer[1]];
        let body_len = usize::from(mask::reveal(
            wire_len,
            mask::of(&self.length_key, self.counter),
        ));
        if !(MIN_BODY..=MAX_BODY).contains(&body_len) {
            return FrameStep::Malformed;
        }
        let frame_len = LENGTH_LEN + body_len;
        if buffer.len() < frame_len {
            return FrameStep::NeedMore;
        }
        let opened = match self.cipher.decrypt(
            Nonce::from_slice(&nonce(self.counter)),
            Payload {
                msg: &buffer[LENGTH_LEN..frame_len],
                aad: &aad(wire_len, self.counter),
            },
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => return FrameStep::Malformed,
        };
        if opened.len() < DATA_LEN_LEN {
            return FrameStep::Malformed;
        }
        let data_len = usize::from(u16::from_be_bytes([opened[0], opened[1]]));
        if DATA_LEN_LEN + data_len > opened.len() {
            return FrameStep::Malformed;
        }
        self.counter += 1;
        FrameStep::Opened {
            consumed: frame_len,
            data: opened[DATA_LEN_LEN..DATA_LEN_LEN + data_len].to_vec(),
        }
    }

    pub fn drain(&mut self, buffer: &[u8]) -> Option<(usize, Vec<u8>)> {
        let mut data = Vec::new();
        let mut offset = 0usize;
        while offset < buffer.len() {
            match self.step(&buffer[offset..]) {
                FrameStep::Opened {
                    consumed,
                    data: part,
                } => {
                    data.extend_from_slice(&part);
                    offset += consumed;
                }
                FrameStep::NeedMore => break,
                FrameStep::Malformed => return None,
            }
        }
        Some((offset, data))
    }

    pub fn open(&mut self, buffer: &[u8]) -> Option<Vec<u8>> {
        let counter = self.counter;
        match self.drain(buffer) {
            Some((consumed, data)) if consumed == buffer.len() => Some(data),
            _ => {
                self.counter = counter;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Opener;
    use crate::random::os_random::OsRandom;
    use crate::vortex_obfs::config::VortexObfsConfig;
    use crate::vortex_obfs::frame::limits::{MAX_FRAME, MAX_PAYLOAD};
    use crate::vortex_obfs::frame::sealer::Sealer;
    use crate::vortex_obfs::frame::step::FrameStep;
    use crate::vortex_obfs::schedule::keys;
    use crate::vortex_obfs::schedule::role::Role;
    use crate::vortex_obfs::schedule::salt::SessionSalt;
    use crate::vortex_obfs::secret::shared_secret::SharedSecret;

    fn pair() -> (Sealer, Opener) {
        let secret = SharedSecret::derive(b"testsecret").unwrap();
        let salt = SessionSalt::from_bytes([0x11; 16]);
        (
            Sealer::new(&keys::derive(&secret, &salt, Role::Initiator)),
            Opener::new(&keys::derive(&secret, &salt, Role::Responder)),
        )
    }

    #[test]
    fn what_one_side_sealed_the_other_side_opens() {
        let (mut sealer, mut opener) = pair();
        let frame = sealer.wrap_one(b"Hello, Vortex!", &[0x00; 64]).unwrap();
        assert_eq!(opener.open(&frame), Some(b"Hello, Vortex!".to_vec()));
    }

    #[test]
    fn a_frame_captured_from_the_wire_never_opens_twice() {
        let (mut sealer, mut opener) = pair();
        let frame = sealer.wrap_one(b"body", &[0x00; 64]).unwrap();
        assert!(opener.open(&frame).is_some());
        assert!(!matches!(opener.step(&frame), FrameStep::Opened { .. }));
        assert!(opener.open(&frame).is_none());
    }

    #[test]
    fn a_frame_captured_from_another_session_does_not_open() {
        let (mut sealer, _) = pair();
        let frame = sealer.wrap_one(b"body", &[0x00; 64]).unwrap();
        let secret = SharedSecret::derive(b"testsecret").unwrap();
        let mut stranger = Opener::new(&keys::derive(
            &secret,
            &SessionSalt::from_bytes([0x12; 16]),
            Role::Responder,
        ));
        assert_eq!(stranger.step(&frame), FrameStep::Malformed);
    }

    #[test]
    fn frames_out_of_order_are_refused() {
        let (mut sealer, mut opener) = pair();
        let _first = sealer.wrap_one(b"one", &[0x00; 64]).unwrap();
        let second = sealer.wrap_one(b"two", &[0x00; 64]).unwrap();
        assert_eq!(opener.step(&second), FrameStep::Malformed);
    }

    #[test]
    fn a_tampered_frame_is_refused() {
        let (mut sealer, mut opener) = pair();
        let mut frame = sealer.wrap_one(b"body", &[0x00; 64]).unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert_eq!(opener.step(&frame), FrameStep::Malformed);
    }

    #[test]
    fn a_tampered_length_is_refused() {
        let (mut sealer, mut opener) = pair();
        let mut frame = sealer.wrap_one(b"body", &[0x00; 64]).unwrap();
        frame[0] ^= 0x01;
        assert_ne!(
            opener.step(&frame),
            FrameStep::Opened {
                consumed: frame.len(),
                data: b"body".to_vec()
            }
        );
    }

    #[test]
    fn a_frame_arriving_byte_by_byte_asks_for_more_until_it_is_whole() {
        let (mut sealer, mut opener) = pair();
        let frame = sealer.wrap_one(b"body", &[0x00; 64]).unwrap();
        for taken in 0..frame.len() {
            assert_eq!(
                opener.step(&frame[..taken]),
                FrameStep::NeedMore,
                "префикс длиной {taken} должен был просить ещё"
            );
        }
        assert!(matches!(opener.step(&frame), FrameStep::Opened { .. }));
    }

    #[test]
    fn nothing_incomplete_is_ever_longer_than_the_biggest_frame() {
        let (mut sealer, mut opener) = pair();
        let config = VortexObfsConfig::default();
        let random = OsRandom::new();
        let frames = sealer.wrap(&vec![0x41; MAX_PAYLOAD], &config, &random);
        for taken in 0..frames.len().min(MAX_FRAME + 1) {
            if opener.step(&frames[..taken]) == FrameStep::NeedMore {
                assert!(taken < MAX_FRAME);
            }
        }
    }

    #[test]
    fn several_frames_in_one_read_are_all_opened() {
        let (mut sealer, mut opener) = pair();
        let config = VortexObfsConfig::default();
        let random = OsRandom::new();
        let frames = sealer.wrap(&vec![0x41; MAX_PAYLOAD * 2 + 7], &config, &random);
        assert_eq!(opener.open(&frames), Some(vec![0x41; MAX_PAYLOAD * 2 + 7]));
    }

    #[test]
    fn a_buffer_that_ends_mid_frame_opens_nothing() {
        let (mut sealer, mut opener) = pair();
        let frame = sealer.wrap_one(b"body", &[0x00; 64]).unwrap();
        assert_eq!(opener.open(&frame[..frame.len() - 1]), None);
    }

    #[test]
    fn a_read_that_ends_mid_frame_loses_neither_the_frames_before_it_nor_the_session() {
        let (mut sealer, mut opener) = pair();
        let mut both = sealer.wrap_one(b"one", &[0x00; 64]).unwrap();
        both.extend_from_slice(&sealer.wrap_one(b"two", &[0x00; 64]).unwrap());
        assert_eq!(opener.open(&both[..both.len() - 1]), None);
        assert_eq!(opener.counter(), 0, "недочитанный хвост съел готовый кадр");
        assert_eq!(opener.open(&both), Some(b"onetwo".to_vec()));
    }

    #[test]
    fn draining_a_stream_returns_the_whole_frames_and_leaves_the_tail() {
        let (mut sealer, mut opener) = pair();
        let mut both = sealer.wrap_one(b"one", &[0x00; 64]).unwrap();
        let first_len = both.len();
        both.extend_from_slice(&sealer.wrap_one(b"two", &[0x00; 64]).unwrap());
        let (consumed, data) = opener.drain(&both[..both.len() - 1]).unwrap();
        assert_eq!(consumed, first_len);
        assert_eq!(data, b"one".to_vec());
        assert_eq!(opener.counter(), 1);
    }

    #[test]
    fn draining_a_stream_that_is_not_a_stream_refuses() {
        let (mut sealer, mut opener) = pair();
        let mut frame = sealer.wrap_one(b"body", &[0x00; 64]).unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert_eq!(opener.drain(&frame), None);
    }

    #[test]
    fn draining_nothing_consumes_nothing() {
        let (_, mut opener) = pair();
        assert_eq!(opener.drain(&[]), Some((0, Vec::new())));
        assert_eq!(opener.drain(&[0x00]), Some((0, Vec::new())));
    }

    #[test]
    fn an_empty_buffer_opens_an_empty_message() {
        let (_, mut opener) = pair();
        assert_eq!(opener.open(&[]), Some(Vec::new()));
    }

    #[test]
    fn a_refused_frame_does_not_advance_the_counter() {
        let (mut sealer, mut opener) = pair();
        let mut frame = sealer.wrap_one(b"body", &[0x00; 64]).unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert_eq!(opener.step(&frame), FrameStep::Malformed);
        assert_eq!(opener.counter(), 0);
        frame[last] ^= 0x01;
        assert!(matches!(opener.step(&frame), FrameStep::Opened { .. }));
    }
}
