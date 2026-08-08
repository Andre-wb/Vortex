use crate::shadowsocks::frame::limits::{
    frame_len, nonce, LENGTH_CHUNK_LEN, MAX_PAYLOAD, NONCES_PER_FRAME,
};
use crate::shadowsocks::frame::step::FrameStep;
use crate::shadowsocks::schedule::keys::SessionKeys;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

pub struct Opener {
    cipher: Aes256Gcm,
    counter: u64,
}

impl Opener {
    pub fn new(keys: &SessionKeys) -> Self {
        Opener {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&keys.recv)),
            counter: 0,
        }
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn opened_frames(&self) -> u64 {
        self.counter / NONCES_PER_FRAME
    }

    pub fn step(&mut self, buffer: &[u8]) -> FrameStep {
        if buffer.len() < LENGTH_CHUNK_LEN {
            return FrameStep::NeedMore;
        }
        let declared = match self.cipher.decrypt(
            Nonce::from_slice(&nonce(self.counter)),
            &buffer[..LENGTH_CHUNK_LEN],
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => return FrameStep::Malformed,
        };
        let payload_len = usize::from(u16::from_be_bytes([declared[0], declared[1]]));
        if payload_len == 0 || payload_len > MAX_PAYLOAD {
            return FrameStep::Malformed;
        }
        let whole = frame_len(payload_len);
        if buffer.len() < whole {
            return FrameStep::NeedMore;
        }
        let body = match self.cipher.decrypt(
            Nonce::from_slice(&nonce(self.counter + 1)),
            &buffer[LENGTH_CHUNK_LEN..whole],
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => return FrameStep::Malformed,
        };
        self.counter += NONCES_PER_FRAME;
        FrameStep::Opened {
            consumed: whole,
            body,
        }
    }

    pub fn drain(&mut self, buffer: &[u8]) -> Option<(usize, Vec<u8>)> {
        let mut data = Vec::new();
        let mut offset = 0usize;
        while offset < buffer.len() {
            match self.step(&buffer[offset..]) {
                FrameStep::Opened { consumed, body } => {
                    data.extend_from_slice(&body);
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
    use crate::shadowsocks::frame::limits::{LENGTH_CHUNK_LEN, MAX_FRAME, MAX_PAYLOAD};
    use crate::shadowsocks::frame::sealer::Sealer;
    use crate::shadowsocks::frame::step::FrameStep;
    use crate::shadowsocks::schedule::keys;
    use crate::shadowsocks::schedule::role::Role;
    use crate::shadowsocks::schedule::salt::SessionSalt;
    use crate::shadowsocks::secret::password_key::PasswordKey;

    fn pair() -> (Sealer, Opener) {
        let password = PasswordKey::derive(b"test_password").unwrap();
        let salt = SessionSalt::from_bytes([0x11; 32]);
        (
            Sealer::new(&keys::derive(&password, &salt, Role::Client)),
            Opener::new(&keys::derive(&password, &salt, Role::Server)),
        )
    }

    #[test]
    fn what_one_side_sealed_the_other_side_opens() {
        let (mut sealer, mut opener) = pair();
        let frame = sealer.seal_one(b"Hello, Vortex!").unwrap();
        assert_eq!(opener.open(&frame), Some(b"Hello, Vortex!".to_vec()));
    }

    #[test]
    fn a_frame_captured_from_the_wire_never_opens_twice() {
        let (mut sealer, mut opener) = pair();
        let frame = sealer.seal_one(b"body").unwrap();
        assert!(opener.open(&frame).is_some());
        assert!(opener.step(&frame).is_malformed());
        assert!(opener.open(&frame).is_none());
    }

    #[test]
    fn a_frame_captured_from_another_session_does_not_open() {
        let (mut sealer, _) = pair();
        let frame = sealer.seal_one(b"body").unwrap();
        let password = PasswordKey::derive(b"test_password").unwrap();
        let mut stranger = Opener::new(&keys::derive(
            &password,
            &SessionSalt::from_bytes([0x12; 32]),
            Role::Server,
        ));
        assert!(stranger.step(&frame).is_malformed());
    }

    #[test]
    fn a_frame_from_a_stranger_with_another_password_does_not_open() {
        let (mut sealer, _) = pair();
        let frame = sealer.seal_one(b"body").unwrap();
        let salt = SessionSalt::from_bytes([0x11; 32]);
        let mut stranger = Opener::new(&keys::derive(
            &PasswordKey::derive(b"other_password").unwrap(),
            &salt,
            Role::Server,
        ));
        assert!(stranger.step(&frame).is_malformed());
    }

    #[test]
    fn frames_out_of_order_are_refused() {
        let (mut sealer, mut opener) = pair();
        let _first = sealer.seal_one(b"one").unwrap();
        let second = sealer.seal_one(b"two").unwrap();
        assert!(opener.step(&second).is_malformed());
    }

    #[test]
    fn a_tampered_body_is_refused() {
        let (mut sealer, mut opener) = pair();
        let mut frame = sealer.seal_one(b"body").unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert!(opener.step(&frame).is_malformed());
    }

    #[test]
    fn a_tampered_length_is_refused_before_the_body_is_touched() {
        let (mut sealer, mut opener) = pair();
        let mut frame = sealer.seal_one(b"body").unwrap();
        frame[0] ^= 0x01;
        assert!(opener.step(&frame).is_malformed());
    }

    #[test]
    fn a_frame_arriving_byte_by_byte_asks_for_more_until_it_is_whole() {
        let (mut sealer, mut opener) = pair();
        let frame = sealer.seal_one(b"body").unwrap();
        for taken in 0..frame.len() {
            assert_eq!(
                opener.step(&frame[..taken]),
                FrameStep::NeedMore,
                "префикс длиной {taken} должен был просить ещё"
            );
        }
        assert!(opener.step(&frame).is_opened());
    }

    #[test]
    fn the_length_is_read_before_the_body_arrives() {
        let (mut sealer, mut opener) = pair();
        let frame = sealer.seal_one(&[0x41; 4096]).unwrap();
        assert!(opener.step(&frame[..LENGTH_CHUNK_LEN]).needs_more());
        assert_eq!(opener.counter(), 0, "неполный кадр сдвинул счётчик");
    }

    #[test]
    fn nothing_incomplete_is_ever_longer_than_the_biggest_frame() {
        let (mut sealer, mut opener) = pair();
        let stream = sealer.seal(&vec![0x41; MAX_PAYLOAD]);
        for taken in 0..stream.len() {
            if opener.step(&stream[..taken]).needs_more() {
                assert!(taken < MAX_FRAME, "просит ещё, имея {taken} байт");
            }
        }
    }

    #[test]
    fn several_frames_in_one_read_are_all_opened() {
        let (mut sealer, mut opener) = pair();
        let stream = sealer.seal(&vec![0x41; MAX_PAYLOAD * 2 + 7]);
        assert_eq!(opener.open(&stream), Some(vec![0x41; MAX_PAYLOAD * 2 + 7]));
        assert_eq!(opener.opened_frames(), 3);
    }

    #[test]
    fn a_read_that_ends_mid_frame_loses_neither_the_frames_before_it_nor_the_session() {
        let (mut sealer, mut opener) = pair();
        let mut both = sealer.seal_one(b"one").unwrap();
        both.extend_from_slice(&sealer.seal_one(b"two").unwrap());
        assert_eq!(opener.open(&both[..both.len() - 1]), None);
        assert_eq!(opener.counter(), 0, "недочитанный хвост съел готовый кадр");
        assert_eq!(opener.open(&both), Some(b"onetwo".to_vec()));
    }

    #[test]
    fn draining_a_stream_returns_the_whole_frames_and_leaves_the_tail() {
        let (mut sealer, mut opener) = pair();
        let mut both = sealer.seal_one(b"one").unwrap();
        let first_len = both.len();
        both.extend_from_slice(&sealer.seal_one(b"two").unwrap());
        let (consumed, data) = opener.drain(&both[..both.len() - 1]).unwrap();
        assert_eq!(consumed, first_len);
        assert_eq!(data, b"one".to_vec());
        assert_eq!(opener.opened_frames(), 1);
    }

    #[test]
    fn draining_a_stream_that_is_not_a_stream_refuses() {
        let (mut sealer, mut opener) = pair();
        let mut frame = sealer.seal_one(b"body").unwrap();
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
    fn a_refused_frame_does_not_advance_the_counter() {
        let (mut sealer, mut opener) = pair();
        let mut frame = sealer.seal_one(b"body").unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert!(opener.step(&frame).is_malformed());
        assert_eq!(opener.counter(), 0);
        frame[last] ^= 0x01;
        assert!(opener.step(&frame).is_opened());
    }
}
