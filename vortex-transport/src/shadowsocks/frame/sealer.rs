use crate::shadowsocks::frame::limits::{nonce, MAX_PAYLOAD, NONCES_PER_FRAME};
use crate::shadowsocks::schedule::keys::SessionKeys;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

pub struct Sealer {
    cipher: Aes256Gcm,
    counter: u64,
}

impl Sealer {
    pub fn new(keys: &SessionKeys) -> Self {
        Sealer {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&keys.send)),
            counter: 0,
        }
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn sealed_frames(&self) -> u64 {
        self.counter / NONCES_PER_FRAME
    }

    pub fn seal_one(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        if body.is_empty() || body.len() > MAX_PAYLOAD {
            return None;
        }
        let length = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce(self.counter)),
                (body.len() as u16).to_be_bytes().as_slice(),
            )
            .ok()?;
        let sealed = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce(self.counter + 1)), body)
            .ok()?;
        self.counter += NONCES_PER_FRAME;

        let mut frame = Vec::with_capacity(length.len() + sealed.len());
        frame.extend_from_slice(&length);
        frame.extend_from_slice(&sealed);
        Some(frame)
    }

    pub fn seal(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut offset = 0usize;
        while offset < data.len() {
            let end = data.len().min(offset + MAX_PAYLOAD);
            let frame = self
                .seal_one(&data[offset..end])
                .expect("непустой кусок не длиннее предела всегда запечатывается");
            out.extend_from_slice(&frame);
            offset = end;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::Sealer;
    use crate::shadowsocks::frame::limits::{frame_len, MAX_PAYLOAD};
    use crate::shadowsocks::schedule::keys::{self, SessionKeys};
    use crate::shadowsocks::schedule::role::Role;
    use crate::shadowsocks::schedule::salt::SessionSalt;
    use crate::shadowsocks::secret::password_key::PasswordKey;

    fn session_keys() -> SessionKeys {
        keys::derive(
            &PasswordKey::derive(b"test_password").unwrap(),
            &SessionSalt::from_bytes([0x11; 32]),
            Role::Client,
        )
    }

    #[test]
    fn the_body_never_appears_on_the_wire() {
        let mut sealer = Sealer::new(&session_keys());
        let frame = sealer.seal_one(b"secret-marker").unwrap();
        assert!(!frame.windows(13).any(|window| window == b"secret-marker"));
    }

    #[test]
    fn the_length_never_appears_on_the_wire_either() {
        let mut sealer = Sealer::new(&session_keys());
        let frame = sealer.seal_one(&[0x41; 4096]).unwrap();
        assert_ne!(&frame[..2], 4096u16.to_be_bytes());
    }

    #[test]
    fn a_frame_is_exactly_as_long_as_the_format_says() {
        let mut sealer = Sealer::new(&session_keys());
        assert_eq!(sealer.seal_one(b"body").unwrap().len(), frame_len(4));
    }

    #[test]
    fn each_frame_spends_two_nonces() {
        let mut sealer = Sealer::new(&session_keys());
        assert_eq!(sealer.counter(), 0);
        sealer.seal_one(b"one").unwrap();
        assert_eq!(sealer.counter(), 2);
        sealer.seal_one(b"two").unwrap();
        assert_eq!(sealer.counter(), 4);
        assert_eq!(sealer.sealed_frames(), 2);
    }

    #[test]
    fn the_same_body_twice_never_yields_the_same_bytes() {
        let mut sealer = Sealer::new(&session_keys());
        let first = sealer.seal_one(b"body").unwrap();
        let second = sealer.seal_one(b"body").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn an_empty_frame_is_not_a_frame() {
        let mut sealer = Sealer::new(&session_keys());
        assert!(sealer.seal_one(b"").is_none());
        assert_eq!(sealer.counter(), 0);
    }

    #[test]
    fn a_body_larger_than_a_frame_is_refused_by_the_single_frame_path() {
        let mut sealer = Sealer::new(&session_keys());
        assert!(sealer.seal_one(&vec![0x41; MAX_PAYLOAD + 1]).is_none());
        assert!(sealer.seal_one(&vec![0x41; MAX_PAYLOAD]).is_some());
    }

    #[test]
    fn a_body_larger_than_a_frame_is_split_by_the_stream_path() {
        let mut sealer = Sealer::new(&session_keys());
        let stream = sealer.seal(&vec![0x41; MAX_PAYLOAD * 2 + 7]);
        assert_eq!(sealer.sealed_frames(), 3);
        assert_eq!(
            stream.len(),
            frame_len(MAX_PAYLOAD) * 2 + frame_len(7),
            "поток длиннее суммы своих кадров"
        );
    }

    #[test]
    fn nothing_to_send_sends_nothing() {
        let mut sealer = Sealer::new(&session_keys());
        assert!(sealer.seal(b"").is_empty());
        assert_eq!(sealer.counter(), 0);
    }
}
