use crate::shadowtls::session::keys::{SessionKey, SessionKeys};
use crate::tls::record::header::{
    self, CONTENT_APPLICATION_DATA, RECORD_HEADER_LEN, RECORD_VERSION,
};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

pub const TLS_RECORD_MAX: usize = 16384;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

pub struct SealedStream {
    send: Aes256Gcm,
    recv: Aes256Gcm,
    send_seq: u64,
    recv_seq: u64,
}

impl SealedStream {
    pub fn new(keys: &SessionKeys) -> Self {
        SealedStream {
            send: cipher(&keys.send),
            recv: cipher(&keys.recv),
            send_seq: 0,
            recv_seq: 0,
        }
    }

    pub fn wrap(&mut self, data: &[u8]) -> Vec<u8> {
        let chunk = TLS_RECORD_MAX - TAG_LEN;
        let mut out = Vec::new();
        let mut offset = 0usize;
        loop {
            let end = data.len().min(offset + chunk);
            let piece = &data[offset..end];
            let head = header::encode(CONTENT_APPLICATION_DATA, piece.len() + TAG_LEN)
                .expect("кусок не длиннее 16 КиБ всегда помещается в TLS-запись");
            let sealed = self
                .send
                .encrypt(
                    Nonce::from_slice(&nonce(self.send_seq)),
                    Payload {
                        msg: piece,
                        aad: &aad(&head, self.send_seq),
                    },
                )
                .expect("AES-256-GCM запечатывает запись не длиннее 16 КиБ");
            out.extend_from_slice(&head);
            out.extend_from_slice(&sealed);
            self.send_seq += 1;
            offset = end;
            if offset >= data.len() {
                return out;
            }
        }
    }

    pub fn unwrap(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos + RECORD_HEADER_LEN <= frame.len() {
            let head = &frame[pos..pos + RECORD_HEADER_LEN];
            if head[0] != CONTENT_APPLICATION_DATA || head[1..3] != RECORD_VERSION {
                return None;
            }
            let body_len = usize::from(u16::from_be_bytes([head[3], head[4]]));
            pos += RECORD_HEADER_LEN;
            if pos + body_len > frame.len() || body_len < TAG_LEN {
                return None;
            }
            let opened = self
                .recv
                .decrypt(
                    Nonce::from_slice(&nonce(self.recv_seq)),
                    Payload {
                        msg: &frame[pos..pos + body_len],
                        aad: &aad(head, self.recv_seq),
                    },
                )
                .ok()?;
            out.extend_from_slice(&opened);
            self.recv_seq += 1;
            pos += body_len;
        }
        if pos != frame.len() {
            return None;
        }
        Some(out)
    }
}

fn cipher(key: &SessionKey) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
}

fn nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    out[NONCE_LEN - 8..].copy_from_slice(&seq.to_be_bytes());
    out
}

fn aad(head: &[u8], seq: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.len() + 8);
    out.extend_from_slice(head);
    out.extend_from_slice(&seq.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::{nonce, SealedStream, TAG_LEN, TLS_RECORD_MAX};
    use crate::shadowtls::secret::password_key;
    use crate::shadowtls::session::keys;
    use crate::shadowtls::session::role::Role;
    use crate::shadowtls::switch::session_id::SessionId;

    fn pair() -> (SealedStream, SealedStream) {
        let key = password_key::derive(b"testpass").unwrap();
        let session_id = SessionId::from_bytes([0x02; 16]);
        (
            SealedStream::new(&keys::derive(&key, &[0x01; 32], &session_id, Role::Server)),
            SealedStream::new(&keys::derive(&key, &[0x01; 32], &session_id, Role::Client)),
        )
    }

    #[test]
    fn what_one_side_wraps_the_other_unwraps() {
        let (mut server, mut client) = pair();
        let frame = server.wrap(b"hello");
        assert_eq!(client.unwrap(&frame), Some(b"hello".to_vec()));
        let back = client.wrap(b"world");
        assert_eq!(server.unwrap(&back), Some(b"world".to_vec()));
    }

    #[test]
    fn every_record_looks_like_tls_application_data() {
        let (mut server, _) = pair();
        let frame = server.wrap(b"body");
        assert_eq!(&frame[..3], &[0x17, 0x03, 0x03]);
        assert_eq!(
            usize::from(u16::from_be_bytes([frame[3], frame[4]])),
            frame.len() - 5
        );
    }

    #[test]
    fn data_larger_than_a_record_is_split_and_rejoined() {
        let (mut server, mut client) = pair();
        let payload = vec![0x5A; TLS_RECORD_MAX * 2 + 7];
        let frame = server.wrap(&payload);
        assert_eq!(client.unwrap(&frame), Some(payload));
    }

    #[test]
    fn an_empty_payload_still_produces_one_record() {
        let (mut server, mut client) = pair();
        let frame = server.wrap(b"");
        assert_eq!(frame.len(), 5 + TAG_LEN);
        assert_eq!(client.unwrap(&frame), Some(Vec::new()));
    }

    #[test]
    fn a_reordered_record_is_refused() {
        let (mut server, mut client) = pair();
        let _first = server.wrap(b"one");
        let second = server.wrap(b"two");
        assert_eq!(client.unwrap(&second), None);
    }

    #[test]
    fn a_replayed_record_is_refused() {
        let (mut server, mut client) = pair();
        let first = server.wrap(b"one");
        assert_eq!(client.unwrap(&first), Some(b"one".to_vec()));
        assert_eq!(client.unwrap(&first), None);
    }

    #[test]
    fn a_tampered_body_is_refused() {
        let (mut server, mut client) = pair();
        let mut frame = server.wrap(b"one");
        frame[7] ^= 0x01;
        assert_eq!(client.unwrap(&frame), None);
    }

    #[test]
    fn a_tampered_header_is_refused() {
        let (mut server, mut client) = pair();
        let mut frame = server.wrap(b"one");
        frame[0] = 0x16;
        assert_eq!(client.unwrap(&frame), None);
    }

    #[test]
    fn a_truncated_or_padded_frame_is_refused() {
        let (mut server, mut client) = pair();
        let frame = server.wrap(b"one");
        assert_eq!(client.unwrap(&frame[..frame.len() - 1]), None);
        let mut longer = frame.clone();
        longer.push(0x00);
        assert_eq!(client.unwrap(&longer), None);
    }

    #[test]
    fn the_other_direction_cannot_open_the_stream() {
        let (mut server, _) = pair();
        let mut peer = {
            let key = password_key::derive(b"testpass").unwrap();
            let session_id = SessionId::from_bytes([0x02; 16]);
            SealedStream::new(&keys::derive(&key, &[0x01; 32], &session_id, Role::Server))
        };
        let frame = server.wrap(b"one");
        assert_eq!(peer.unwrap(&frame), None);
    }

    #[test]
    fn the_nonce_is_the_record_counter() {
        assert_eq!(nonce(0), [0u8; 12]);
        assert_eq!(
            nonce(1),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "счётчик занимает младшие восемь байт"
        );
    }
}
