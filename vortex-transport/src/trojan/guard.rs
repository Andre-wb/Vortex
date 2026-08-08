use crate::error::{Result, TransportError};
use crate::trojan::request::decoder::{self, Decoded};
use crate::trojan::request::encoder;
use crate::trojan::request::header::Header;
use crate::trojan::request::probe::{self, Probe};
use crate::trojan::secret::keyring::Keyring;
use crate::trojan::secret::password_hash::PasswordHash;
use crate::trojan::verdict::Verdict;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trojan {
    keyring: Keyring,
}

impl Trojan {
    pub fn new(password: &[u8], previous: &[u8]) -> Self {
        Trojan {
            keyring: Keyring::new(password, previous),
        }
    }

    pub fn reload(&mut self, password: &[u8], previous: &[u8]) {
        self.keyring.reload(password, previous);
    }

    pub fn add_password(&mut self, password: &[u8]) -> bool {
        self.keyring.add(password)
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

    pub fn password_hash(&self) -> Option<&PasswordHash> {
        self.keyring.sealing_hash()
    }

    pub fn encode_request(&self, host: &str, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
        let hash = self
            .keyring
            .sealing_hash()
            .ok_or(TransportError::TrojanUnconfigured)?;
        Ok(encoder::encode(
            hash,
            &Header::connect(host, port)?,
            payload,
        ))
    }

    pub fn decode_request(&self, data: &[u8]) -> Verdict {
        match decoder::decode(data) {
            Decoded::NeedMore => Verdict::NeedMore,
            Decoded::Malformed => Verdict::Malformed,
            Decoded::Complete(incoming) => {
                if self.keyring.accepts(&incoming.hash) {
                    Verdict::Accepted(incoming)
                } else {
                    Verdict::Unauthorized
                }
            }
        }
    }

    pub fn probe(&self, data: &[u8]) -> Probe {
        probe::probe(data)
    }
}

#[cfg(test)]
mod tests {
    use super::Trojan;
    use crate::error::TransportError;
    use crate::trojan::request::probe::Probe;
    use crate::trojan::verdict::Verdict;

    fn guard() -> Trojan {
        Trojan::new(b"testpass", b"")
    }

    fn request(guard: &Trojan, payload: &[u8]) -> Vec<u8> {
        guard
            .encode_request("www.example.com", 443, payload)
            .unwrap()
    }

    #[test]
    fn a_request_it_wrote_is_a_request_it_accepts() {
        let guard = guard();
        let verdict = guard.decode_request(&request(&guard, b"hello"));
        let incoming = verdict.accepted().unwrap();
        assert_eq!(incoming.host(), "www.example.com");
        assert_eq!(incoming.payload, b"hello");
    }

    #[test]
    fn a_request_written_with_another_password_is_unauthorized_not_malformed() {
        let other = Trojan::new(b"otherpass", b"");
        assert_eq!(
            guard().decode_request(&request(&other, b"hello")),
            Verdict::Unauthorized
        );
    }

    #[test]
    fn the_previous_password_still_authenticates() {
        let rotated = Trojan::new(b"newpass", b"testpass");
        assert!(rotated
            .decode_request(&request(&guard(), b"x"))
            .is_accepted());
    }

    #[test]
    fn a_password_added_by_hand_authenticates_too() {
        let mut rotated = Trojan::new(b"newpass", b"");
        assert!(rotated.add_password(b"testpass"));
        assert!(rotated
            .decode_request(&request(&guard(), b"x"))
            .is_accepted());
    }

    #[test]
    fn an_unconfigured_guard_writes_nothing_and_accepts_nobody() {
        let guard = Trojan::new(b"", b"");
        assert!(!guard.is_configured());
        assert_eq!(
            guard.encode_request("13.10.1.2", 443, b""),
            Err(TransportError::TrojanUnconfigured)
        );
        assert_eq!(
            guard.decode_request(&request(&Trojan::new(b"testpass", b""), b"")),
            Verdict::Unauthorized
        );
    }

    #[test]
    fn the_hash_of_an_empty_password_authenticates_nobody() {
        let guard = Trojan::new(b"", b"");
        let mut data = b"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f".to_vec();
        data.extend_from_slice(b"\r\n\x01\x01\x0d\x0a\x01\x02\x01\xbb\r\n");
        assert_eq!(guard.decode_request(&data), Verdict::Unauthorized);
    }

    #[test]
    fn an_unfinished_request_is_told_apart_from_a_broken_one() {
        let guard = guard();
        let data = request(&guard, b"hello");
        assert_eq!(guard.decode_request(&data[..40]), Verdict::NeedMore);
        let mut broken = data.clone();
        broken[0] = b'z';
        assert_eq!(guard.decode_request(&broken), Verdict::Malformed);
    }

    #[test]
    fn an_address_it_cannot_write_is_refused_before_anything_is_sealed() {
        assert!(matches!(
            guard().encode_request("no such host", 443, b""),
            Err(TransportError::TrojanAddress(_))
        ));
    }

    #[test]
    fn probing_looks_no_further_than_the_hash_field() {
        let guard = guard();
        assert_eq!(guard.probe(&request(&guard, b"")), Probe::Trojan);
        assert_eq!(guard.probe(b"GET / HTTP/1.1\r\n"), Probe::NotTrojan);
        assert_eq!(guard.probe(b"abcdef"), Probe::NeedMore);
    }

    #[test]
    fn a_rotation_forgets_the_password_before_the_previous_one() {
        let mut rotated = Trojan::new(b"newpass", b"testpass");
        rotated.reload(b"newest", b"newpass");
        assert_eq!(
            rotated.decode_request(&request(&guard(), b"x")),
            Verdict::Unauthorized
        );
    }
}
