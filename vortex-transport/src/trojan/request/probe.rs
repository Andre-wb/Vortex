use crate::trojan::request::header::CRLF;
use crate::trojan::secret::password_hash::PASSWORD_HASH_HEX_LEN;

pub const HASH_FIELD_LEN: usize = PASSWORD_HASH_HEX_LEN + 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    Trojan,
    NeedMore,
    NotTrojan,
}

impl Probe {
    pub fn name(self) -> &'static str {
        match self {
            Probe::Trojan => "trojan",
            Probe::NeedMore => "need_more",
            Probe::NotTrojan => "not_trojan",
        }
    }
}

pub fn probe(data: &[u8]) -> Probe {
    let digits = &data[..data.len().min(PASSWORD_HASH_HEX_LEN)];
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return Probe::NotTrojan;
    }
    for (offset, expected) in CRLF.iter().enumerate() {
        match data.get(PASSWORD_HASH_HEX_LEN + offset) {
            None => return Probe::NeedMore,
            Some(byte) if byte == expected => continue,
            Some(_) => return Probe::NotTrojan,
        }
    }
    Probe::Trojan
}

#[cfg(test)]
mod tests {
    use super::{probe, Probe, HASH_FIELD_LEN};
    use crate::trojan::secret::password_hash::PASSWORD_HASH_HEX_LEN;

    fn digits() -> Vec<u8> {
        vec![b'a'; PASSWORD_HASH_HEX_LEN]
    }

    fn field() -> Vec<u8> {
        let mut out = digits();
        out.extend_from_slice(b"\r\n");
        out
    }

    #[test]
    fn a_hash_field_followed_by_crlf_is_a_trojan_prefix() {
        assert_eq!(probe(&field()), Probe::Trojan);
        let mut with_body = field();
        with_body.extend_from_slice(b"anything at all");
        assert_eq!(probe(&with_body), Probe::Trojan);
        assert_eq!(field().len(), HASH_FIELD_LEN);
    }

    #[test]
    fn a_short_read_asks_for_more_instead_of_denying() {
        for cut in 0..HASH_FIELD_LEN {
            assert_eq!(probe(&field()[..cut]), Probe::NeedMore, "срез {cut}");
        }
    }

    #[test]
    fn a_non_hex_byte_settles_it_at_once() {
        let mut broken = field();
        broken[3] = b'z';
        assert_eq!(probe(&broken), Probe::NotTrojan);
        assert_eq!(probe(&broken[..4]), Probe::NotTrojan);
    }

    #[test]
    fn what_python_read_as_hex_is_refused() {
        for prefix in ["0x", "1_", "+4", " 4"] {
            let mut candidate = prefix.as_bytes().to_vec();
            candidate.extend_from_slice(&digits()[prefix.len()..]);
            candidate.extend_from_slice(b"\r\n");
            assert_eq!(candidate.len(), HASH_FIELD_LEN);
            assert_eq!(probe(&candidate), Probe::NotTrojan, "префикс {prefix}");
        }
    }

    #[test]
    fn uppercase_hex_is_still_hex() {
        let mut shouted = vec![b'A'; PASSWORD_HASH_HEX_LEN];
        shouted.extend_from_slice(b"\r\n");
        assert_eq!(probe(&shouted), Probe::Trojan);
    }

    #[test]
    fn a_wrong_separator_settles_it_at_once() {
        let mut broken = field();
        broken[PASSWORD_HASH_HEX_LEN] = b' ';
        assert_eq!(probe(&broken), Probe::NotTrojan);
        assert_eq!(
            probe(&broken[..PASSWORD_HASH_HEX_LEN + 1]),
            Probe::NotTrojan
        );

        let mut half = field();
        half[PASSWORD_HASH_HEX_LEN + 1] = b' ';
        assert_eq!(probe(&half), Probe::NotTrojan);
    }

    #[test]
    fn a_tls_client_hello_is_never_a_trojan_prefix() {
        assert_eq!(probe(&[0x16, 0x03, 0x01, 0x02, 0x00]), Probe::NotTrojan);
    }

    #[test]
    fn every_name_is_stable() {
        assert_eq!(Probe::Trojan.name(), "trojan");
        assert_eq!(Probe::NeedMore.name(), "need_more");
        assert_eq!(Probe::NotTrojan.name(), "not_trojan");
    }
}
