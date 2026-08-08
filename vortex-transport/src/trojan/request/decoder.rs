use crate::parse::step::Step;
use crate::socks::domain_name::MAX_DOMAIN_FIELD_LEN;
use crate::trojan::request::header::{Header, COMMAND_LEN, CRLF};
use crate::trojan::request::incoming::Incoming;
use crate::trojan::request::probe::{self, Probe, HASH_FIELD_LEN};
use crate::trojan::secret::password_hash::{PasswordHash, PASSWORD_HASH_HEX_LEN};

pub const MAX_REQUEST_HEADER_LEN: usize =
    HASH_FIELD_LEN + COMMAND_LEN + 2 + MAX_DOMAIN_FIELD_LEN + 2 + CRLF.len();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    Complete(Incoming),
    NeedMore,
    Malformed,
}

pub fn decode(data: &[u8]) -> Decoded {
    match probe::probe(data) {
        Probe::NotTrojan => return Decoded::Malformed,
        Probe::NeedMore => return Decoded::NeedMore,
        Probe::Trojan => {}
    }
    let Some(hash) = PasswordHash::parse_hex(&data[..PASSWORD_HASH_HEX_LEN]) else {
        return Decoded::Malformed;
    };
    match Header::parse(&data[HASH_FIELD_LEN..]) {
        Step::Parsed { value, consumed } => Decoded::Complete(Incoming::new(
            hash,
            value,
            data[HASH_FIELD_LEN + consumed..].to_vec(),
        )),
        Step::NeedMore => Decoded::NeedMore,
        Step::Malformed => Decoded::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, Decoded, MAX_REQUEST_HEADER_LEN};
    use crate::trojan::request::encoder;
    use crate::trojan::request::header::Header;
    use crate::trojan::secret::password_hash::PasswordHash;

    fn hash() -> PasswordHash {
        PasswordHash::derive(b"testpass").unwrap()
    }

    fn request(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
        encoder::encode(&hash(), &Header::connect(host, port).unwrap(), payload)
    }

    fn complete(data: &[u8]) -> crate::trojan::request::incoming::Incoming {
        match decode(data) {
            Decoded::Complete(incoming) => incoming,
            other => panic!("запрос не разобран: {other:?}"),
        }
    }

    #[test]
    fn a_whole_request_yields_its_destination_and_payload() {
        let incoming = complete(&request("www.example.com", 443, b"GET / HTTP/1.1\r\n"));
        assert_eq!(incoming.hash, hash());
        assert_eq!(incoming.host(), "www.example.com");
        assert_eq!(incoming.port(), 443);
        assert_eq!(incoming.payload, b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn a_port_that_encodes_to_crlf_does_not_move_the_payload() {
        let incoming = complete(&request("www.example.com", 3338, b"payload"));
        assert_eq!(incoming.port(), 3338);
        assert_eq!(incoming.payload, b"payload");
    }

    #[test]
    fn an_address_whose_bytes_are_crlf_does_not_move_the_payload() {
        let incoming = complete(&request("13.10.13.10", 443, b"payload"));
        assert_eq!(incoming.host(), "13.10.13.10");
        assert_eq!(incoming.payload, b"payload");
    }

    #[test]
    fn a_request_without_a_payload_is_complete_all_the_same() {
        let incoming = complete(&request("13.10.1.2", 443, b""));
        assert_eq!(incoming.payload, b"");
    }

    #[test]
    fn every_prefix_of_a_request_asks_for_more() {
        let data = request("www.example.com", 443, b"payload");
        let header_len = data.len() - 7;
        for cut in 0..header_len {
            assert_eq!(decode(&data[..cut]), Decoded::NeedMore, "срез {cut}");
        }
    }

    #[test]
    fn a_prefix_that_stops_before_the_second_crlf_is_not_an_empty_payload() {
        let data = request("www.example.com", 443, b"payload");
        let without_crlf = data.len() - 7 - 2;
        assert_eq!(decode(&data[..without_crlf]), Decoded::NeedMore);
    }

    #[test]
    fn a_request_that_can_never_complete_is_refused_at_once() {
        let mut data = request("www.example.com", 443, b"payload");
        data[0] = b'z';
        assert_eq!(decode(&data), Decoded::Malformed);
    }

    #[test]
    fn nothing_incomplete_is_ever_longer_than_the_biggest_header() {
        let data = request(&"a".repeat(253), 443, b"");
        assert!(data.len() <= MAX_REQUEST_HEADER_LEN);
        assert_eq!(decode(&data[..data.len() - 1]), Decoded::NeedMore);
        for extra in [0usize, 1, 64] {
            let mut padded = data.clone();
            padded.extend(std::iter::repeat_n(b'x', extra));
            assert!(matches!(decode(&padded), Decoded::Complete(_)));
        }
    }
}
