use crate::parse::step::Step;
use crate::shadowsocks::request::padding::MAX_PADDING;
use crate::socks::destination::Destination;

pub const PADDING_LEN_LEN: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub destination: Destination,
}

impl RequestHeader {
    pub fn new(destination: Destination) -> Self {
        RequestHeader { destination }
    }

    pub fn resolve(host: &str, port: u16) -> Option<Self> {
        Destination::resolve(host, port).map(RequestHeader::new)
    }

    pub fn encode(&self, padding: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        if padding.len() > MAX_PADDING {
            return None;
        }
        let mut body = Vec::with_capacity(64 + padding.len() + payload.len());
        self.destination.encode(&mut body);
        body.extend_from_slice(&(padding.len() as u16).to_be_bytes());
        body.extend_from_slice(padding);
        body.extend_from_slice(payload);
        Some(body)
    }

    pub fn parse(body: &[u8]) -> Option<(Self, &[u8])> {
        let (destination, consumed) = match Destination::parse(body) {
            Step::Parsed { value, consumed } => (value, consumed),
            Step::NeedMore | Step::Malformed => return None,
        };
        let rest = &body[consumed..];
        if rest.len() < PADDING_LEN_LEN {
            return None;
        }
        let padding_len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        if padding_len > MAX_PADDING {
            return None;
        }
        let payload = rest.get(PADDING_LEN_LEN + padding_len..)?;
        Some((RequestHeader::new(destination), payload))
    }

    pub fn host(&self) -> String {
        self.destination.host()
    }

    pub fn port(&self) -> u16 {
        self.destination.port
    }
}

#[cfg(test)]
mod tests {
    use super::{RequestHeader, PADDING_LEN_LEN};
    use crate::shadowsocks::request::padding::MAX_PADDING;

    fn header() -> RequestHeader {
        RequestHeader::resolve("www.example.com", 9000).unwrap()
    }

    #[test]
    fn the_destination_survives_the_round_trip() {
        let body = header().encode(&[0x00; 64], b"hello").unwrap();
        let (parsed, payload) = RequestHeader::parse(&body).unwrap();
        assert_eq!(parsed, header());
        assert_eq!(parsed.host(), "www.example.com");
        assert_eq!(parsed.port(), 9000);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn every_kind_of_destination_survives_the_round_trip() {
        for (host, port) in [("13.10.1.2", 443), ("2001:db8::1", 80), ("a.example", 1)] {
            let one = RequestHeader::resolve(host, port).unwrap();
            let body = one.encode(&[], b"").unwrap();
            let (parsed, payload) = RequestHeader::parse(&body).unwrap();
            assert_eq!(parsed.host(), host);
            assert_eq!(parsed.port(), port);
            assert!(payload.is_empty());
        }
    }

    #[test]
    fn the_padding_is_not_the_payload() {
        let body = header().encode(&[0xAA; 128], b"tail").unwrap();
        let (_, payload) = RequestHeader::parse(&body).unwrap();
        assert_eq!(payload, b"tail");
        assert!(body.len() > 128 + 4);
    }

    #[test]
    fn a_padded_request_is_never_the_same_length_as_an_unpadded_one() {
        let bare = header().encode(&[], b"hi").unwrap();
        let padded = header().encode(&[0x00; 64], b"hi").unwrap();
        assert_eq!(padded.len(), bare.len() + 64);
    }

    #[test]
    fn a_host_no_client_could_reach_is_refused_at_the_source() {
        assert_eq!(RequestHeader::resolve("he re.com", 80), None);
        assert_eq!(RequestHeader::resolve("", 80), None);
    }

    #[test]
    fn padding_past_the_ceiling_is_refused() {
        assert!(header().encode(&vec![0x00; MAX_PADDING], b"").is_some());
        assert!(header().encode(&vec![0x00; MAX_PADDING + 1], b"").is_none());
    }

    #[test]
    fn a_body_that_stops_before_the_padding_field_is_not_a_request() {
        let body = header().encode(&[0x00; 8], b"").unwrap();
        let cut = body.len() - 8 - PADDING_LEN_LEN;
        assert_eq!(RequestHeader::parse(&body[..cut]), None);
        assert_eq!(RequestHeader::parse(&body[..cut + 1]), None);
    }

    #[test]
    fn a_body_that_promises_more_padding_than_it_carries_is_not_a_request() {
        let mut body = header().encode(&[0x00; 8], b"").unwrap();
        let field = body.len() - 8 - PADDING_LEN_LEN;
        body[field] = 0x00;
        body[field + 1] = 0x09;
        assert_eq!(RequestHeader::parse(&body), None);
    }

    #[test]
    fn a_body_that_promises_padding_past_the_ceiling_is_not_a_request() {
        let mut body = header().encode(&[0x00; 8], b"").unwrap();
        let field = body.len() - 8 - PADDING_LEN_LEN;
        body[field] = 0xFF;
        body[field + 1] = 0xFF;
        assert_eq!(RequestHeader::parse(&body), None);
    }

    #[test]
    fn a_body_that_is_not_a_request_at_all_is_refused() {
        assert_eq!(RequestHeader::parse(b""), None);
        assert_eq!(RequestHeader::parse(&[0x02, 0x00, 0x00, 0x00]), None);
    }
}
