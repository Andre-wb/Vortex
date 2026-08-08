use crate::error::{Result, TransportError};
use crate::parse::step::Step;
use crate::socks::destination::Destination;
use crate::trojan::request::command::Command;

pub const CRLF: [u8; 2] = [0x0D, 0x0A];
pub const COMMAND_LEN: usize = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub command: Command,
    pub destination: Destination,
}

impl Header {
    pub fn new(command: Command, destination: Destination) -> Self {
        Header {
            command,
            destination,
        }
    }

    pub fn connect(host: &str, port: u16) -> Result<Self> {
        let destination = Destination::resolve(host, port)
            .ok_or_else(|| TransportError::TrojanAddress(host.to_owned()))?;
        Ok(Header::new(Command::Connect, destination))
    }

    pub fn parse(data: &[u8]) -> Step<Self> {
        let Some(code) = data.first().copied() else {
            return Step::NeedMore;
        };
        let Some(command) = Command::parse(code) else {
            return Step::Malformed;
        };
        let (destination, consumed) = match Destination::parse(&data[COMMAND_LEN..]) {
            Step::Parsed { value, consumed } => (value, consumed + COMMAND_LEN),
            Step::NeedMore => return Step::NeedMore,
            Step::Malformed => return Step::Malformed,
        };
        match data.get(consumed..consumed + CRLF.len()) {
            None => Step::NeedMore,
            Some(tail) if tail == CRLF => {
                Step::parsed(Header::new(command, destination), consumed + CRLF.len())
            }
            Some(_) => Step::Malformed,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.command.code());
        self.destination.encode(out);
        out.extend_from_slice(&CRLF);
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
    use super::{Header, CRLF};
    use crate::parse::step::Step;
    use crate::socks::destination::Destination;
    use crate::trojan::request::command::Command;

    fn encoded(header: &Header) -> Vec<u8> {
        let mut out = Vec::new();
        header.encode(&mut out);
        out
    }

    #[test]
    fn the_header_ends_where_the_format_says_and_not_at_the_first_crlf() {
        let header = Header::connect("13.10.13.10", 3338).unwrap();
        let bytes = encoded(&header);
        assert_eq!(bytes.iter().position(|byte| *byte == CRLF[0]), Some(2));
        assert_eq!(Header::parse(&bytes), Step::parsed(header, bytes.len()));
    }

    #[test]
    fn the_payload_starts_after_the_header_and_nowhere_earlier() {
        let header = Header::connect("13.10.13.10", 3338).unwrap();
        let mut bytes = encoded(&header);
        bytes.extend_from_slice(b"GET / HTTP/1.1\r\n");
        let consumed = match Header::parse(&bytes) {
            Step::Parsed { consumed, .. } => consumed,
            other => panic!("заголовок не разобран: {other:?}"),
        };
        assert_eq!(&bytes[consumed..], b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn a_udp_header_is_a_header_too() {
        let header = Header::new(
            Command::UdpAssociate,
            Destination::resolve("www.example.com", 53).unwrap(),
        );
        let bytes = encoded(&header);
        assert_eq!(Header::parse(&bytes), Step::parsed(header, bytes.len()));
    }

    #[test]
    fn an_unknown_command_is_refused_before_anything_is_read() {
        assert!(Header::parse(&[0x02, 0x01, 13, 10, 1, 2, 0x01, 0xBB, 0x0D, 0x0A]).is_malformed());
    }

    #[test]
    fn a_header_that_does_not_end_in_crlf_is_refused() {
        let mut bytes = encoded(&Header::connect("13.10.1.2", 443).unwrap());
        let last = bytes.len() - 1;
        bytes[last] = 0x00;
        assert!(Header::parse(&bytes).is_malformed());
    }

    #[test]
    fn every_prefix_of_a_header_asks_for_more() {
        let bytes = encoded(&Header::connect("www.example.com", 443).unwrap());
        for cut in 0..bytes.len() {
            assert!(Header::parse(&bytes[..cut]).needs_more(), "срез {cut}");
        }
    }
}
