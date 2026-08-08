use crate::parse::step::Step;
use crate::socks::address::Address;

pub const PORT_LEN: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub address: Address,
    pub port: u16,
}

impl Destination {
    pub fn new(address: Address, port: u16) -> Self {
        Destination { address, port }
    }

    pub fn resolve(host: &str, port: u16) -> Option<Self> {
        Some(Destination::new(Address::resolve(host)?, port))
    }

    pub fn parse(data: &[u8]) -> Step<Self> {
        let (address, consumed) = match Address::parse(data) {
            Step::Parsed { value, consumed } => (value, consumed),
            Step::NeedMore => return Step::NeedMore,
            Step::Malformed => return Step::Malformed,
        };
        if data.len() < consumed + PORT_LEN {
            return Step::NeedMore;
        }
        let port = u16::from_be_bytes([data[consumed], data[consumed + 1]]);
        Step::parsed(Destination::new(address, port), consumed + PORT_LEN)
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        out.extend_from_slice(&self.port.to_be_bytes());
    }

    pub fn host(&self) -> String {
        self.address.host()
    }
}

#[cfg(test)]
mod tests {
    use super::Destination;
    use crate::parse::step::Step;

    fn encoded(destination: &Destination) -> Vec<u8> {
        let mut out = Vec::new();
        destination.encode(&mut out);
        out
    }

    #[test]
    fn the_port_travels_big_endian_after_the_address() {
        let destination = Destination::resolve("13.10.1.2", 443).unwrap();
        assert_eq!(encoded(&destination), vec![0x01, 13, 10, 1, 2, 0x01, 0xBB]);
    }

    #[test]
    fn a_port_that_encodes_to_crlf_is_still_just_a_port() {
        let destination = Destination::resolve("www.example.com", 3338).unwrap();
        let bytes = encoded(&destination);
        assert_eq!(&bytes[bytes.len() - 2..], b"\r\n");
        assert_eq!(
            Destination::parse(&bytes),
            Step::parsed(destination, bytes.len())
        );
    }

    #[test]
    fn an_address_whose_bytes_contain_crlf_survives_the_round_trip() {
        let destination = Destination::resolve("13.10.13.10", 80).unwrap();
        let bytes = encoded(&destination);
        assert_eq!(&bytes[1..5], b"\r\n\r\n");
        assert_eq!(
            Destination::parse(&bytes),
            Step::parsed(destination, bytes.len())
        );
    }

    #[test]
    fn a_missing_port_asks_for_more() {
        let bytes = encoded(&Destination::resolve("13.10.1.2", 443).unwrap());
        assert!(Destination::parse(&bytes[..bytes.len() - 1]).needs_more());
        assert!(Destination::parse(&bytes[..bytes.len() - 2]).needs_more());
    }

    #[test]
    fn a_broken_address_stays_broken_with_a_port_behind_it() {
        assert!(Destination::parse(&[0x02, 0x00, 0x00, 0x01, 0xBB]).is_malformed());
    }
}
