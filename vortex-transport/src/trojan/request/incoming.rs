use crate::trojan::request::header::Header;
use crate::trojan::secret::password_hash::PasswordHash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub hash: PasswordHash,
    pub header: Header,
    pub payload: Vec<u8>,
}

impl Incoming {
    pub fn new(hash: PasswordHash, header: Header, payload: Vec<u8>) -> Self {
        Incoming {
            hash,
            header,
            payload,
        }
    }

    pub fn host(&self) -> String {
        self.header.host()
    }

    pub fn port(&self) -> u16 {
        self.header.port()
    }
}

#[cfg(test)]
mod tests {
    use super::Incoming;
    use crate::trojan::request::header::Header;
    use crate::trojan::secret::password_hash::PasswordHash;

    #[test]
    fn a_request_reports_the_destination_of_its_header() {
        let incoming = Incoming::new(
            PasswordHash::derive(b"testpass").unwrap(),
            Header::connect("www.example.com", 8443).unwrap(),
            b"hello".to_vec(),
        );
        assert_eq!(incoming.host(), "www.example.com");
        assert_eq!(incoming.port(), 8443);
        assert_eq!(incoming.payload, b"hello");
    }
}
