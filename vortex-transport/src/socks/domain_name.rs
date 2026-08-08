use crate::tls::server_name::plausible_host;

pub const MAX_DOMAIN_FIELD_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainName(String);

impl DomainName {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_DOMAIN_FIELD_LEN {
            return None;
        }
        plausible_host(bytes).map(|host| DomainName(host.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn length_byte(&self) -> u8 {
        self.0.len() as u8
    }
}

#[cfg(test)]
mod tests {
    use super::{DomainName, MAX_DOMAIN_FIELD_LEN};

    #[test]
    fn a_host_name_keeps_its_bytes() {
        let name = DomainName::parse(b"www.example.com").unwrap();
        assert_eq!(name.as_str(), "www.example.com");
        assert_eq!(name.len(), 15);
        assert!(!name.is_empty());
    }

    #[test]
    fn no_name_that_exists_can_overflow_the_length_byte() {
        let longest = DomainName::parse(&vec![b'a'; MAX_DOMAIN_FIELD_LEN]);
        assert!(longest.is_none());
        let name = DomainName::parse(&vec![b'a'; 253]).unwrap();
        assert_eq!(usize::from(name.length_byte()), name.len());
    }

    #[test]
    fn an_empty_name_is_not_a_name() {
        assert_eq!(DomainName::parse(b""), None);
    }

    #[test]
    fn bytes_a_host_never_carries_are_refused() {
        for candidate in [
            b"a b.com".as_slice(),
            b"a\x00b.com".as_slice(),
            b"a\r\nb.com".as_slice(),
            "звезда.рф".as_bytes(),
        ] {
            assert_eq!(DomainName::parse(candidate), None);
        }
    }
}
