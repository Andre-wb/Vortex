use crate::entry::refusal::AddressRefusal;

pub const MAX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientAddress(String);

impl ClientAddress {
    pub fn parse(value: &str) -> Result<Self, AddressRefusal> {
        if value.is_empty() {
            return Err(AddressRefusal::Empty);
        }
        if value.len() > MAX_LEN {
            return Err(AddressRefusal::TooLong {
                max: MAX_LEN,
                got: value.len(),
            });
        }
        if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(AddressRefusal::NotPrintable);
        }
        Ok(ClientAddress(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientAddress, MAX_LEN};
    use crate::entry::refusal::AddressRefusal;

    #[test]
    fn the_four_shapes_a_socket_hands_over_are_all_accepted() {
        for value in [
            "127.0.0.1",
            "fe80::1%lo0",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "unknown",
        ] {
            assert_eq!(ClientAddress::parse(value).unwrap().as_str(), value);
        }
    }

    #[test]
    fn an_empty_address_names_no_client() {
        assert_eq!(ClientAddress::parse(""), Err(AddressRefusal::Empty));
    }

    #[test]
    fn an_address_longer_than_any_literal_is_refused() {
        let long = "a".repeat(MAX_LEN + 1);
        assert_eq!(
            ClientAddress::parse(&long),
            Err(AddressRefusal::TooLong {
                max: MAX_LEN,
                got: MAX_LEN + 1
            })
        );
    }

    #[test]
    fn whitespace_and_control_characters_never_travel_inside_an_address() {
        for hostile in ["10.0.0.1 ", "10.0.0.1\n", "10.0.0.1\u{0}"] {
            assert_eq!(
                ClientAddress::parse(hostile),
                Err(AddressRefusal::NotPrintable)
            );
        }
    }
}
