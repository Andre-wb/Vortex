use crate::error::{BmpError, Result};

pub const MIN_LEN: usize = 16;
pub const MAX_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MailboxId(String);

impl MailboxId {
    pub fn parse(value: &str) -> Result<Self> {
        let length = value.len();
        if !(MIN_LEN..=MAX_LEN).contains(&length) {
            return Err(BmpError::MailboxIdLength {
                min: MIN_LEN,
                max: MAX_LEN,
                got: length,
            });
        }
        if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(BmpError::MailboxIdNotHex);
        }
        Ok(MailboxId(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for MailboxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{MailboxId, MAX_LEN, MIN_LEN};
    use crate::error::BmpError;

    #[test]
    fn a_derived_identifier_is_accepted() {
        let id = MailboxId::parse("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(id.as_str(), "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn the_shortest_and_longest_identifiers_are_accepted() {
        assert!(MailboxId::parse(&"a".repeat(MIN_LEN)).is_ok());
        assert!(MailboxId::parse(&"a".repeat(MAX_LEN)).is_ok());
    }

    #[test]
    fn an_identifier_outside_the_length_range_is_refused() {
        assert_eq!(
            MailboxId::parse(&"a".repeat(MIN_LEN - 1)),
            Err(BmpError::MailboxIdLength {
                min: MIN_LEN,
                max: MAX_LEN,
                got: MIN_LEN - 1
            })
        );
        assert_eq!(
            MailboxId::parse(&"a".repeat(MAX_LEN + 1)),
            Err(BmpError::MailboxIdLength {
                min: MIN_LEN,
                max: MAX_LEN,
                got: MAX_LEN + 1
            })
        );
    }

    #[test]
    fn a_non_hex_identifier_is_refused() {
        assert_eq!(
            MailboxId::parse("../../../etc/passwd0"),
            Err(BmpError::MailboxIdNotHex)
        );
        assert_eq!(
            MailboxId::parse("zzzzzzzzzzzzzzzz"),
            Err(BmpError::MailboxIdNotHex)
        );
    }

    #[test]
    fn a_multibyte_identifier_is_refused_and_measured_in_bytes() {
        assert_eq!(
            MailboxId::parse("ффффффффффффффффф"),
            Err(BmpError::MailboxIdNotHex)
        );
        assert_eq!(
            MailboxId::parse("ффффф"),
            Err(BmpError::MailboxIdLength {
                min: MIN_LEN,
                max: MAX_LEN,
                got: 10
            })
        );
    }

    #[test]
    fn uppercase_and_lowercase_are_different_mailboxes() {
        let lower = MailboxId::parse("abcdef0123456789").unwrap();
        let upper = MailboxId::parse("ABCDEF0123456789").unwrap();
        assert_ne!(lower, upper);
    }
}
