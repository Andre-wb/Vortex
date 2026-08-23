use crate::message::refusal::Refusal;

pub const MAX_LENGTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(String);

impl MessageId {
    pub fn parse(value: &str) -> Result<Self, Refusal> {
        if value.is_empty() {
            return Err(Refusal::Empty);
        }
        if value.len() > MAX_LENGTH {
            return Err(Refusal::TooLong);
        }
        if !value.bytes().all(is_allowed) {
            return Err(Refusal::Unprintable);
        }
        Ok(MessageId(value.to_owned()))
    }

    pub fn written(&self) -> &str {
        &self.0
    }
}

fn is_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
}

#[cfg(test)]
mod tests {
    use super::{MessageId, MAX_LENGTH};
    use crate::message::refusal::Refusal;

    #[test]
    fn an_ordinary_identifier_is_kept_as_written() {
        let id = MessageId::parse("msg-7f.2:a_b").unwrap();
        assert_eq!(id.written(), "msg-7f.2:a_b");
    }

    #[test]
    fn an_empty_identifier_names_no_message() {
        assert_eq!(MessageId::parse(""), Err(Refusal::Empty));
    }

    #[test]
    fn the_length_is_bounded() {
        let long = "a".repeat(MAX_LENGTH);
        assert!(MessageId::parse(&long).is_ok());
        assert_eq!(
            MessageId::parse(&"a".repeat(MAX_LENGTH + 1)),
            Err(Refusal::TooLong)
        );
    }

    #[test]
    fn a_key_separator_cannot_be_smuggled_in() {
        assert_eq!(MessageId::parse("a b"), Err(Refusal::Unprintable));
        assert_eq!(MessageId::parse("a\nb"), Err(Refusal::Unprintable));
        assert_eq!(MessageId::parse("a/b"), Err(Refusal::Unprintable));
    }
}
