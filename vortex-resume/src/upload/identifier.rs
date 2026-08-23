use crate::upload::limits;
use crate::upload::refusal::Refusal;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UploadId(String);

impl UploadId {
    pub fn parse(value: &str) -> Result<Self, Refusal> {
        if value.is_empty() {
            return Err(Refusal::EmptyIdentifier);
        }
        if value.len() > limits::MAX_IDENTIFIER_LENGTH {
            return Err(Refusal::OverLongIdentifier);
        }
        if !value.bytes().all(is_url_safe) {
            return Err(Refusal::IdentifierOutsideAlphabet);
        }
        Ok(UploadId(value.to_owned()))
    }

    pub fn written(&self) -> &str {
        &self.0
    }
}

fn is_url_safe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::UploadId;
    use crate::upload::refusal::Refusal;

    #[test]
    fn a_url_safe_token_names_a_upload() {
        assert_eq!(UploadId::parse("aB9-_x").unwrap().written(), "aB9-_x");
    }

    #[test]
    fn an_empty_token_names_no_upload() {
        assert_eq!(UploadId::parse(""), Err(Refusal::EmptyIdentifier));
    }

    #[test]
    fn a_token_outside_the_alphabet_is_refused() {
        assert_eq!(
            UploadId::parse("has space"),
            Err(Refusal::IdentifierOutsideAlphabet)
        );
        assert_eq!(
            UploadId::parse("colon:inside"),
            Err(Refusal::IdentifierOutsideAlphabet)
        );
    }

    #[test]
    fn an_over_long_token_is_refused() {
        assert_eq!(
            UploadId::parse(&"a".repeat(65)),
            Err(Refusal::OverLongIdentifier)
        );
    }
}
