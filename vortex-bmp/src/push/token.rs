use crate::push::limits;
use crate::push::refusal::PushRefusal;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PushToken(String);

impl PushToken {
    pub fn parse(value: &str) -> Result<Self, PushRefusal> {
        if value.chars().count() < limits::MIN_TOKEN_LENGTH {
            return Err(PushRefusal::ShortToken);
        }
        if value.chars().count() > limits::MAX_TOKEN_LENGTH {
            return Err(PushRefusal::OverLongToken);
        }
        if value.chars().any(|c| c.is_control()) {
            return Err(PushRefusal::TokenOutsideAlphabet);
        }
        Ok(PushToken(value.to_owned()))
    }

    pub fn written(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::PushToken;
    use crate::push::refusal::PushRefusal;

    #[test]
    fn a_subscription_document_names_a_token() {
        let value = r#"{"p256dh":"abc","auth":"def"}"#;
        assert_eq!(PushToken::parse(value).unwrap().written(), value);
    }

    #[test]
    fn a_short_token_is_refused() {
        assert_eq!(PushToken::parse("abc"), Err(PushRefusal::ShortToken));
    }

    #[test]
    fn a_token_with_a_line_break_is_refused() {
        assert_eq!(
            PushToken::parse("abcdefghij\nklm"),
            Err(PushRefusal::TokenOutsideAlphabet)
        );
    }
}
