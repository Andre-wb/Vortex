pub const MAX_CREDENTIAL_LEN: usize = 255;

pub const REFUSED_BYTES: [u8; 7] = [b'"', b'\\', b'\'', b'`', b'{', b'}', b'#'];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialText(String);

impl CredentialText {
    pub fn parse(value: &str) -> Option<CredentialText> {
        if value.is_empty() || value.len() > MAX_CREDENTIAL_LEN {
            return None;
        }
        if !value.bytes().all(acceptable) {
            return None;
        }
        Some(CredentialText(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn acceptable(byte: u8) -> bool {
    byte.is_ascii_graphic() && !REFUSED_BYTES.contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::{CredentialText, MAX_CREDENTIAL_LEN};

    #[test]
    fn a_generated_credential_is_accepted() {
        for value in ["a3f9c2b1", "xK-_9Zq", "p4ssw0rd", "a.b~c!d$e%f"] {
            assert!(CredentialText::parse(value).is_some(), "{value}");
        }
    }

    #[test]
    fn a_value_that_means_something_to_the_caddyfile_lexer_is_refused() {
        for value in [
            "pass word",
            "pass\nword",
            "pass\tword",
            "pass\"word",
            "pass\\word",
            "pass'word",
            "pass`word",
            "pass{env.HOME}",
            "pass}",
            "pass#comment",
        ] {
            assert_eq!(CredentialText::parse(value), None, "{value}");
        }
    }

    #[test]
    fn a_directive_smuggled_through_a_newline_never_becomes_a_credential() {
        assert_eq!(
            CredentialText::parse("secret\n    respond \"pwned\"\n"),
            None
        );
    }

    #[test]
    fn a_credential_outside_ascii_is_refused() {
        assert_eq!(CredentialText::parse("пароль"), None);
        assert_eq!(CredentialText::parse("pass\u{7f}word"), None);
        assert_eq!(CredentialText::parse("pass\u{0}word"), None);
    }

    #[test]
    fn an_empty_or_overlong_credential_is_refused() {
        assert_eq!(CredentialText::parse(""), None);
        let long = "a".repeat(MAX_CREDENTIAL_LEN + 1);
        assert_eq!(CredentialText::parse(&long), None);
        assert!(CredentialText::parse(&"a".repeat(MAX_CREDENTIAL_LEN)).is_some());
    }
}
