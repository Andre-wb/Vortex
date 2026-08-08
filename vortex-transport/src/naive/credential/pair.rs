use crate::error::{Result, TransportError};
use crate::naive::credential::text::CredentialText;

pub const USERNAME_FIELD: &str = "имя пользователя";
pub const PASSWORD_FIELD: &str = "пароль";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: CredentialText,
    pub password: CredentialText,
}

impl Credentials {
    pub fn parse(username: &str, password: &str) -> Result<Credentials> {
        Ok(Credentials {
            username: CredentialText::parse(username)
                .ok_or_else(|| TransportError::NaiveCredential(USERNAME_FIELD.to_owned()))?,
            password: CredentialText::parse(password)
                .ok_or_else(|| TransportError::NaiveCredential(PASSWORD_FIELD.to_owned()))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Credentials, PASSWORD_FIELD, USERNAME_FIELD};
    use crate::error::TransportError;

    #[test]
    fn a_pair_of_generated_credentials_is_accepted() {
        let credentials = Credentials::parse("a3f9c2b1", "xK-_9Zq").unwrap();
        assert_eq!(credentials.username.as_str(), "a3f9c2b1");
        assert_eq!(credentials.password.as_str(), "xK-_9Zq");
    }

    #[test]
    fn the_refused_field_is_named_and_its_value_is_not() {
        assert_eq!(
            Credentials::parse("user name", "s3cret"),
            Err(TransportError::NaiveCredential(USERNAME_FIELD.to_owned()))
        );
        let refusal = Credentials::parse("user", "s3cret}\nrespond").unwrap_err();
        assert_eq!(
            refusal,
            TransportError::NaiveCredential(PASSWORD_FIELD.to_owned())
        );
        assert!(!refusal.to_string().contains("s3cret"));
    }

    #[test]
    fn the_username_is_judged_before_the_password() {
        assert_eq!(
            Credentials::parse("", ""),
            Err(TransportError::NaiveCredential(USERNAME_FIELD.to_owned()))
        );
    }
}
