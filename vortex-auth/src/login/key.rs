use std::fmt;

use subtle::ConstantTimeEq;

pub const HEX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginPublicKey(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRefusal {
    WrongLength { expected: usize, got: usize },
    NotHex,
}

impl fmt::Display for KeyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyRefusal::WrongLength { expected, got } => write!(
                f,
                "открытый ключ входа записан не {expected} символами, получено {got}"
            ),
            KeyRefusal::NotHex => write!(f, "открытый ключ входа записан не шестнадцатерично"),
        }
    }
}

impl std::error::Error for KeyRefusal {}

impl LoginPublicKey {
    pub fn parse(value: &str) -> Result<Self, KeyRefusal> {
        if value.len() != HEX_LEN {
            return Err(KeyRefusal::WrongLength {
                expected: HEX_LEN,
                got: value.len(),
            });
        }
        if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(KeyRefusal::NotHex);
        }
        Ok(LoginPublicKey(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn matches(&self, supplied: &str) -> bool {
        if self.0.len() != supplied.len() {
            return false;
        }
        bool::from(self.0.as_bytes().ct_eq(supplied.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyRefusal, LoginPublicKey, HEX_LEN};

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn the_key_a_client_registers_is_accepted_as_written() {
        assert_eq!(LoginPublicKey::parse(KEY).unwrap().as_str(), KEY);
    }

    #[test]
    fn a_key_of_the_wrong_size_is_not_a_key() {
        assert_eq!(
            LoginPublicKey::parse("aabb").unwrap_err(),
            KeyRefusal::WrongLength {
                expected: HEX_LEN,
                got: 4
            }
        );
    }

    #[test]
    fn what_is_not_hex_is_not_a_key() {
        let hostile = "z".repeat(HEX_LEN);
        assert_eq!(
            LoginPublicKey::parse(&hostile).unwrap_err(),
            KeyRefusal::NotHex
        );
    }

    #[test]
    fn a_separator_never_travels_inside_a_key() {
        let hostile = format!("{}:{}", "a".repeat(HEX_LEN - 32), "b".repeat(31));
        assert_eq!(
            LoginPublicKey::parse(&hostile).unwrap_err(),
            KeyRefusal::NotHex
        );
    }

    #[test]
    fn only_the_very_same_key_matches() {
        let key = LoginPublicKey::parse(KEY).unwrap();
        assert!(key.matches(KEY));
        assert!(!key.matches(&KEY.to_uppercase()));
        assert!(!key.matches("aabb"));
    }
}
