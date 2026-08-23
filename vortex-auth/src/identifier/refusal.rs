use std::fmt;

use crate::identifier::cause::Cause;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifierRefusal {
    label: &'static str,
    cause: Cause,
}

impl IdentifierRefusal {
    pub fn new(label: &'static str, cause: Cause) -> Self {
        IdentifierRefusal { label, cause }
    }

    pub fn label(&self) -> &'static str {
        self.label
    }

    pub fn cause(&self) -> &Cause {
        &self.cause
    }
}

impl fmt::Display for IdentifierRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = self.label;
        match &self.cause {
            Cause::Empty => write!(f, "идентификатор {label} пуст"),
            Cause::TooLong { max, got } => write!(
                f,
                "идентификатор {label} длиннее {max} символов, получено {got}"
            ),
            Cause::NotAllowed => write!(
                f,
                "идентификатор {label} содержит символ вне алфавита A-Z a-z 0-9 - _"
            ),
        }
    }
}

impl std::error::Error for IdentifierRefusal {}

#[cfg(test)]
mod tests {
    use super::IdentifierRefusal;
    use crate::identifier::cause::Cause;

    #[test]
    fn a_refusal_names_the_identifier_it_speaks_about() {
        let refusal = IdentifierRefusal::new("токена", Cause::Empty);
        assert_eq!(refusal.to_string(), "идентификатор токена пуст");
        assert_eq!(refusal.label(), "токена");
        assert_eq!(refusal.cause(), &Cause::Empty);
    }

    #[test]
    fn the_limit_and_the_length_that_broke_it_are_both_told() {
        let refusal = IdentifierRefusal::new("челленджа", Cause::TooLong { max: 128, got: 129 });
        assert_eq!(
            refusal.to_string(),
            "идентификатор челленджа длиннее 128 символов, получено 129"
        );
    }
}
