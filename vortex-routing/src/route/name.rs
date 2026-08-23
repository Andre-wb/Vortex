use crate::route::refusal::RouteNameRefusal;

pub const MAX_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteName(String);

impl RouteName {
    pub fn parse(value: &str) -> Result<Self, RouteNameRefusal> {
        if value.is_empty() {
            return Err(RouteNameRefusal::Empty);
        }
        if value.len() > MAX_LENGTH {
            return Err(RouteNameRefusal::TooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(RouteNameRefusal::Alphabet);
        }
        Ok(RouteName(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{RouteName, MAX_LENGTH};
    use crate::route::refusal::RouteNameRefusal;

    #[test]
    fn a_name_is_lowercase_digits_and_hyphens() {
        assert!(RouteName::parse("health").is_ok());
        assert!(RouteName::parse("health-ready").is_ok());
        assert_eq!(
            RouteName::parse("Health").err(),
            Some(RouteNameRefusal::Alphabet)
        );
        assert_eq!(
            RouteName::parse("health/ready").err(),
            Some(RouteNameRefusal::Alphabet)
        );
    }

    #[test]
    fn an_empty_or_overlong_name_is_refused() {
        assert_eq!(RouteName::parse("").err(), Some(RouteNameRefusal::Empty));
        assert_eq!(
            RouteName::parse(&"a".repeat(MAX_LENGTH + 1)).err(),
            Some(RouteNameRefusal::TooLong)
        );
    }
}
