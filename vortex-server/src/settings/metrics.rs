use crate::settings::environment;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetricsToken {
    secret: String,
}

impl MetricsToken {
    pub fn new(secret: impl Into<String>) -> Self {
        MetricsToken {
            secret: secret.into().trim().to_string(),
        }
    }

    pub fn from_environment() -> Self {
        MetricsToken::new(environment::text_or("METRICS_TOKEN", ""))
    }

    pub fn configured(&self) -> bool {
        !self.secret.is_empty()
    }

    pub fn matches(&self, presented: &str) -> bool {
        self.configured() && constant_time_equals(self.secret.as_bytes(), presented.as_bytes())
    }
}

fn constant_time_equals(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::MetricsToken;

    #[test]
    fn an_unset_token_never_authorizes_anyone() {
        let token = MetricsToken::new("  ");
        assert!(!token.configured());
        assert!(!token.matches(""));
    }

    #[test]
    fn only_the_exact_secret_matches() {
        let token = MetricsToken::new("s3cret");
        assert!(token.matches("s3cret"));
        assert!(!token.matches("s3cre"));
        assert!(!token.matches("s3cret "));
    }
}
