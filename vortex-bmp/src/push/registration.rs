use crate::push::endpoint::PushEndpoint;
use crate::push::limits;
use crate::push::token::PushToken;

#[derive(Debug, Clone, PartialEq)]
pub struct Registration {
    token: PushToken,
    endpoint: PushEndpoint,
    registered_at: f64,
}

impl Registration {
    pub fn made(token: PushToken, endpoint: PushEndpoint, registered_at: f64) -> Self {
        Registration {
            token,
            endpoint,
            registered_at,
        }
    }

    pub fn token(&self) -> &PushToken {
        &self.token
    }

    pub fn endpoint(&self) -> &PushEndpoint {
        &self.endpoint
    }

    pub fn registered_at(&self) -> f64 {
        self.registered_at
    }

    pub fn stale(&self, now: f64) -> bool {
        now - self.registered_at >= limits::TOKEN_LIFETIME_SECONDS
    }
}

#[cfg(test)]
mod tests {
    use super::Registration;
    use crate::push::endpoint::PushEndpoint;
    use crate::push::limits;
    use crate::push::token::PushToken;

    fn registration(at: f64) -> Registration {
        Registration::made(
            PushToken::parse(r#"{"auth":"abcdef"}"#).unwrap(),
            PushEndpoint::parse("https://push.example/abc").unwrap(),
            at,
        )
    }

    #[test]
    fn a_registration_goes_stale_at_its_lifetime_and_not_before() {
        let made = registration(1000.0);
        assert!(!made.stale(1000.0 + limits::TOKEN_LIFETIME_SECONDS - 0.001));
        assert!(made.stale(1000.0 + limits::TOKEN_LIFETIME_SECONDS));
    }
}
