use crate::token::ttl::Ttl;

pub const CHALLENGE_SECONDS: u64 = 300;

pub fn challenge_ttl() -> Ttl {
    Ttl::seconds(CHALLENGE_SECONDS).expect("время жизни челленджа passkey задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{challenge_ttl, CHALLENGE_SECONDS};

    #[test]
    fn the_passkey_challenge_lives_the_five_minutes_the_authenticator_is_given() {
        assert_eq!(CHALLENGE_SECONDS, 300);
        assert_eq!(challenge_ttl().as_seconds(), 300);
    }
}
