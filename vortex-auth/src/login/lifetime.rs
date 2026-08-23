use crate::token::ttl::Ttl;

pub const ACCOUNT_SECONDS: u64 = 60;
pub const QR_SECONDS: u64 = 300;

pub fn account_ttl() -> Ttl {
    Ttl::seconds(ACCOUNT_SECONDS).expect("время жизни челленджа входа задано ненулевым")
}

pub fn qr_ttl() -> Ttl {
    Ttl::seconds(QR_SECONDS).expect("время жизни QR-челленджа задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{account_ttl, qr_ttl, ACCOUNT_SECONDS, QR_SECONDS};

    #[test]
    fn a_challenge_lives_the_minute_the_client_is_given_to_answer() {
        assert_eq!(ACCOUNT_SECONDS, 60);
        assert_eq!(account_ttl().as_seconds(), 60);
    }

    #[test]
    fn a_qr_challenge_lives_as_long_as_the_code_on_the_screen() {
        assert_eq!(QR_SECONDS, 300);
        assert_eq!(qr_ttl().as_seconds(), 300);
    }
}
