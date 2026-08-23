use crate::token::ttl::Ttl;

pub const SESSION_SECONDS: u64 = 300;

pub fn session_ttl() -> Ttl {
    Ttl::seconds(SESSION_SECONDS).expect("время жизни QR-сессии задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{session_ttl, SESSION_SECONDS};

    #[test]
    fn a_qr_session_lives_as_long_as_the_code_on_the_screen() {
        assert_eq!(SESSION_SECONDS, 300);
        assert_eq!(session_ttl().as_seconds(), 300);
    }
}
