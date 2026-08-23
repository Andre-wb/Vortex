use crate::token::ttl::Ttl;

pub const TOKEN_SECONDS: u64 = 300;
pub const REMEMBERED_SECONDS: u64 = TOKEN_SECONDS * 2;

pub fn remembered_ttl() -> Ttl {
    Ttl::seconds(REMEMBERED_SECONDS).expect("память о переданном токене задана ненулевой")
}

#[cfg(test)]
mod tests {
    use super::{remembered_ttl, REMEMBERED_SECONDS, TOKEN_SECONDS};

    #[test]
    fn a_spent_token_is_remembered_twice_as_long_as_it_lives() {
        assert_eq!(TOKEN_SECONDS, 300);
        assert_eq!(REMEMBERED_SECONDS, 600);
        assert_eq!(remembered_ttl().as_seconds(), 600);
    }
}
