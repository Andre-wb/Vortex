use crate::token::ttl::Ttl;

pub const MARKER_SECONDS: u64 = 300;

pub fn marker_ttl() -> Ttl {
    Ttl::seconds(MARKER_SECONDS).expect("время жизни маркера задано ненулевым")
}

#[cfg(test)]
mod tests {
    use super::{marker_ttl, MARKER_SECONDS};

    #[test]
    fn the_marker_lives_the_five_minutes_the_second_step_is_given() {
        assert_eq!(MARKER_SECONDS, 300);
        assert_eq!(marker_ttl().as_seconds(), 300);
    }
}
