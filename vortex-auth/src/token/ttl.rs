#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ttl(u64);

impl Ttl {
    pub fn seconds(value: u64) -> Option<Self> {
        if value == 0 {
            return None;
        }
        Some(Ttl(value))
    }

    pub fn until(expires_at: f64, now: f64) -> Option<Self> {
        if !expires_at.is_finite() || !now.is_finite() {
            return None;
        }
        let left = (expires_at - now) as i64;
        if left <= 0 {
            return None;
        }
        Some(Ttl(left as u64))
    }

    pub fn as_seconds(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Ttl;

    #[test]
    fn a_lifetime_counts_only_whole_seconds_left() {
        assert_eq!(Ttl::until(1_000.9, 0.0).unwrap().as_seconds(), 1_000);
        assert_eq!(Ttl::until(1_002.0, 1_000.4).unwrap().as_seconds(), 1);
    }

    #[test]
    fn less_than_a_second_left_is_no_lifetime_at_all() {
        assert!(Ttl::until(1_000.0, 999.5).is_none());
    }

    #[test]
    fn a_token_that_already_expired_has_no_lifetime_left() {
        assert!(Ttl::until(1_000.0, 1_000.0).is_none());
        assert!(Ttl::until(999.0, 1_000.0).is_none());
    }

    #[test]
    fn a_lifetime_of_zero_seconds_does_not_exist() {
        assert!(Ttl::seconds(0).is_none());
        assert_eq!(Ttl::seconds(1).unwrap().as_seconds(), 1);
    }

    #[test]
    fn a_lifetime_is_never_derived_from_a_number_that_is_not_one() {
        assert!(Ttl::until(f64::NAN, 0.0).is_none());
        assert!(Ttl::until(f64::INFINITY, 0.0).is_none());
        assert!(Ttl::until(1_000.0, f64::NAN).is_none());
    }
}
