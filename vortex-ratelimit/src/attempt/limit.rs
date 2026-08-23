#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Limit(u32);

impl Limit {
    pub fn of(value: u32) -> Option<Self> {
        if value == 0 {
            return None;
        }
        Some(Limit(value))
    }

    pub fn value(self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Limit;

    #[test]
    fn a_limit_counts_the_attempts_it_was_given() {
        assert_eq!(Limit::of(10).unwrap().value(), 10);
    }

    #[test]
    fn a_limit_of_zero_would_refuse_everyone_and_does_not_exist() {
        assert!(Limit::of(0).is_none());
        assert!(Limit::of(1).is_some());
    }
}
