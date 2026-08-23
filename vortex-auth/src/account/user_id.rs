#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(i64);

impl UserId {
    pub fn of(value: i64) -> Option<Self> {
        if value <= 0 {
            return None;
        }
        Some(UserId(value))
    }

    pub fn value(self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::UserId;

    #[test]
    fn an_account_is_named_by_a_positive_number() {
        assert_eq!(UserId::of(7).unwrap().value(), 7);
    }

    #[test]
    fn zero_and_below_name_no_account() {
        assert!(UserId::of(0).is_none());
        assert!(UserId::of(-1).is_none());
    }
}
