pub const CAPACITY: usize = 10_000;
pub const LIFETIME_SECONDS: f64 = 300.0;

#[cfg(test)]
mod tests {
    use super::{CAPACITY, LIFETIME_SECONDS};

    #[test]
    fn ten_thousand_identifiers_are_remembered_for_five_minutes() {
        assert_eq!(CAPACITY, 10_000);
        assert_eq!(LIFETIME_SECONDS, 5.0 * 60.0);
    }
}
