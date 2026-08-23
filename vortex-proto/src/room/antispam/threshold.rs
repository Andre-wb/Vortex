pub const ALLOWED_THRESHOLDS: [i64; 3] = [5, 10, 15];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Threshold(i64);

impl Threshold {
    pub fn read(value: i64) -> Option<Self> {
        ALLOWED_THRESHOLDS
            .contains(&value)
            .then_some(Threshold(value))
    }

    pub fn value(&self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Threshold, ALLOWED_THRESHOLDS};

    #[test]
    fn only_the_three_offered_thresholds_are_accepted() {
        for value in ALLOWED_THRESHOLDS {
            assert_eq!(Threshold::read(value).unwrap().value(), value);
        }
    }

    #[test]
    fn a_threshold_that_was_never_offered_is_refused() {
        for value in [0, 1, 4, 6, 11, 20, -5] {
            assert_eq!(Threshold::read(value), None);
        }
    }
}
