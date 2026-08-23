pub const ATTEMPTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Swapped {
    Done,
    Changed,
    Missing,
}

impl Swapped {
    pub fn done(self) -> bool {
        self == Swapped::Done
    }

    pub fn worth_retrying(self) -> bool {
        self == Swapped::Changed
    }
}

#[cfg(test)]
mod tests {
    use super::Swapped;

    #[test]
    fn only_a_swap_that_went_through_is_done() {
        assert!(Swapped::Done.done());
        assert!(!Swapped::Changed.done());
        assert!(!Swapped::Missing.done());
    }

    #[test]
    fn a_record_someone_else_changed_is_worth_reading_again() {
        assert!(Swapped::Changed.worth_retrying());
        assert!(!Swapped::Missing.worth_retrying());
        assert!(!Swapped::Done.worth_retrying());
    }
}
