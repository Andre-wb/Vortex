#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    Accepted,
    Replayed,
}

impl Acceptance {
    pub fn accepted(self) -> bool {
        matches!(self, Acceptance::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::Acceptance;

    #[test]
    fn only_the_first_arrival_of_a_token_is_accepted() {
        assert!(Acceptance::Accepted.accepted());
        assert!(!Acceptance::Replayed.accepted());
    }
}
