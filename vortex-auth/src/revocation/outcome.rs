#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    Recorded,
    AlreadyExpired,
}

impl Revocation {
    pub fn recorded(self) -> bool {
        matches!(self, Revocation::Recorded)
    }
}

#[cfg(test)]
mod tests {
    use super::Revocation;

    #[test]
    fn only_a_written_revocation_counts_as_recorded() {
        assert!(Revocation::Recorded.recorded());
        assert!(!Revocation::AlreadyExpired.recorded());
    }
}
