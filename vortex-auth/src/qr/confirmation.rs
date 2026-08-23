#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    Missing,
    AlreadyConfirmed,
    Confirmed,
}

impl Confirmation {
    pub fn outcome(self) -> &'static str {
        match self {
            Confirmation::Missing => "missing",
            Confirmation::AlreadyConfirmed => "already_confirmed",
            Confirmation::Confirmed => "confirmed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Confirmation;

    #[test]
    fn every_outcome_names_itself_for_the_caller() {
        assert_eq!(Confirmation::Missing.outcome(), "missing");
        assert_eq!(
            Confirmation::AlreadyConfirmed.outcome(),
            "already_confirmed"
        );
        assert_eq!(Confirmation::Confirmed.outcome(), "confirmed");
    }
}
