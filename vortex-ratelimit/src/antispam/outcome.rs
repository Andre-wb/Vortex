#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamOutcome {
    Clean,
    Spam,
    Unavailable,
}

impl SpamOutcome {
    pub fn blocks(self) -> bool {
        !matches!(self, SpamOutcome::Clean)
    }

    pub fn reason(self) -> &'static str {
        match self {
            SpamOutcome::Clean => "clean",
            SpamOutcome::Spam => "spam",
            SpamOutcome::Unavailable => "unavailable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SpamOutcome;

    #[test]
    fn only_a_clean_message_reaches_the_room() {
        assert!(!SpamOutcome::Clean.blocks());
        assert!(SpamOutcome::Spam.blocks());
    }

    #[test]
    fn a_message_nobody_could_count_is_held_back_rather_than_waved_through() {
        assert!(SpamOutcome::Unavailable.blocks());
    }

    #[test]
    fn every_outcome_names_itself() {
        assert_eq!(SpamOutcome::Clean.reason(), "clean");
        assert_eq!(SpamOutcome::Spam.reason(), "spam");
        assert_eq!(SpamOutcome::Unavailable.reason(), "unavailable");
    }
}
