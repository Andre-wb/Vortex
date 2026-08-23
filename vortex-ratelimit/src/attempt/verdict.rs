#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    OverTheLimit,
    Unavailable,
}

impl Verdict {
    pub fn allowed(self) -> bool {
        matches!(self, Verdict::Allowed)
    }

    pub fn reason(self) -> &'static str {
        match self {
            Verdict::Allowed => "allowed",
            Verdict::OverTheLimit => "over_the_limit",
            Verdict::Unavailable => "unavailable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Verdict;

    #[test]
    fn only_an_attempt_within_the_window_is_allowed() {
        assert!(Verdict::Allowed.allowed());
        assert!(!Verdict::OverTheLimit.allowed());
    }

    #[test]
    fn an_attempt_nobody_could_count_is_refused_rather_than_waved_through() {
        assert!(!Verdict::Unavailable.allowed());
    }

    #[test]
    fn every_verdict_names_itself() {
        assert_eq!(Verdict::Allowed.reason(), "allowed");
        assert_eq!(Verdict::OverTheLimit.reason(), "over_the_limit");
        assert_eq!(Verdict::Unavailable.reason(), "unavailable");
    }
}
