#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloodOutcome {
    Passed,
    Flooding { strikes: u32, earns_a_ban: bool },
}

impl FloodOutcome {
    pub fn flooding(self) -> bool {
        matches!(self, FloodOutcome::Flooding { .. })
    }

    pub fn strikes(self) -> u32 {
        match self {
            FloodOutcome::Passed => 0,
            FloodOutcome::Flooding { strikes, .. } => strikes,
        }
    }

    pub fn earns_a_ban(self) -> bool {
        matches!(
            self,
            FloodOutcome::Flooding {
                earns_a_ban: true,
                ..
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::FloodOutcome;

    #[test]
    fn a_message_within_the_threshold_carries_no_penalty() {
        let outcome = FloodOutcome::Passed;
        assert!(!outcome.flooding());
        assert_eq!(outcome.strikes(), 0);
        assert!(!outcome.earns_a_ban());
    }

    #[test]
    fn a_penalty_carries_its_running_count() {
        let outcome = FloodOutcome::Flooding {
            strikes: 2,
            earns_a_ban: false,
        };
        assert!(outcome.flooding());
        assert_eq!(outcome.strikes(), 2);
        assert!(!outcome.earns_a_ban());
    }

    #[test]
    fn the_penalty_that_earns_a_ban_says_so() {
        let outcome = FloodOutcome::Flooding {
            strikes: 3,
            earns_a_ban: true,
        };
        assert!(outcome.flooding());
        assert!(outcome.earns_a_ban());
    }
}
