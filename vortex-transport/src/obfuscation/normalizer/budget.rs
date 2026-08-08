#[derive(Debug, Clone, PartialEq)]
pub struct Budget {
    rate: f64,
    ceiling: f64,
    owed: f64,
    observed_at: Option<f64>,
}

impl Budget {
    pub fn new(rate: f64, ceiling: f64) -> Self {
        Budget {
            rate: rate.max(0.0),
            ceiling: ceiling.max(0.0),
            owed: 0.0,
            observed_at: None,
        }
    }

    pub fn advance(&mut self, now: f64) {
        if !now.is_finite() {
            return;
        }
        let elapsed = match self.observed_at {
            Some(previous) => (now - previous).max(0.0),
            None => 0.0,
        };
        self.observed_at = Some(now);
        self.owed = (self.owed + self.rate * elapsed).min(self.ceiling);
    }

    pub fn spend(&mut self, bytes: usize) {
        self.owed = (self.owed - bytes as f64).max(0.0);
    }

    pub fn owed(&self) -> f64 {
        self.owed
    }
}

#[cfg(test)]
mod tests {
    use super::Budget;

    #[test]
    fn nothing_is_owed_before_any_time_has_passed() {
        let mut budget = Budget::new(8192.0, 8192.0);
        budget.advance(100.0);
        assert_eq!(budget.owed(), 0.0);
    }

    #[test]
    fn the_debt_grows_with_the_time_that_passed_and_not_in_steps() {
        let mut budget = Budget::new(8192.0, 100000.0);
        budget.advance(100.0);
        budget.advance(100.25);
        assert_eq!(budget.owed(), 2048.0);
        budget.advance(100.5);
        assert_eq!(budget.owed(), 4096.0);
    }

    #[test]
    fn what_was_really_sent_pays_the_debt_down() {
        let mut budget = Budget::new(8192.0, 100000.0);
        budget.advance(100.0);
        budget.advance(101.0);
        budget.spend(4096);
        assert_eq!(budget.owed(), 4096.0);
    }

    #[test]
    fn sending_more_than_was_owed_does_not_earn_credit_for_later() {
        let mut budget = Budget::new(8192.0, 100000.0);
        budget.advance(100.0);
        budget.advance(101.0);
        budget.spend(1_000_000);
        assert_eq!(budget.owed(), 0.0);
    }

    #[test]
    fn a_long_silence_does_not_turn_into_one_enormous_burst() {
        let mut budget = Budget::new(8192.0, 8192.0);
        budget.advance(100.0);
        budget.advance(1000.0);
        assert_eq!(budget.owed(), 8192.0);
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_owe_anything_extra() {
        let mut budget = Budget::new(8192.0, 100000.0);
        budget.advance(100.0);
        budget.advance(90.0);
        assert_eq!(budget.owed(), 0.0);
        budget.advance(91.0);
        assert_eq!(budget.owed(), 8192.0);
    }

    #[test]
    fn a_time_that_is_not_a_time_is_ignored() {
        let mut budget = Budget::new(8192.0, 100000.0);
        budget.advance(100.0);
        budget.advance(f64::NAN);
        budget.advance(101.0);
        assert_eq!(budget.owed(), 8192.0);
    }
}
