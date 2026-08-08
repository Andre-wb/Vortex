use crate::timeout::config::TimeoutConfig;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadBudget {
    started_at: f64,
    seconds: f64,
}

impl ReadBudget {
    pub fn start(now: f64, seconds: f64) -> Self {
        ReadBudget {
            started_at: now,
            seconds,
        }
    }

    pub fn handshake(now: f64, config: &TimeoutConfig) -> Self {
        ReadBudget::start(now, config.handshake_secs)
    }

    pub fn seconds(&self) -> f64 {
        self.seconds
    }

    pub fn remaining(&self, now: f64) -> f64 {
        if !self.seconds.is_finite() || self.seconds <= 0.0 || !now.is_finite() {
            return 0.0;
        }
        let spent = now - self.started_at;
        if !spent.is_finite() || spent <= 0.0 {
            return self.seconds;
        }
        (self.seconds - spent).max(0.0)
    }

    pub fn expired(&self, now: f64) -> bool {
        self.remaining(now) <= 0.0
    }
}

#[cfg(test)]
mod tests {
    use super::ReadBudget;
    use crate::timeout::config::TimeoutConfig;

    #[test]
    fn a_fresh_budget_is_the_whole_budget() {
        let budget = ReadBudget::start(100.0, 10.0);
        assert_eq!(budget.remaining(100.0), 10.0);
        assert_eq!(budget.seconds(), 10.0);
        assert!(!budget.expired(100.0));
    }

    #[test]
    fn what_was_spent_is_gone() {
        let budget = ReadBudget::start(100.0, 10.0);
        assert_eq!(budget.remaining(103.0), 7.0);
        assert_eq!(budget.remaining(109.5), 0.5);
    }

    #[test]
    fn a_spent_budget_is_expired_and_never_goes_negative() {
        let budget = ReadBudget::start(100.0, 10.0);
        assert_eq!(budget.remaining(110.0), 0.0);
        assert_eq!(budget.remaining(1000.0), 0.0);
        assert!(budget.expired(110.0));
        assert!(budget.expired(1000.0));
    }

    #[test]
    fn a_clock_that_went_backwards_does_not_hand_out_extra_time() {
        let budget = ReadBudget::start(100.0, 10.0);
        assert_eq!(budget.remaining(90.0), 10.0);
        assert!(!budget.expired(90.0));
    }

    #[test]
    fn a_budget_that_is_not_a_budget_is_spent_from_the_start() {
        for seconds in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let budget = ReadBudget::start(100.0, seconds);
            assert_eq!(budget.remaining(100.0), 0.0, "{seconds}");
            assert!(budget.expired(100.0), "{seconds}");
        }
    }

    #[test]
    fn a_clock_that_is_not_a_clock_leaves_no_time() {
        let budget = ReadBudget::start(100.0, 10.0);
        assert_eq!(budget.remaining(f64::NAN), 0.0);
        assert!(budget.expired(f64::NAN));
    }

    #[test]
    fn the_handshake_budget_is_the_one_the_configuration_names() {
        let config = TimeoutConfig::default();
        let budget = ReadBudget::handshake(0.0, &config);
        assert_eq!(budget.seconds(), config.handshake_secs);
        assert!(!budget.expired(config.handshake_secs - 0.1));
        assert!(budget.expired(config.handshake_secs));
    }
}
