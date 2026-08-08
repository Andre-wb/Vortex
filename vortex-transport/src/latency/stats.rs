pub const NO_LATENCY: f64 = -1.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stats {
    pub current: f64,
    pub average: f64,
    pub best: f64,
    pub worst: f64,
    pub failures: usize,
    pub total: usize,
}

impl Stats {
    pub fn of(samples: &[f64]) -> Stats {
        let answered: Vec<f64> = samples.iter().copied().filter(is_answer).collect();
        Stats {
            current: samples.last().copied().unwrap_or(NO_LATENCY),
            average: mean(&answered),
            best: answered
                .iter()
                .copied()
                .fold(f64::INFINITY, f64::min)
                .round_or_none(),
            worst: answered
                .iter()
                .copied()
                .fold(f64::NEG_INFINITY, f64::max)
                .round_or_none(),
            failures: samples.iter().filter(|value| !is_answer(value)).count(),
            total: samples.len(),
        }
    }
}

fn is_answer(value: &f64) -> bool {
    *value > 0.0
}

fn mean(answered: &[f64]) -> f64 {
    if answered.is_empty() {
        return NO_LATENCY;
    }
    (answered.iter().sum::<f64>() / answered.len() as f64).round()
}

trait RoundOrNone {
    fn round_or_none(self) -> f64;
}

impl RoundOrNone for f64 {
    fn round_or_none(self) -> f64 {
        if self.is_finite() {
            self.round()
        } else {
            NO_LATENCY
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Stats, NO_LATENCY};

    #[test]
    fn an_empty_history_measures_nothing() {
        let stats = Stats::of(&[]);
        assert_eq!(stats.current, NO_LATENCY);
        assert_eq!(stats.average, NO_LATENCY);
        assert_eq!(stats.best, NO_LATENCY);
        assert_eq!(stats.worst, NO_LATENCY);
        assert_eq!(stats.failures, 0);
        assert_eq!(stats.total, 0);
    }

    #[test]
    fn a_failure_is_counted_but_never_averaged() {
        let stats = Stats::of(&[10.0, -1.0, 30.0]);
        assert_eq!(stats.average, 20.0);
        assert_eq!(stats.best, 10.0);
        assert_eq!(stats.worst, 30.0);
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.total, 3);
    }

    #[test]
    fn the_latest_sample_is_reported_even_when_it_failed() {
        assert_eq!(Stats::of(&[10.0, -1.0]).current, -1.0);
    }

    #[test]
    fn a_history_of_nothing_but_failures_has_no_average() {
        let stats = Stats::of(&[-1.0, -1.0]);
        assert_eq!(stats.average, NO_LATENCY);
        assert_eq!(stats.best, NO_LATENCY);
        assert_eq!(stats.failures, 2);
    }

    #[test]
    fn a_measurement_of_exactly_zero_is_not_an_answer() {
        let stats = Stats::of(&[0.0]);
        assert_eq!(stats.average, NO_LATENCY);
        assert_eq!(stats.failures, 1);
    }
}
