use crate::latency::config::LatencyConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Fine,
    Blocked,
    Degraded,
}

pub fn of(samples: &[f64], config: &LatencyConfig) -> Verdict {
    if is_blocked(samples, config) {
        return Verdict::Blocked;
    }
    if is_degraded(samples, config) {
        return Verdict::Degraded;
    }
    Verdict::Fine
}

fn is_blocked(samples: &[f64], config: &LatencyConfig) -> bool {
    if config.failures_to_block == 0 || samples.len() < config.failures_to_block {
        return false;
    }
    samples[samples.len() - config.failures_to_block..]
        .iter()
        .all(|value| *value <= 0.0)
}

fn is_degraded(samples: &[f64], config: &LatencyConfig) -> bool {
    let Some(latest) = samples.last().copied() else {
        return false;
    };
    if latest <= 0.0 || samples.len() <= config.samples_before_degradation {
        return false;
    }
    let earlier: Vec<f64> = samples[..samples.len() - 1]
        .iter()
        .copied()
        .filter(|value| *value > 0.0)
        .collect();
    if earlier.is_empty() {
        return false;
    }
    let average = earlier.iter().sum::<f64>() / earlier.len() as f64;
    average > 0.0 && latest > average * config.degradation_factor
}

pub fn average_before_last(samples: &[f64]) -> f64 {
    if samples.is_empty() {
        return -1.0;
    }
    let earlier: Vec<f64> = samples[..samples.len() - 1]
        .iter()
        .copied()
        .filter(|value| *value > 0.0)
        .collect();
    if earlier.is_empty() {
        return -1.0;
    }
    (earlier.iter().sum::<f64>() / earlier.len() as f64).round()
}

#[cfg(test)]
mod tests {
    use super::{average_before_last, of, Verdict};
    use crate::latency::config::LatencyConfig;

    fn config() -> LatencyConfig {
        LatencyConfig::default()
    }

    #[test]
    fn three_failures_in_a_row_are_a_block() {
        assert_eq!(of(&[10.0, -1.0, -1.0, -1.0], &config()), Verdict::Blocked);
    }

    #[test]
    fn two_failures_in_a_row_are_not_yet_a_block() {
        assert_eq!(of(&[10.0, -1.0, -1.0], &config()), Verdict::Fine);
    }

    #[test]
    fn a_single_answer_clears_a_run_of_failures() {
        assert_eq!(of(&[-1.0, -1.0, -1.0, 10.0], &config()), Verdict::Fine);
    }

    #[test]
    fn a_latency_far_above_the_usual_one_is_degradation() {
        let samples = [10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 100.0];
        assert_eq!(of(&samples, &config()), Verdict::Degraded);
    }

    #[test]
    fn a_latency_close_to_the_usual_one_is_not_degradation() {
        let samples = [10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 20.0];
        assert_eq!(of(&samples, &config()), Verdict::Fine);
    }

    #[test]
    fn degradation_needs_more_history_than_a_block_does() {
        let samples = [10.0, 10.0, 100.0];
        assert_eq!(of(&samples, &config()), Verdict::Fine);
    }

    #[test]
    fn a_block_is_read_before_a_slowdown() {
        let samples = [10.0, 10.0, 10.0, 10.0, 10.0, -1.0, -1.0, -1.0];
        assert_eq!(of(&samples, &config()), Verdict::Blocked);
    }

    #[test]
    fn a_history_of_only_failures_never_reads_as_degradation() {
        let samples = [-1.0, -1.0, -1.0, -1.0, -1.0, -1.0, 100.0];
        assert_eq!(of(&samples, &config()), Verdict::Fine);
    }

    #[test]
    fn the_average_the_alert_reports_leaves_out_the_sample_that_raised_it() {
        assert_eq!(average_before_last(&[10.0, 20.0, 900.0]), 15.0);
        assert_eq!(average_before_last(&[-1.0, 900.0]), -1.0);
        assert_eq!(average_before_last(&[]), -1.0);
    }
}
