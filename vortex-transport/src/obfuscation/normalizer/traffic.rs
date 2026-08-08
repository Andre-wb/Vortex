use crate::obfuscation::normalizer::budget::Budget;
use crate::obfuscation::normalizer::config::NormalizerConfig;

#[derive(Debug, Clone)]
pub struct TrafficNormalizer {
    config: NormalizerConfig,
    budget: Budget,
}

impl TrafficNormalizer {
    pub fn new(config: NormalizerConfig) -> Self {
        let budget = Budget::new(config.bytes_per_second(), config.burst_ceiling_bytes());
        TrafficNormalizer { config, budget }
    }

    pub fn record_sent(&mut self, now: f64, bytes: usize) {
        self.budget.advance(now);
        self.budget.spend(bytes);
    }

    pub fn padding_needed(&mut self, now: f64) -> usize {
        self.budget.advance(now);
        let owed = self.budget.owed();
        if owed < self.config.min_chunk as f64 {
            return 0;
        }
        (owed as usize).min(self.config.max_chunk)
    }

    pub fn config(&self) -> &NormalizerConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::TrafficNormalizer;
    use crate::obfuscation::normalizer::config::NormalizerConfig;

    fn normalizer() -> TrafficNormalizer {
        TrafficNormalizer::new(NormalizerConfig::default())
    }

    #[test]
    fn the_first_look_at_the_clock_asks_for_nothing() {
        let mut normalizer = normalizer();
        assert_eq!(normalizer.padding_needed(100.0), 0);
    }

    #[test]
    fn a_silent_second_is_filled_up_to_the_target() {
        let mut normalizer = normalizer();
        normalizer.padding_needed(100.0);
        assert_eq!(normalizer.padding_needed(101.0), 4096);
    }

    #[test]
    fn real_traffic_takes_the_place_of_padding() {
        let mut normalizer = normalizer();
        normalizer.padding_needed(100.0);
        normalizer.record_sent(100.5, 4096);
        assert_eq!(normalizer.padding_needed(100.5), 0);
    }

    #[test]
    fn the_second_boundary_is_not_a_moment_of_its_own() {
        let mut inside = normalizer();
        inside.padding_needed(100.4);
        let inside_step = inside.padding_needed(100.5);
        let mut across = normalizer();
        across.padding_needed(100.95);
        let across_step = across.padding_needed(101.05);
        assert!(
            inside_step.abs_diff(across_step) <= 1,
            "на границе секунды нормализатор просит другое: {inside_step} против {across_step}"
        );
    }

    #[test]
    fn a_debt_smaller_than_the_floor_is_not_worth_a_packet() {
        let mut normalizer = normalizer();
        normalizer.padding_needed(100.0);
        assert_eq!(normalizer.padding_needed(100.001), 0);
    }

    #[test]
    fn one_burst_never_exceeds_the_ceiling_on_a_single_write() {
        let mut normalizer = normalizer();
        normalizer.padding_needed(100.0);
        assert_eq!(normalizer.padding_needed(400.0), 4096);
    }

    #[test]
    fn asking_twice_at_the_same_moment_asks_for_the_same_thing() {
        let mut normalizer = normalizer();
        normalizer.padding_needed(100.0);
        let first = normalizer.padding_needed(101.0);
        assert_eq!(normalizer.padding_needed(101.0), first);
    }

    #[test]
    fn padding_that_was_actually_sent_is_counted_as_traffic() {
        let mut normalizer = normalizer();
        normalizer.padding_needed(100.0);
        let first = normalizer.padding_needed(101.0);
        normalizer.record_sent(101.0, first);
        let second = normalizer.padding_needed(101.0);
        normalizer.record_sent(101.0, second);
        assert_eq!(normalizer.padding_needed(101.0), 0);
    }

    #[test]
    fn a_target_of_nothing_never_asks_for_padding() {
        let mut normalizer = TrafficNormalizer::new(NormalizerConfig::new(0.0));
        normalizer.padding_needed(100.0);
        assert_eq!(normalizer.padding_needed(200.0), 0);
    }
}
