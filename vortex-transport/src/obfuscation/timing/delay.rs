use crate::obfuscation::timing::config::DelayConfig;
use crate::ports::random_source::RandomSource;
use crate::random::sample::{exponential, truncated, uniform};

pub fn sample(config: &DelayConfig, random: &dyn RandomSource) -> f64 {
    if !config.is_usable() {
        return 0.0;
    }
    truncated::within(0.0, config.ceiling, || {
        exponential::sample(random, config.rate)
    })
    .unwrap_or_else(|| uniform::range(random, 0.0, config.ceiling))
}

pub fn is_worth_waiting(config: &DelayConfig, delay: f64) -> bool {
    delay > config.floor
}

#[cfg(test)]
mod tests {
    use super::{is_worth_waiting, sample};
    use crate::obfuscation::timing::config::DelayConfig;
    use crate::random::os_random::OsRandom;

    #[test]
    fn the_wait_never_leaves_the_interval() {
        let config = DelayConfig::default();
        let random = OsRandom::new();
        for _ in 0..5000 {
            let delay = sample(&config, &random);
            assert!((0.0..=config.ceiling).contains(&delay));
        }
    }

    #[test]
    fn the_ceiling_does_not_collect_the_tail_that_was_cut_off() {
        let config = DelayConfig::default();
        let random = OsRandom::new();
        let draws: Vec<f64> = (0..20000).map(|_| sample(&config, &random)).collect();
        let at_ceiling = draws
            .iter()
            .filter(|delay| (**delay - config.ceiling).abs() < 1e-9)
            .count();
        assert_eq!(
            at_ceiling, 0,
            "потолок стал отдельным значением, по которому узнают трафик"
        );
    }

    #[test]
    fn the_average_wait_is_the_one_the_configuration_asks_for() {
        let config = DelayConfig::default();
        let random = OsRandom::new();
        let draws: Vec<f64> = (0..20000).map(|_| sample(&config, &random)).collect();
        let mean = draws.iter().sum::<f64>() / draws.len() as f64;
        assert!((mean - 0.05).abs() < 0.005, "среднее уехало: {mean}");
    }

    #[test]
    fn a_configuration_that_means_nothing_asks_for_no_wait() {
        let random = OsRandom::new();
        assert_eq!(sample(&DelayConfig::new(0.0, 0.3, 0.005), &random), 0.0);
    }

    #[test]
    fn a_wait_shorter_than_the_floor_is_not_worth_taking() {
        let config = DelayConfig::default();
        assert!(!is_worth_waiting(&config, 0.001));
        assert!(!is_worth_waiting(&config, config.floor));
        assert!(is_worth_waiting(&config, 0.05));
    }
}
