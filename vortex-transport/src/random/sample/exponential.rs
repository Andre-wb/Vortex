use crate::ports::random_source::RandomSource;
use crate::random::sample::uniform;

pub fn sample(random: &dyn RandomSource, rate: f64) -> f64 {
    if rate <= 0.0 {
        return 0.0;
    }
    -(1.0 - uniform::unit(random)).ln() / rate
}

#[cfg(test)]
mod tests {
    use super::sample;
    use crate::random::fixed_random::FixedRandom;
    use crate::random::os_random::OsRandom;

    #[test]
    fn a_zero_draw_is_the_bottom_of_the_distribution() {
        let random = FixedRandom::new(vec![]).with_filler(0x00);
        assert_eq!(sample(&random, 20.0), 0.0);
    }

    #[test]
    fn the_largest_draw_stays_finite() {
        let random = FixedRandom::new(vec![]).with_filler(0xFF);
        assert!(sample(&random, 20.0).is_finite());
    }

    #[test]
    fn a_rate_that_means_nothing_yields_no_wait() {
        let random = OsRandom::new();
        assert_eq!(sample(&random, 0.0), 0.0);
        assert_eq!(sample(&random, -1.0), 0.0);
    }

    #[test]
    fn the_mean_is_the_reciprocal_of_the_rate() {
        let random = OsRandom::new();
        let draws: Vec<f64> = (0..20000).map(|_| sample(&random, 20.0)).collect();
        let mean = draws.iter().sum::<f64>() / draws.len() as f64;
        assert!((mean - 0.05).abs() < 0.005, "среднее уехало: {mean}");
    }
}
