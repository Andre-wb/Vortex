use crate::ports::random_source::RandomSource;
use crate::random::sample::uniform;
use std::f64::consts::PI;

pub fn standard(random: &dyn RandomSource) -> f64 {
    let first = uniform::unit(random).max(f64::MIN_POSITIVE);
    let second = uniform::unit(random);
    (-2.0 * first.ln()).sqrt() * (2.0 * PI * second).cos()
}

pub fn normal(random: &dyn RandomSource, mean: f64, deviation: f64) -> f64 {
    mean + deviation * standard(random)
}

#[cfg(test)]
mod tests {
    use super::{normal, standard};
    use crate::random::fixed_random::FixedRandom;
    use crate::random::os_random::OsRandom;

    #[test]
    fn a_zero_draw_does_not_take_the_logarithm_of_zero() {
        let random = FixedRandom::new(vec![]).with_filler(0x00);
        assert!(standard(&random).is_finite());
    }

    #[test]
    fn the_mean_and_the_spread_are_the_ones_that_were_asked_for() {
        let random = OsRandom::new();
        let draws: Vec<f64> = (0..20000).map(|_| normal(&random, 128.0, 64.0)).collect();
        let mean = draws.iter().sum::<f64>() / draws.len() as f64;
        let variance = draws.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / draws.len() as f64;
        assert!((mean - 128.0).abs() < 4.0, "среднее уехало: {mean}");
        assert!(
            (variance.sqrt() - 64.0).abs() < 4.0,
            "разброс уехал: {}",
            variance.sqrt()
        );
    }

    #[test]
    fn both_tails_are_reachable() {
        let random = OsRandom::new();
        let draws: Vec<f64> = (0..5000).map(|_| standard(&random)).collect();
        assert!(draws.iter().any(|x| *x > 1.5));
        assert!(draws.iter().any(|x| *x < -1.5));
    }
}
