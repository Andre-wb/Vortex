use crate::ports::random_source::RandomSource;
use crate::random::sample::uniform;

pub const DEFAULT_JITTER_RATIO: f64 = 0.5;

pub fn randomize(base: f64, jitter_ratio: f64, random: &dyn RandomSource) -> f64 {
    if !base.is_finite() || base <= 0.0 || !jitter_ratio.is_finite() || jitter_ratio <= 0.0 {
        return base.max(0.0);
    }
    let low = (base * (1.0 - jitter_ratio)).max(0.0);
    let high = base * (1.0 + jitter_ratio);
    uniform::range(random, low, high)
}

#[cfg(test)]
mod tests {
    use super::randomize;
    use crate::random::os_random::OsRandom;

    #[test]
    fn the_interval_stays_inside_the_asked_for_spread() {
        let random = OsRandom::new();
        for _ in 0..5000 {
            let interval = randomize(30.0, 0.5, &random);
            assert!((15.0..=45.0).contains(&interval));
        }
    }

    #[test]
    fn a_wider_spread_reaches_further_in_both_directions() {
        let random = OsRandom::new();
        let draws: Vec<f64> = (0..5000).map(|_| randomize(30.0, 0.7, &random)).collect();
        assert!(draws.iter().all(|value| (9.0..=51.0).contains(value)));
        assert!(draws.iter().any(|value| *value < 15.0));
        assert!(draws.iter().any(|value| *value > 45.0));
    }

    #[test]
    fn a_spread_wider_than_the_interval_never_asks_to_wait_backwards() {
        let random = OsRandom::new();
        for _ in 0..2000 {
            assert!(randomize(30.0, 2.0, &random) >= 0.0);
        }
    }

    #[test]
    fn an_interval_without_spread_is_left_alone() {
        let random = OsRandom::new();
        assert_eq!(randomize(30.0, 0.0, &random), 30.0);
        assert_eq!(randomize(0.0, 0.5, &random), 0.0);
        assert_eq!(randomize(-5.0, 0.5, &random), 0.0);
    }
}
