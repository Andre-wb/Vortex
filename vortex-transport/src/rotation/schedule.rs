use crate::ports::random_source::RandomSource;
use crate::random::sample::uniform;

pub const DEFAULT_MIN_INTERVAL: f64 = 300.0;
pub const DEFAULT_MAX_INTERVAL: f64 = 900.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RotationSchedule {
    pub min_interval: f64,
    pub max_interval: f64,
}

impl Default for RotationSchedule {
    fn default() -> Self {
        RotationSchedule {
            min_interval: DEFAULT_MIN_INTERVAL,
            max_interval: DEFAULT_MAX_INTERVAL,
        }
    }
}

impl RotationSchedule {
    pub fn between(low: f64, high: f64) -> Self {
        RotationSchedule {
            min_interval: low,
            max_interval: high,
        }
    }

    pub fn next_wait(&self, random: &dyn RandomSource) -> f64 {
        if !self.min_interval.is_finite() || self.min_interval < 0.0 {
            return 0.0;
        }
        if !self.max_interval.is_finite() || self.max_interval <= self.min_interval {
            return self.min_interval;
        }
        uniform::range(random, self.min_interval, self.max_interval)
    }
}

#[cfg(test)]
mod tests {
    use super::RotationSchedule;
    use crate::random::os_random::OsRandom;

    #[test]
    fn a_key_is_rotated_as_often_as_a_browser_rotates_one() {
        let schedule = RotationSchedule::default();
        let random = OsRandom::new();
        for _ in 0..2000 {
            let waited = schedule.next_wait(&random);
            assert!((300.0..900.0).contains(&waited), "{waited}");
        }
    }

    #[test]
    fn the_wait_is_not_the_same_twice_in_a_row() {
        let schedule = RotationSchedule::default();
        let random = OsRandom::new();
        assert_ne!(schedule.next_wait(&random), schedule.next_wait(&random));
    }

    #[test]
    fn an_interval_that_means_nothing_never_asks_for_a_negative_wait() {
        let random = OsRandom::new();
        assert_eq!(RotationSchedule::between(5.0, 5.0).next_wait(&random), 5.0);
        assert_eq!(RotationSchedule::between(9.0, 2.0).next_wait(&random), 9.0);
        assert_eq!(
            RotationSchedule::between(-1.0, 60.0).next_wait(&random),
            0.0
        );
        assert_eq!(
            RotationSchedule::between(60.0, f64::INFINITY).next_wait(&random),
            60.0
        );
    }
}
