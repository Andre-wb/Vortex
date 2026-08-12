use crate::ports::random_source::RandomSource;
use crate::random::sample::uniform;

pub const DEFAULT_BURST_SIZE: usize = 8;
pub const DEFAULT_GAP_MAX: f64 = 0.05;
pub const DEFAULT_GAP_MIN: f64 = 0.01;
pub const DEFAULT_PAUSE_MIN: f64 = 2.0;
pub const DEFAULT_PAUSE_MAX: f64 = 15.0;
pub const DEFAULT_GATHER: f64 = 0.3;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BurstPlan {
    pub burst_size: usize,
    pub gap_min: f64,
    pub gap_max: f64,
    pub pause_min: f64,
    pub pause_max: f64,
    pub gather: f64,
}

impl Default for BurstPlan {
    fn default() -> Self {
        BurstPlan {
            burst_size: DEFAULT_BURST_SIZE,
            gap_min: DEFAULT_GAP_MIN,
            gap_max: DEFAULT_GAP_MAX,
            pause_min: DEFAULT_PAUSE_MIN,
            pause_max: DEFAULT_PAUSE_MAX,
            gather: DEFAULT_GATHER,
        }
    }
}

impl BurstPlan {
    pub fn burst_size(mut self, size: usize) -> Self {
        self.burst_size = size;
        self
    }

    pub fn pause_between(mut self, low: f64, high: f64) -> Self {
        self.pause_min = low;
        self.pause_max = high;
        self
    }

    pub fn gap(&self, random: &dyn RandomSource) -> f64 {
        if self.gap_max <= self.gap_min {
            return self.gap_min.max(0.0);
        }
        uniform::range(random, self.gap_min, self.gap_max)
    }

    pub fn pause(&self, random: &dyn RandomSource) -> f64 {
        if self.pause_max <= self.pause_min {
            return self.pause_min.max(0.0);
        }
        uniform::range(random, self.pause_min, self.pause_max)
    }

    pub fn room_left(&self, gathered: usize) -> usize {
        self.burst_size.saturating_sub(gathered)
    }
}

#[cfg(test)]
mod tests {
    use super::BurstPlan;
    use crate::random::os_random::OsRandom;

    #[test]
    fn the_gap_inside_a_burst_is_shorter_than_the_pause_between_bursts() {
        let plan = BurstPlan::default();
        let random = OsRandom::new();
        for _ in 0..500 {
            assert!(plan.gap(&random) < plan.pause(&random));
        }
    }

    #[test]
    fn a_gap_looks_like_the_gap_between_two_requests_of_one_page_load() {
        let plan = BurstPlan::default();
        let random = OsRandom::new();
        for _ in 0..2000 {
            let gap = plan.gap(&random);
            assert!((plan.gap_min..plan.gap_max).contains(&gap), "{gap}");
        }
    }

    #[test]
    fn a_pause_looks_like_someone_reading_the_page_they_loaded() {
        let plan = BurstPlan::default();
        let random = OsRandom::new();
        for _ in 0..2000 {
            let pause = plan.pause(&random);
            assert!((plan.pause_min..plan.pause_max).contains(&pause), "{pause}");
        }
    }

    #[test]
    fn a_burst_stops_gathering_once_it_is_full() {
        let plan = BurstPlan::default().burst_size(8);
        assert_eq!(plan.room_left(0), 8);
        assert_eq!(plan.room_left(7), 1);
        assert_eq!(plan.room_left(8), 0);
        assert_eq!(plan.room_left(99), 0);
    }

    #[test]
    fn an_interval_that_means_nothing_asks_for_its_floor_and_never_for_a_negative_wait() {
        let random = OsRandom::new();
        let flat = BurstPlan::default().pause_between(5.0, 5.0);
        assert_eq!(flat.pause(&random), 5.0);
        let backwards = BurstPlan::default().pause_between(9.0, 2.0);
        assert_eq!(backwards.pause(&random), 9.0);
        let negative = BurstPlan::default().pause_between(-3.0, -9.0);
        assert_eq!(negative.pause(&random), 0.0);
    }
}
