use crate::ports::random_source::RandomSource;
use crate::probe::config::ProbeConfig;
use crate::random::sample::memoryless;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Schedule {
    last_run: Option<f64>,
    interval_secs: f64,
}

impl Schedule {
    pub fn new(config: &ProbeConfig, random: &dyn RandomSource) -> Self {
        Schedule {
            last_run: None,
            interval_secs: draw(config, random),
        }
    }

    pub fn record_run(&mut self, now: f64, config: &ProbeConfig, random: &dyn RandomSource) {
        self.last_run = Some(now);
        self.interval_secs = draw(config, random);
    }

    pub fn due(&self, now: f64) -> bool {
        match self.last_run {
            None => true,
            Some(last) => now - last > self.interval_secs,
        }
    }

    pub fn interval_secs(&self) -> f64 {
        self.interval_secs
    }

    pub fn last_run(&self) -> Option<f64> {
        self.last_run
    }
}

fn draw(config: &ProbeConfig, random: &dyn RandomSource) -> f64 {
    memoryless::delay(
        config.base_interval_secs,
        config.jitter_low,
        config.jitter_high,
        random,
    )
}

#[cfg(test)]
mod tests {
    use super::Schedule;
    use crate::probe::config::ProbeConfig;
    use crate::random::os_random::OsRandom;

    #[test]
    fn a_run_that_never_happened_is_always_due() {
        let schedule = Schedule::new(&ProbeConfig::default(), &OsRandom::new());
        assert!(schedule.due(0.0));
        assert!(schedule.due(1_000_000.0));
    }

    #[test]
    fn a_run_that_just_happened_is_not_due_again() {
        let config = ProbeConfig::default();
        let random = OsRandom::new();
        let mut schedule = Schedule::new(&config, &random);
        schedule.record_run(1000.0, &config, &random);
        let interval = schedule.interval_secs();
        assert!(!schedule.due(1000.0));
        assert!(!schedule.due(1000.0 + interval * 0.5));
        assert!(schedule.due(1000.0 + interval * 2.0));
    }

    #[test]
    fn every_run_draws_its_own_wait() {
        let config = ProbeConfig::default();
        let random = OsRandom::new();
        let mut schedule = Schedule::new(&config, &random);
        let mut drawn = Vec::new();
        for tick in 0..50 {
            schedule.record_run(tick as f64, &config, &random);
            drawn.push(schedule.interval_secs());
        }
        drawn.sort_by(|left, right| left.partial_cmp(right).unwrap());
        drawn.dedup();
        assert!(drawn.len() > 40, "расписание стало периодическим");
    }

    #[test]
    fn the_wait_stays_inside_the_bounds_the_configuration_names() {
        let config = ProbeConfig::default();
        let random = OsRandom::new();
        for _ in 0..2000 {
            let schedule = Schedule::new(&config, &random);
            assert!(schedule.interval_secs() >= config.shortest_interval());
            assert!(schedule.interval_secs() <= config.longest_interval());
        }
    }

    #[test]
    fn a_clock_that_went_backwards_does_not_bring_the_next_run_forward() {
        let config = ProbeConfig::default();
        let random = OsRandom::new();
        let mut schedule = Schedule::new(&config, &random);
        schedule.record_run(1000.0, &config, &random);
        assert!(!schedule.due(900.0));
    }
}
