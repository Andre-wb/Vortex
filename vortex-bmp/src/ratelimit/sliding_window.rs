use std::sync::Arc;

use dashmap::DashMap;

use crate::config::rate::RateConfig;
use crate::ports::clock::Clock;
use crate::ports::rate_limiter::RateLimiter;

pub struct SlidingWindowLimiter {
    windows: DashMap<String, Vec<f64>>,
    clock: Arc<dyn Clock>,
    config: RateConfig,
}

impl SlidingWindowLimiter {
    pub fn new(clock: Arc<dyn Clock>, config: RateConfig) -> Self {
        SlidingWindowLimiter {
            windows: DashMap::new(),
            clock,
            config,
        }
    }
}

impl RateLimiter for SlidingWindowLimiter {
    fn allow(&self, key: &str, limit: u32) -> bool {
        if self.windows.len() >= self.config.max_tracked_keys {
            self.forget_stale();
        }

        let now = self.clock.unix_seconds();
        let mut window = self.windows.entry(key.to_string()).or_default();
        window.retain(|stamp| now - stamp < self.config.window_secs);

        if window.len() >= limit as usize {
            return false;
        }
        window.push(now);
        true
    }

    fn forget_stale(&self) {
        let now = self.clock.unix_seconds();
        self.windows.retain(|_, window| {
            window.retain(|stamp| now - *stamp < self.config.window_secs);
            !window.is_empty()
        });
    }

    fn tracked_keys(&self) -> usize {
        self.windows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::SlidingWindowLimiter;
    use crate::config::rate::RateConfig;
    use crate::ports::rate_limiter::RateLimiter;
    use crate::time::manual_clock::ManualClock;
    use std::sync::Arc;

    const NOW: f64 = 1_700_000_000.0;

    fn limiter_with(config: RateConfig) -> (SlidingWindowLimiter, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::at(NOW));
        (SlidingWindowLimiter::new(clock.clone(), config), clock)
    }

    #[test]
    fn requests_under_the_limit_are_allowed() {
        let (limiter, _) = limiter_with(RateConfig::default());
        for _ in 0..600 {
            assert!(limiter.allow("1.2.3.4", 600));
        }
    }

    #[test]
    fn the_request_after_the_limit_is_refused() {
        let (limiter, _) = limiter_with(RateConfig::default());
        for _ in 0..600 {
            limiter.allow("1.2.3.4", 600);
        }
        assert!(!limiter.allow("1.2.3.4", 600));
    }

    #[test]
    fn one_noisy_client_does_not_silence_another() {
        let (limiter, _) = limiter_with(RateConfig::default());
        for _ in 0..600 {
            limiter.allow("1.1.1.1", 600);
        }
        assert!(!limiter.allow("1.1.1.1", 600));
        assert!(limiter.allow("2.2.2.2", 600));
    }

    #[test]
    fn the_window_slides_forward_with_the_clock() {
        let (limiter, clock) = limiter_with(RateConfig::default());
        for _ in 0..600 {
            limiter.allow("1.2.3.4", 600);
        }
        clock.advance(59.0);
        assert!(!limiter.allow("1.2.3.4", 600));
        clock.advance(1.0);
        assert!(limiter.allow("1.2.3.4", 600));
    }

    #[test]
    fn stale_keys_are_forgotten_instead_of_growing_without_bound() {
        let (limiter, clock) = limiter_with(RateConfig::default());
        for index in 0..100 {
            limiter.allow(&format!("10.0.0.{index}"), 600);
        }
        assert_eq!(limiter.tracked_keys(), 100);
        clock.advance(60.0);
        limiter.forget_stale();
        assert_eq!(limiter.tracked_keys(), 0);
    }

    #[test]
    fn reaching_the_key_ceiling_prunes_instead_of_refusing_the_request() {
        let config = RateConfig::default().max_tracked_keys(4);
        let (limiter, clock) = limiter_with(config);
        for index in 0..4 {
            limiter.allow(&format!("10.0.0.{index}"), 600);
        }
        clock.advance(60.0);
        assert!(limiter.allow("10.0.1.1", 600));
        assert_eq!(limiter.tracked_keys(), 1);
    }
}
