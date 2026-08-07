use std::sync::Arc;

use crate::config::rate::RateConfig;
use crate::ports::clock::Clock;
use crate::ports::rate_limiter::RateLimiter;
use crate::time::manual_clock::ManualClock;

pub const NOW: f64 = 1_700_000_000.0;

pub type LimiterFactory = dyn Fn(Arc<dyn Clock>, RateConfig) -> Arc<dyn RateLimiter>;

struct Subject {
    limiter: Arc<dyn RateLimiter>,
    clock: Arc<ManualClock>,
}

fn subject(make: &LimiterFactory, config: RateConfig) -> Subject {
    let clock = Arc::new(ManualClock::at(NOW));
    Subject {
        limiter: make(clock.clone(), config),
        clock,
    }
}

pub fn check_all(make: &LimiterFactory) {
    requests_under_the_limit_are_allowed(make);
    the_request_after_the_limit_is_refused(make);
    one_noisy_client_does_not_silence_another(make);
    the_window_slides_forward_with_the_clock(make);
    two_classes_of_traffic_keep_separate_windows(make);
}

pub fn requests_under_the_limit_are_allowed(make: &LimiterFactory) {
    let subject = subject(make, RateConfig::default());
    for _ in 0..10 {
        assert!(subject.limiter.allow("1.2.3.4", 10));
    }
}

pub fn the_request_after_the_limit_is_refused(make: &LimiterFactory) {
    let subject = subject(make, RateConfig::default());
    for _ in 0..3 {
        assert!(subject.limiter.allow("1.2.3.5", 3));
    }
    assert!(!subject.limiter.allow("1.2.3.5", 3));
}

pub fn one_noisy_client_does_not_silence_another(make: &LimiterFactory) {
    let subject = subject(make, RateConfig::default());
    for _ in 0..3 {
        subject.limiter.allow("1.1.1.1", 3);
    }
    assert!(!subject.limiter.allow("1.1.1.1", 3));
    assert!(subject.limiter.allow("2.2.2.2", 3));
}

pub fn the_window_slides_forward_with_the_clock(make: &LimiterFactory) {
    let subject = subject(make, RateConfig::default());
    for _ in 0..3 {
        subject.limiter.allow("3.3.3.3", 3);
    }
    subject.clock.advance(59.0);
    assert!(!subject.limiter.allow("3.3.3.3", 3));
    subject.clock.advance(1.0);
    assert!(subject.limiter.allow("3.3.3.3", 3));
}

pub fn two_classes_of_traffic_keep_separate_windows(make: &LimiterFactory) {
    let subject = subject(make, RateConfig::default());
    for _ in 0..2 {
        subject.limiter.allow("std:4.4.4.4", 2);
    }
    assert!(!subject.limiter.allow("std:4.4.4.4", 2));
    assert!(subject.limiter.allow("fast:4.4.4.4", 2));
}
