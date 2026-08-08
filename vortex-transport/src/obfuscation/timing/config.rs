pub const DEFAULT_RATE: f64 = 20.0;
pub const DEFAULT_CEILING: f64 = 0.3;
pub const DEFAULT_FLOOR: f64 = 0.005;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DelayConfig {
    pub rate: f64,
    pub ceiling: f64,
    pub floor: f64,
}

impl Default for DelayConfig {
    fn default() -> Self {
        DelayConfig {
            rate: DEFAULT_RATE,
            ceiling: DEFAULT_CEILING,
            floor: DEFAULT_FLOOR,
        }
    }
}

impl DelayConfig {
    pub fn new(rate: f64, ceiling: f64, floor: f64) -> Self {
        DelayConfig {
            rate,
            ceiling,
            floor,
        }
    }

    pub fn is_usable(&self) -> bool {
        self.rate > 0.0 && self.ceiling > 0.0 && self.ceiling.is_finite()
    }
}

#[cfg(test)]
mod tests {
    use super::{DelayConfig, DEFAULT_CEILING, DEFAULT_RATE};

    #[test]
    fn the_default_wait_averages_fifty_milliseconds_and_stops_at_three_hundred() {
        let config = DelayConfig::default();
        assert_eq!(1.0 / config.rate, 1.0 / DEFAULT_RATE);
        assert_eq!(config.ceiling, DEFAULT_CEILING);
        assert!(config.is_usable());
    }

    #[test]
    fn a_rate_or_ceiling_that_means_nothing_is_not_usable() {
        assert!(!DelayConfig::new(0.0, 0.3, 0.005).is_usable());
        assert!(!DelayConfig::new(20.0, 0.0, 0.005).is_usable());
    }
}
