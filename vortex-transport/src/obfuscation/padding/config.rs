pub const DEFAULT_MIN: usize = 16;
pub const DEFAULT_MAX: usize = 512;
pub const DEFAULT_MEAN: f64 = 128.0;
pub const DEFAULT_DEVIATION: f64 = 64.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PaddingConfig {
    pub min: usize,
    pub max: usize,
    pub mean: f64,
    pub deviation: f64,
}

impl Default for PaddingConfig {
    fn default() -> Self {
        PaddingConfig {
            min: DEFAULT_MIN,
            max: DEFAULT_MAX,
            mean: DEFAULT_MEAN,
            deviation: DEFAULT_DEVIATION,
        }
    }
}

impl PaddingConfig {
    pub fn new(min: usize, max: usize, mean: f64, deviation: f64) -> Self {
        PaddingConfig {
            min,
            max,
            mean,
            deviation,
        }
    }

    pub fn is_usable(&self) -> bool {
        self.min <= self.max && self.deviation > 0.0 && self.mean.is_finite()
    }
}

#[cfg(test)]
mod tests {
    use super::{PaddingConfig, DEFAULT_MAX, DEFAULT_MIN};

    #[test]
    fn the_default_spread_is_the_one_the_padding_was_built_around() {
        let config = PaddingConfig::default();
        assert_eq!((config.min, config.max), (DEFAULT_MIN, DEFAULT_MAX));
        assert!(config.is_usable());
    }

    #[test]
    fn an_interval_that_is_not_an_interval_is_not_usable() {
        assert!(!PaddingConfig::new(512, 16, 128.0, 64.0).is_usable());
        assert!(!PaddingConfig::new(16, 512, 128.0, 0.0).is_usable());
    }

    #[test]
    fn a_single_allowed_size_is_still_usable() {
        assert!(PaddingConfig::new(64, 64, 64.0, 8.0).is_usable());
    }
}
