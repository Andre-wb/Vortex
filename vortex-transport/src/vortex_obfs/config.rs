pub const DEFAULT_MIN_PADDING: usize = 64;
pub const DEFAULT_MAX_PADDING: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VortexObfsConfig {
    pub min_padding: usize,
    pub max_padding: usize,
}

impl Default for VortexObfsConfig {
    fn default() -> Self {
        VortexObfsConfig {
            min_padding: DEFAULT_MIN_PADDING,
            max_padding: DEFAULT_MAX_PADDING,
        }
    }
}

impl VortexObfsConfig {
    pub fn new(min_padding: usize, max_padding: usize) -> Self {
        VortexObfsConfig {
            min_padding,
            max_padding,
        }
    }

    pub fn is_usable(&self) -> bool {
        self.min_padding <= self.max_padding
    }
}

#[cfg(test)]
mod tests {
    use super::{VortexObfsConfig, DEFAULT_MAX_PADDING, DEFAULT_MIN_PADDING};

    #[test]
    fn the_default_padding_hides_the_length_of_a_short_message() {
        let config = VortexObfsConfig::default();
        assert_eq!(config.min_padding, DEFAULT_MIN_PADDING);
        assert_eq!(config.max_padding, DEFAULT_MAX_PADDING);
        assert!(config.is_usable());
    }

    #[test]
    fn an_interval_that_is_not_an_interval_is_not_usable() {
        assert!(!VortexObfsConfig::new(512, 64).is_usable());
    }
}
