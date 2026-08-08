pub const DEFAULT_MIN_PADDING: usize = 64;
pub const DEFAULT_MAX_PADDING: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowsocksConfig {
    pub min_padding: usize,
    pub max_padding: usize,
}

impl Default for ShadowsocksConfig {
    fn default() -> Self {
        ShadowsocksConfig {
            min_padding: DEFAULT_MIN_PADDING,
            max_padding: DEFAULT_MAX_PADDING,
        }
    }
}

impl ShadowsocksConfig {
    pub fn new(min_padding: usize, max_padding: usize) -> Self {
        ShadowsocksConfig {
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
    use super::{ShadowsocksConfig, DEFAULT_MAX_PADDING, DEFAULT_MIN_PADDING};

    #[test]
    fn the_request_is_padded_by_default_so_that_it_has_no_fixed_size() {
        let config = ShadowsocksConfig::default();
        assert_eq!(config.min_padding, DEFAULT_MIN_PADDING);
        assert_eq!(config.max_padding, DEFAULT_MAX_PADDING);
        assert!(
            config.min_padding > 0,
            "нулевой паддинг вернул бы точный размер"
        );
        assert!(config.is_usable());
    }

    #[test]
    fn an_interval_that_is_not_an_interval_is_not_usable() {
        assert!(!ShadowsocksConfig::new(512, 64).is_usable());
    }
}
