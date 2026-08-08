pub const DEFAULT_TARGET_KBPS: f64 = 64.0;
pub const DEFAULT_MIN_CHUNK: usize = 64;
pub const DEFAULT_MAX_CHUNK: usize = 4096;
pub const DEFAULT_BURST_CEILING_SECS: f64 = 1.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NormalizerConfig {
    pub target_kbps: f64,
    pub min_chunk: usize,
    pub max_chunk: usize,
    pub burst_ceiling_secs: f64,
}

impl Default for NormalizerConfig {
    fn default() -> Self {
        NormalizerConfig {
            target_kbps: DEFAULT_TARGET_KBPS,
            min_chunk: DEFAULT_MIN_CHUNK,
            max_chunk: DEFAULT_MAX_CHUNK,
            burst_ceiling_secs: DEFAULT_BURST_CEILING_SECS,
        }
    }
}

impl NormalizerConfig {
    pub fn new(target_kbps: f64) -> Self {
        NormalizerConfig {
            target_kbps,
            ..NormalizerConfig::default()
        }
    }

    pub fn bytes_per_second(&self) -> f64 {
        if !self.target_kbps.is_finite() || self.target_kbps <= 0.0 {
            return 0.0;
        }
        self.target_kbps * 1024.0 / 8.0
    }

    pub fn burst_ceiling_bytes(&self) -> f64 {
        self.bytes_per_second() * self.burst_ceiling_secs.max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{NormalizerConfig, DEFAULT_TARGET_KBPS};

    #[test]
    fn the_target_is_read_as_kibibits_per_second() {
        let config = NormalizerConfig::default();
        assert_eq!(config.target_kbps, DEFAULT_TARGET_KBPS);
        assert_eq!(config.bytes_per_second(), 8192.0);
    }

    #[test]
    fn a_target_that_means_nothing_asks_for_no_traffic() {
        assert_eq!(NormalizerConfig::new(0.0).bytes_per_second(), 0.0);
        assert_eq!(NormalizerConfig::new(-1.0).bytes_per_second(), 0.0);
        assert_eq!(NormalizerConfig::new(f64::NAN).bytes_per_second(), 0.0);
    }

    #[test]
    fn the_burst_ceiling_is_one_second_of_the_target() {
        assert_eq!(NormalizerConfig::default().burst_ceiling_bytes(), 8192.0);
    }
}
