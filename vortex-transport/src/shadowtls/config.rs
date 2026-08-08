use crate::ports::random_source::RandomSource;

pub const DEFAULT_SWITCH_PADDING_MIN: usize = 128;
pub const DEFAULT_SWITCH_PADDING_MAX: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowTlsConfig {
    pub switch_padding_min: usize,
    pub switch_padding_max: usize,
}

impl Default for ShadowTlsConfig {
    fn default() -> Self {
        ShadowTlsConfig {
            switch_padding_min: DEFAULT_SWITCH_PADDING_MIN,
            switch_padding_max: DEFAULT_SWITCH_PADDING_MAX,
        }
    }
}

impl ShadowTlsConfig {
    pub fn new() -> Self {
        ShadowTlsConfig::default()
    }

    pub fn switch_padding(mut self, min: usize, max: usize) -> Self {
        self.switch_padding_min = min;
        self.switch_padding_max = max.max(min);
        self
    }

    pub fn padding_len(&self, random: &dyn RandomSource) -> usize {
        let span = self
            .switch_padding_max
            .saturating_sub(self.switch_padding_min);
        if span == 0 {
            return self.switch_padding_min;
        }
        let mut pick = [0u8; 2];
        random.fill_bytes(&mut pick);
        self.switch_padding_min + usize::from(u16::from_be_bytes(pick)) % (span + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::{ShadowTlsConfig, DEFAULT_SWITCH_PADDING_MAX, DEFAULT_SWITCH_PADDING_MIN};
    use crate::random::fixed_random::FixedRandom;

    #[test]
    fn a_switch_record_is_never_a_bare_marker() {
        assert_eq!(DEFAULT_SWITCH_PADDING_MIN, 128);
        assert_eq!(DEFAULT_SWITCH_PADDING_MAX, 512);
    }

    #[test]
    fn padding_stays_inside_the_configured_span() {
        let config = ShadowTlsConfig::default();
        for filler in [0x00u8, 0x7F, 0xFF] {
            let random = FixedRandom::new(vec![]).with_filler(filler);
            let len = config.padding_len(&random);
            assert!(len >= config.switch_padding_min);
            assert!(len <= config.switch_padding_max);
        }
    }

    #[test]
    fn a_collapsed_span_asks_the_random_source_for_nothing() {
        let config = ShadowTlsConfig::new().switch_padding(64, 64);
        let random = FixedRandom::new(vec![]).with_filler(0xFF);
        assert_eq!(config.padding_len(&random), 64);
    }

    #[test]
    fn a_max_below_the_min_is_raised_to_it() {
        let config = ShadowTlsConfig::new().switch_padding(200, 10);
        assert_eq!(config.switch_padding_max, 200);
    }
}
