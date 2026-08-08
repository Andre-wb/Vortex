use crate::ports::random_source::RandomSource;
use crate::random::sample::uniform;
use crate::shadowsocks::config::ShadowsocksConfig;

pub const MAX_PADDING: usize = 1024;

pub fn length(config: &ShadowsocksConfig, random: &dyn RandomSource) -> usize {
    if !config.is_usable() {
        return 0;
    }
    let span = (config.max_padding - config.min_padding) as u64 + 1;
    let drawn = config.min_padding + uniform::below(random, span) as usize;
    drawn.min(MAX_PADDING)
}

#[cfg(test)]
mod tests {
    use super::{length, MAX_PADDING};
    use crate::random::os_random::OsRandom;
    use crate::shadowsocks::config::ShadowsocksConfig;

    #[test]
    fn the_length_stays_inside_the_configured_interval() {
        let config = ShadowsocksConfig::default();
        let random = OsRandom::new();
        for _ in 0..200 {
            let drawn = length(&config, &random);
            assert!((config.min_padding..=config.max_padding).contains(&drawn));
        }
    }

    #[test]
    fn two_requests_are_not_padded_alike() {
        let config = ShadowsocksConfig::default();
        let random = OsRandom::new();
        let mut seen: Vec<usize> = (0..200).map(|_| length(&config, &random)).collect();
        seen.sort_unstable();
        seen.dedup();
        assert!(seen.len() > 50, "длина паддинга предсказуема");
    }

    #[test]
    fn an_interval_that_means_nothing_adds_no_padding() {
        let random = OsRandom::new();
        assert_eq!(length(&ShadowsocksConfig::new(512, 64), &random), 0);
    }

    #[test]
    fn no_configuration_can_ask_for_more_than_the_format_allows() {
        let random = OsRandom::new();
        let config = ShadowsocksConfig::new(MAX_PADDING * 4, MAX_PADDING * 8);
        assert_eq!(length(&config, &random), MAX_PADDING);
    }
}
