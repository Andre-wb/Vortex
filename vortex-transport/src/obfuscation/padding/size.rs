use crate::obfuscation::padding::config::PaddingConfig;
use crate::obfuscation::padding::header::HEADER_LEN;
use crate::ports::random_source::RandomSource;
use crate::random::sample::{gaussian, truncated, uniform};

pub fn choose(config: &PaddingConfig, random: &dyn RandomSource) -> usize {
    if !config.is_usable() {
        return config.min;
    }
    truncated::within(config.min as f64, config.max as f64, || {
        gaussian::normal(random, config.mean, config.deviation).round()
    })
    .map(|drawn| drawn as usize)
    .unwrap_or_else(|| spread_evenly(config, random))
}

pub fn for_target(
    real_len: usize,
    targets: &[usize],
    config: &PaddingConfig,
    random: &dyn RandomSource,
) -> usize {
    let floor = real_len + HEADER_LEN + config.min;
    targets
        .iter()
        .copied()
        .filter(|target| *target >= floor)
        .min()
        .map(|target| target - real_len - HEADER_LEN)
        .unwrap_or_else(|| choose(config, random))
}

fn spread_evenly(config: &PaddingConfig, random: &dyn RandomSource) -> usize {
    let span = (config.max - config.min) as u64 + 1;
    config.min + uniform::below(random, span) as usize
}

#[cfg(test)]
mod tests {
    use super::{choose, for_target};
    use crate::obfuscation::padding::config::PaddingConfig;
    use crate::obfuscation::padding::header::HEADER_LEN;
    use crate::obfuscation::padding::web_sizes::WEB_SIZES;
    use crate::random::os_random::OsRandom;

    #[test]
    fn the_chosen_size_never_leaves_the_configured_interval() {
        let config = PaddingConfig::default();
        let random = OsRandom::new();
        for _ in 0..5000 {
            let size = choose(&config, &random);
            assert!((config.min..=config.max).contains(&size));
        }
    }

    #[test]
    fn neither_bound_collects_the_mass_that_was_rejected() {
        let config = PaddingConfig::default();
        let random = OsRandom::new();
        let draws: Vec<usize> = (0..20000).map(|_| choose(&config, &random)).collect();
        let at_bottom = draws.iter().filter(|size| **size == config.min).count();
        let at_top = draws.iter().filter(|size| **size == config.max).count();
        assert!(
            at_bottom * 200 < draws.len(),
            "нижняя граница собрала выброшенный хвост: {at_bottom}"
        );
        assert!(
            at_top * 200 < draws.len(),
            "верхняя граница собрала выброшенный хвост: {at_top}"
        );
    }

    #[test]
    fn a_configuration_that_cannot_be_drawn_from_falls_back_to_its_floor() {
        let config = PaddingConfig::new(64, 64, 128.0, 0.0);
        let random = OsRandom::new();
        assert_eq!(choose(&config, &random), 64);
    }

    #[test]
    fn a_mean_outside_the_interval_still_yields_a_size_inside_it() {
        let config = PaddingConfig::new(16, 512, 100000.0, 1.0);
        let random = OsRandom::new();
        for _ in 0..200 {
            let size = choose(&config, &random);
            assert!((16..=512).contains(&size));
        }
    }

    #[test]
    fn a_target_size_is_hit_exactly_rather_than_overshot() {
        let config = PaddingConfig::default();
        let random = OsRandom::new();
        for real_len in [1usize, 100, 200, 235, 236, 1000] {
            let pad = for_target(real_len, &WEB_SIZES, &config, &random);
            let total = real_len + HEADER_LEN + pad;
            if let Some(target) = WEB_SIZES
                .iter()
                .copied()
                .find(|size| *size >= real_len + HEADER_LEN + config.min)
            {
                assert_eq!(total, target, "длина {real_len} промахнулась мимо {target}");
            }
        }
    }

    #[test]
    fn a_message_larger_than_every_target_gets_ordinary_padding() {
        let config = PaddingConfig::default();
        let random = OsRandom::new();
        let pad = for_target(40000, &WEB_SIZES, &config, &random);
        assert!((config.min..=config.max).contains(&pad));
    }

    #[test]
    fn a_message_that_only_just_fits_a_target_takes_the_next_one() {
        let config = PaddingConfig::default();
        let random = OsRandom::new();
        let real_len = 256 - HEADER_LEN - config.min + 1;
        let pad = for_target(real_len, &WEB_SIZES, &config, &random);
        assert_eq!(real_len + HEADER_LEN + pad, 512);
    }
}
