use crate::ports::random_source::RandomSource;

const MANTISSA_BITS: u32 = 53;

pub const MAX_ATTEMPTS: usize = 32;

pub fn unit(random: &dyn RandomSource) -> f64 {
    let mut bytes = [0u8; 8];
    random.fill_bytes(&mut bytes);
    let drawn = u64::from_be_bytes(bytes) >> (64 - MANTISSA_BITS);
    drawn as f64 / (1u64 << MANTISSA_BITS) as f64
}

pub fn range(random: &dyn RandomSource, low: f64, high: f64) -> f64 {
    low + unit(random) * (high - low)
}

pub fn below(random: &dyn RandomSource, bound: u64) -> u64 {
    if bound <= 1 {
        return 0;
    }
    let limit = u64::MAX - u64::MAX % bound;
    let mut drawn = 0u64;
    for _ in 0..MAX_ATTEMPTS {
        let mut bytes = [0u8; 8];
        random.fill_bytes(&mut bytes);
        drawn = u64::from_be_bytes(bytes);
        if drawn < limit {
            return drawn % bound;
        }
    }
    drawn % bound
}

#[cfg(test)]
mod tests {
    use super::{below, range, unit};
    use crate::random::fixed_random::FixedRandom;
    use crate::random::os_random::OsRandom;

    #[test]
    fn all_zero_bytes_are_the_bottom_of_the_interval() {
        let random = FixedRandom::new(vec![]).with_filler(0x00);
        assert_eq!(unit(&random), 0.0);
    }

    #[test]
    fn all_one_bytes_stay_below_one() {
        let random = FixedRandom::new(vec![]).with_filler(0xFF);
        let drawn = unit(&random);
        assert!(drawn < 1.0);
        assert!(drawn > 0.999);
    }

    #[test]
    fn the_interval_is_never_left() {
        let random = OsRandom::new();
        for _ in 0..2000 {
            let drawn = range(&random, -3.0, 7.0);
            assert!((-3.0..7.0).contains(&drawn));
        }
    }

    #[test]
    fn a_bound_of_one_or_zero_leaves_no_choice() {
        let random = OsRandom::new();
        assert_eq!(below(&random, 0), 0);
        assert_eq!(below(&random, 1), 0);
    }

    #[test]
    fn every_value_below_the_bound_is_reachable_and_nothing_above_it_is() {
        let random = OsRandom::new();
        let mut seen = [false; 5];
        for _ in 0..500 {
            let drawn = below(&random, 5) as usize;
            assert!(drawn < 5);
            seen[drawn] = true;
        }
        assert!(seen.iter().all(|hit| *hit));
    }

    #[test]
    fn a_source_that_never_draws_below_the_bound_still_answers() {
        let stuck = FixedRandom::new(vec![]).with_filler(0xFF);
        assert_eq!(below(&stuck, 900_000), u64::MAX % 900_000);
        assert!(below(&stuck, 7) < 7);
    }

    #[test]
    fn the_rejection_bound_keeps_the_draw_unbiased() {
        let random = FixedRandom::new(u64::MAX.to_be_bytes().to_vec()).with_filler(0x00);
        assert_eq!(
            below(&random, 3),
            0,
            "перебор отбрасывается и берётся заново"
        );
    }
}
