use crate::ports::random_source::RandomSource;

pub fn below(random: &dyn RandomSource, bound: u32) -> u32 {
    if bound <= 1 {
        return 0;
    }
    let limit = u32::MAX - (u32::MAX % bound) - (bound - 1);
    loop {
        let mut raw = [0u8; 4];
        random.fill_bytes(&mut raw);
        let candidate = u32::from_be_bytes(raw);
        if candidate <= limit {
            return candidate % bound;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::below;
    use crate::random::fixed_random::FixedRandom;
    use crate::random::os_random::OsRandom;

    #[test]
    fn a_bound_of_one_leaves_no_choice() {
        assert_eq!(below(&OsRandom::new(), 1), 0);
        assert_eq!(below(&OsRandom::new(), 0), 0);
    }

    #[test]
    fn every_draw_stays_below_the_bound() {
        let random = OsRandom::new();
        for _ in 0..1000 {
            assert!(below(&random, 384) < 384);
        }
    }

    #[test]
    fn a_draw_above_the_fair_limit_is_discarded() {
        let random = FixedRandom::new(vec![0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x07]);
        assert_eq!(below(&random, 5), 2);
    }
}
