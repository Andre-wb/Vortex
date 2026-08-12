use crate::ports::random_source::RandomSource;
use crate::random::sample::uniform;

pub fn hex(random: &dyn RandomSource, bytes: usize) -> String {
    let drawn = random.bytes(bytes);
    let mut out = String::with_capacity(bytes * 2);
    for byte in drawn {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn between(random: &dyn RandomSource, low: u64, high: u64) -> u64 {
    if high <= low {
        return low;
    }
    low + uniform::below(random, high - low + 1)
}

#[cfg(test)]
mod tests {
    use super::{between, hex};
    use crate::random::fixed_random::FixedRandom;
    use crate::random::os_random::OsRandom;

    #[test]
    fn a_token_is_twice_as_long_as_the_bytes_behind_it() {
        let random = OsRandom::new();
        assert_eq!(hex(&random, 32).len(), 64);
        assert_eq!(hex(&random, 48).len(), 96);
        assert!(hex(&random, 32).chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_token_is_not_the_same_token_twice() {
        let random = OsRandom::new();
        assert_ne!(hex(&random, 32), hex(&random, 32));
    }

    #[test]
    fn a_number_never_leaves_the_interval_it_was_asked_for() {
        let random = OsRandom::new();
        for _ in 0..2000 {
            let drawn = between(&random, 100_000_000, 999_999_999);
            assert!((100_000_000..=999_999_999).contains(&drawn));
        }
    }

    #[test]
    fn both_ends_of_the_interval_are_reachable() {
        let low = FixedRandom::new(vec![]).with_filler(0x00);
        assert_eq!(between(&low, 5, 9), 5);
        let mut seen_high = false;
        let random = OsRandom::new();
        for _ in 0..500 {
            if between(&random, 5, 9) == 9 {
                seen_high = true;
            }
        }
        assert!(seen_high);
    }

    #[test]
    fn an_interval_of_one_value_is_that_value() {
        let random = OsRandom::new();
        assert_eq!(between(&random, 7, 7), 7);
        assert_eq!(between(&random, 9, 5), 9);
    }
}
