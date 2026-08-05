//! Криптографически стойкая случайность операционной системы.

use crate::ports::random_source::RandomSource;
use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl OsRandom {
    pub fn new() -> Self {
        OsRandom
    }
}

impl RandomSource for OsRandom {
    fn below(&self, upper: u32) -> u32 {
        if upper == 0 {
            return 0;
        }
        // Отбрасываем «хвост» диапазона, чтобы распределение осталось равномерным.
        let limit = u32::MAX - (u32::MAX % upper);
        loop {
            let candidate = OsRng.next_u32();
            if candidate < limit {
                return candidate % upper;
            }
        }
    }

    fn fill_bytes(&self, buffer: &mut [u8]) {
        OsRng.fill_bytes(buffer);
    }
}

#[cfg(test)]
mod tests {
    use super::OsRandom;
    use crate::ports::random_source::RandomSource;

    #[test]
    fn stays_within_bounds() {
        let rng = OsRandom::new();
        for _ in 0..200 {
            assert!(rng.below(10) < 10);
        }
        assert_eq!(rng.below(0), 0);
        assert_eq!(rng.hex(8).len(), 16);
    }
}
