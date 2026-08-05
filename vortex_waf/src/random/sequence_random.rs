//! Детерминированный источник случайности для тестов.

use crate::ports::random_source::RandomSource;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Выдаёт заранее заданную последовательность чисел по кругу.
#[derive(Debug)]
pub struct SequenceRandom {
    values: Vec<u32>,
    cursor: AtomicUsize,
    filler: u8,
}

impl SequenceRandom {
    pub fn new(values: Vec<u32>) -> Self {
        SequenceRandom {
            values,
            cursor: AtomicUsize::new(0),
            filler: 0xAB,
        }
    }

    pub fn with_filler(mut self, filler: u8) -> Self {
        self.filler = filler;
        self
    }
}

impl RandomSource for SequenceRandom {
    fn below(&self, upper: u32) -> u32 {
        if upper == 0 || self.values.is_empty() {
            return 0;
        }
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % self.values.len();
        self.values[idx] % upper
    }

    fn fill_bytes(&self, buffer: &mut [u8]) {
        buffer.fill(self.filler);
    }
}

#[cfg(test)]
mod tests {
    use super::SequenceRandom;
    use crate::ports::random_source::RandomSource;

    #[test]
    fn repeats_the_sequence() {
        let rng = SequenceRandom::new(vec![1, 2, 3]);
        assert_eq!(rng.below(10), 1);
        assert_eq!(rng.below(10), 2);
        assert_eq!(rng.below(10), 3);
        assert_eq!(rng.below(10), 1);
    }

    #[test]
    fn hex_is_deterministic() {
        let rng = SequenceRandom::new(vec![0]).with_filler(0x0f);
        assert_eq!(rng.hex(4), "0f0f0f0f");
    }
}
