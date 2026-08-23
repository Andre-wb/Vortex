use parking_lot::Mutex;

use crate::ports::entropy::Entropy;

pub struct FixedEntropy {
    next: Mutex<u8>,
}

impl FixedEntropy {
    pub fn counting_from(first: u8) -> Self {
        FixedEntropy {
            next: Mutex::new(first),
        }
    }
}

impl Entropy for FixedEntropy {
    fn fill(&self, into: &mut [u8]) {
        let mut next = self.next.lock();
        for slot in into.iter_mut() {
            *slot = *next;
            *next = next.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FixedEntropy;
    use crate::ports::entropy::Entropy;

    #[test]
    fn a_predictable_source_keeps_counting_across_draws() {
        let source = FixedEntropy::counting_from(7);
        let mut first = [0u8; 3];
        let mut second = [0u8; 2];
        source.fill(&mut first);
        source.fill(&mut second);
        assert_eq!(first, [7, 8, 9]);
        assert_eq!(second, [10, 11]);
    }
}
