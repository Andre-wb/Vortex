use rand::rngs::OsRng;
use rand::RngCore;

use crate::ports::entropy::Entropy;

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEntropy;

impl SystemEntropy {
    pub fn new() -> Self {
        SystemEntropy
    }
}

impl Entropy for SystemEntropy {
    fn fill(&self, into: &mut [u8]) {
        OsRng.fill_bytes(into);
    }
}

#[cfg(test)]
mod tests {
    use super::SystemEntropy;
    use crate::ports::entropy::Entropy;

    #[test]
    fn two_draws_from_the_operating_system_never_repeat() {
        let source = SystemEntropy::new();
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        source.fill(&mut first);
        source.fill(&mut second);
        assert_ne!(first, second);
        assert_ne!(first, [0u8; 32]);
    }
}
