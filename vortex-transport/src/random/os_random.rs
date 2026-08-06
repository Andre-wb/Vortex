use crate::ports::random_source::RandomSource;
use rand::RngCore;

#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl OsRandom {
    pub fn new() -> Self {
        OsRandom
    }
}

impl RandomSource for OsRandom {
    fn fill_bytes(&self, buffer: &mut [u8]) {
        rand::rngs::OsRng.fill_bytes(buffer);
    }
}
