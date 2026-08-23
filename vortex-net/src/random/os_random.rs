use crate::ports::random_source::RandomSource;
use rand::rngs::OsRng;
use rand::RngCore;

pub struct OsRandom;

impl OsRandom {
    pub fn new() -> Self {
        OsRandom
    }
}

impl Default for OsRandom {
    fn default() -> Self {
        OsRandom::new()
    }
}

impl RandomSource for OsRandom {
    fn fill_bytes(&self, buffer: &mut [u8]) {
        OsRng.fill_bytes(buffer);
    }
}
