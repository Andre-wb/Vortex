use crate::ports::random_source::RandomSource;
use parking_lot::Mutex;

#[derive(Debug)]
pub struct FixedRandom {
    bytes: Mutex<std::collections::VecDeque<u8>>,
    filler: u8,
}

impl FixedRandom {
    pub fn new(bytes: Vec<u8>) -> Self {
        FixedRandom {
            bytes: Mutex::new(bytes.into()),
            filler: 0,
        }
    }

    pub fn with_filler(mut self, filler: u8) -> Self {
        self.filler = filler;
        self
    }
}

impl RandomSource for FixedRandom {
    fn fill_bytes(&self, buffer: &mut [u8]) {
        let mut queue = self.bytes.lock();
        for slot in buffer.iter_mut() {
            *slot = queue.pop_front().unwrap_or(self.filler);
        }
    }
}
