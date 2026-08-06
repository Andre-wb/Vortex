use crate::ports::random_source::RandomSource;
use std::sync::Mutex;

#[derive(Debug)]
pub struct FixedRandom {
    queue: Mutex<Vec<u8>>,
    filler: u8,
}

impl FixedRandom {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        let mut queue = bytes.into();
        queue.reverse();
        FixedRandom {
            queue: Mutex::new(queue),
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
        let mut queue = self.queue.lock().expect("FixedRandom отравлен");
        for slot in buffer.iter_mut() {
            *slot = queue.pop().unwrap_or(self.filler);
        }
    }
}
