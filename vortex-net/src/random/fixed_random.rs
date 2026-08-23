use crate::ports::random_source::RandomSource;
use parking_lot::Mutex;

pub struct FixedRandom {
    bytes: Vec<u8>,
    cursor: Mutex<usize>,
}

impl FixedRandom {
    pub fn new(bytes: Vec<u8>) -> Self {
        FixedRandom {
            bytes,
            cursor: Mutex::new(0),
        }
    }
}

impl RandomSource for FixedRandom {
    fn fill_bytes(&self, buffer: &mut [u8]) {
        if self.bytes.is_empty() {
            buffer.iter_mut().for_each(|slot| *slot = 0);
            return;
        }
        let mut cursor = self.cursor.lock();
        for slot in buffer.iter_mut() {
            *slot = self.bytes[*cursor % self.bytes.len()];
            *cursor += 1;
        }
    }
}
