pub const HEADER: usize = 6;
pub const MAX_CHUNKS: usize = u16::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub message: u16,
    pub total: u16,
    pub index: u16,
}

impl Chunk {
    pub fn written(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + payload.len());
        out.extend_from_slice(&self.message.to_be_bytes());
        out.extend_from_slice(&self.total.to_be_bytes());
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    pub fn read(raw: &[u8]) -> Option<(Chunk, Vec<u8>)> {
        if raw.len() < HEADER {
            return None;
        }
        let chunk = Chunk {
            message: u16::from_be_bytes([raw[0], raw[1]]),
            total: u16::from_be_bytes([raw[2], raw[3]]),
            index: u16::from_be_bytes([raw[4], raw[5]]),
        };
        if chunk.total == 0 || chunk.index >= chunk.total {
            return None;
        }
        Some((chunk, raw[HEADER..].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Chunk, HEADER};

    #[test]
    fn a_chunk_carries_which_message_it_belongs_to_and_where_it_sits() {
        let chunk = Chunk {
            message: 7,
            total: 3,
            index: 1,
        };
        let raw = chunk.written(b"payload");
        assert_eq!(raw.len(), HEADER + 7);
        assert_eq!(Chunk::read(&raw), Some((chunk, b"payload".to_vec())));
    }

    #[test]
    fn a_chunk_with_no_payload_is_still_a_chunk() {
        let chunk = Chunk {
            message: 0,
            total: 1,
            index: 0,
        };
        assert_eq!(Chunk::read(&chunk.written(b"")), Some((chunk, Vec::new())));
    }

    #[test]
    fn what_is_too_short_to_hold_a_header_is_not_a_chunk() {
        for length in 0..HEADER {
            assert_eq!(Chunk::read(&vec![0u8; length]), None);
        }
    }

    #[test]
    fn a_chunk_that_sits_outside_its_own_message_is_refused() {
        let past_the_end = Chunk {
            message: 1,
            total: 2,
            index: 2,
        };
        assert_eq!(Chunk::read(&past_the_end.written(b"x")), None);
        let empty_message = Chunk {
            message: 1,
            total: 0,
            index: 0,
        };
        assert_eq!(Chunk::read(&empty_message.written(b"x")), None);
    }
}
