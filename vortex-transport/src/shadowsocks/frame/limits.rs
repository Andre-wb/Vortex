pub const LENGTH_LEN: usize = 2;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

pub const LENGTH_CHUNK_LEN: usize = LENGTH_LEN + TAG_LEN;

pub const MAX_PAYLOAD: usize = 16384;
pub const MAX_BODY_CHUNK_LEN: usize = MAX_PAYLOAD + TAG_LEN;
pub const MAX_FRAME: usize = LENGTH_CHUNK_LEN + MAX_BODY_CHUNK_LEN;

pub const NONCES_PER_FRAME: u64 = 2;

pub fn nonce(counter: u64) -> [u8; NONCE_LEN] {
    let mut bytes = [0u8; NONCE_LEN];
    bytes[NONCE_LEN - 8..].copy_from_slice(&counter.to_be_bytes());
    bytes
}

pub fn frame_len(payload_len: usize) -> usize {
    LENGTH_CHUNK_LEN + payload_len + TAG_LEN
}

#[cfg(test)]
mod tests {
    use super::{frame_len, nonce, MAX_FRAME, MAX_PAYLOAD};

    #[test]
    fn the_biggest_payload_still_fits_the_length_field() {
        assert!(MAX_PAYLOAD <= usize::from(u16::MAX));
        assert_eq!(frame_len(MAX_PAYLOAD), MAX_FRAME);
    }

    #[test]
    fn a_frame_costs_thirty_four_bytes_over_its_payload() {
        assert_eq!(frame_len(0), 34);
        assert_eq!(frame_len(1), 35);
    }

    #[test]
    fn the_nonce_is_the_operation_counter() {
        assert_eq!(nonce(0), [0u8; 12]);
        assert_eq!(nonce(1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_ne!(nonce(1), nonce(2));
    }

    #[test]
    fn the_length_and_the_body_never_share_a_nonce() {
        assert_ne!(nonce(0), nonce(1));
        assert_ne!(nonce(2), nonce(3));
    }
}
