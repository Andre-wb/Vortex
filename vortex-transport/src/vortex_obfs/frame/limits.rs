pub const LENGTH_LEN: usize = 2;
pub const DATA_LEN_LEN: usize = 2;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

pub const MAX_PAYLOAD: usize = 16384;
pub const MAX_PADDING: usize = 1024;

pub const MIN_BODY: usize = DATA_LEN_LEN + TAG_LEN;
pub const MAX_BODY: usize = DATA_LEN_LEN + MAX_PAYLOAD + MAX_PADDING + TAG_LEN;
pub const MAX_FRAME: usize = LENGTH_LEN + MAX_BODY;

pub fn nonce(counter: u64) -> [u8; NONCE_LEN] {
    let mut bytes = [0u8; NONCE_LEN];
    bytes[NONCE_LEN - 8..].copy_from_slice(&counter.to_be_bytes());
    bytes
}

pub fn aad(length: [u8; LENGTH_LEN], counter: u64) -> [u8; LENGTH_LEN + 8] {
    let mut bytes = [0u8; LENGTH_LEN + 8];
    bytes[..LENGTH_LEN].copy_from_slice(&length);
    bytes[LENGTH_LEN..].copy_from_slice(&counter.to_be_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::{aad, nonce, MAX_BODY, MAX_FRAME, MIN_BODY};

    #[test]
    fn the_biggest_body_still_fits_the_length_field() {
        let biggest: usize = MAX_BODY;
        let smallest: usize = MIN_BODY;
        assert!(biggest <= usize::from(u16::MAX));
        assert!(smallest < biggest);
        assert_eq!(MAX_FRAME, biggest + 2);
    }

    #[test]
    fn the_nonce_is_the_frame_counter() {
        assert_eq!(nonce(0), [0u8; 12]);
        assert_eq!(nonce(1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_ne!(nonce(1), nonce(2));
    }

    #[test]
    fn the_authenticated_data_covers_the_length_on_the_wire_and_the_counter() {
        assert_eq!(aad([0xAB, 0xCD], 7), [0xAB, 0xCD, 0, 0, 0, 0, 0, 0, 0, 7]);
        assert_ne!(aad([0xAB, 0xCD], 7), aad([0xAB, 0xCE], 7));
        assert_ne!(aad([0xAB, 0xCD], 7), aad([0xAB, 0xCD], 8));
    }
}
