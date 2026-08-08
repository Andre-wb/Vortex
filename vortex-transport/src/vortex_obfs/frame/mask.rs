use crate::vortex_obfs::frame::limits::LENGTH_LEN;
use crate::vortex_obfs::schedule::keys::DirectionKey;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn of(key: &DirectionKey, counter: u64) -> [u8; LENGTH_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 принимает любой ключ");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    [digest[0], digest[1]]
}

pub fn hide(length: u16, mask: [u8; LENGTH_LEN]) -> [u8; LENGTH_LEN] {
    let bytes = length.to_be_bytes();
    [bytes[0] ^ mask[0], bytes[1] ^ mask[1]]
}

pub fn reveal(wire: [u8; LENGTH_LEN], mask: [u8; LENGTH_LEN]) -> u16 {
    u16::from_be_bytes([wire[0] ^ mask[0], wire[1] ^ mask[1]])
}

#[cfg(test)]
mod tests {
    use super::{hide, of, reveal};

    const KEY: [u8; 32] = [0x33; 32];

    #[test]
    fn what_was_hidden_is_revealed_again() {
        let mask = of(&KEY, 0);
        for length in [0u16, 1, 4096, u16::MAX] {
            assert_eq!(reveal(hide(length, mask), mask), length);
        }
    }

    #[test]
    fn the_length_on_the_wire_is_not_the_length_itself() {
        let mask = of(&KEY, 0);
        assert_ne!(hide(4096, mask), 4096u16.to_be_bytes());
    }

    #[test]
    fn every_frame_of_a_session_hides_its_length_differently() {
        let mut seen = Vec::new();
        for counter in 0..64u64 {
            seen.push(of(&KEY, counter));
        }
        seen.sort_unstable();
        let count = seen.len();
        seen.dedup();
        assert!(count - seen.len() <= 1, "маски повторяются слишком часто");
    }

    #[test]
    fn a_different_key_hides_the_same_length_differently() {
        let other: [u8; 32] = [0x34; 32];
        assert_ne!(of(&KEY, 0), of(&other, 0));
    }

    #[test]
    fn the_mask_is_frozen() {
        assert_eq!(of(&KEY, 0), [0xDC, 0xFF]);
    }
}
