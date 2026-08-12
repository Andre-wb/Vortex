pub const POLYNOMIAL: u32 = 0xEDB8_8320;

pub fn of(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let carry = crc & 1;
            crc >>= 1;
            if carry != 0 {
                crc ^= POLYNOMIAL;
            }
        }
    }
    crc ^ u32::MAX
}

#[cfg(test)]
mod tests {
    use super::of;

    #[test]
    fn the_published_check_values_are_the_ones_we_produce() {
        assert_eq!(of(b""), 0x0000_0000);
        assert_eq!(of(b"a"), 0xE8B7_BE43);
        assert_eq!(of(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            of(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn a_single_changed_byte_changes_the_sum() {
        assert_ne!(of(b"hello"), of(b"hellp"));
        assert_ne!(of(&[0u8; 32]), of(&[0u8; 33]));
    }

    #[test]
    fn a_long_payload_is_summed_without_overflowing_anything() {
        let long = vec![0xABu8; 100_000];
        assert_eq!(of(&long), of(&long));
    }
}
