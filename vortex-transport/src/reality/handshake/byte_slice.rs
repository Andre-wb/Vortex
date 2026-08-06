pub fn clamped(buffer: &[u8], start: usize, len: usize) -> &[u8] {
    let start = start.min(buffer.len());
    let end = start.saturating_add(len).min(buffer.len());
    &buffer[start..end]
}

pub fn be_uint(buffer: &[u8], start: usize, len: usize) -> usize {
    clamped(buffer, start, len)
        .iter()
        .fold(0usize, |acc, byte| (acc << 8) | *byte as usize)
}

#[cfg(test)]
mod tests {
    use super::{be_uint, clamped};

    #[test]
    fn slicing_past_the_end_yields_what_is_left() {
        assert_eq!(clamped(&[1, 2, 3], 1, 10), &[2, 3]);
        assert_eq!(clamped(&[1, 2, 3], 9, 2), &[] as &[u8]);
    }

    #[test]
    fn reads_big_endian_numbers() {
        assert_eq!(be_uint(&[0x01, 0x02], 0, 2), 0x0102);
        assert_eq!(be_uint(&[0x00, 0xFF], 0, 2), 255);
    }

    #[test]
    fn a_truncated_number_reads_as_the_bytes_that_exist() {
        assert_eq!(be_uint(&[0x05], 0, 2), 5);
        assert_eq!(be_uint(&[], 0, 2), 0);
    }
}
