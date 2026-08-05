//! Обрезка строк по символам, а не по байтам.

/// Первые `max` символов строки. Границы UTF-8 не нарушаются.
pub fn take_chars(input: &str, max: usize) -> &str {
    match input.char_indices().nth(max) {
        Some((idx, _)) => &input[..idx],
        None => input,
    }
}

/// Длина в символах — соответствует `len()` для `str` в Python.
pub fn char_len(input: &str) -> usize {
    input.chars().count()
}

#[cfg(test)]
mod tests {
    use super::{char_len, take_chars};

    #[test]
    fn respects_utf8_boundaries() {
        assert_eq!(take_chars("привет", 3), "при");
        assert_eq!(take_chars("abc", 10), "abc");
        assert_eq!(char_len("привет"), 6);
    }
}
