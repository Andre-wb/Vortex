//! Процентное декодирование — аналог `urllib.parse.unquote`.

/// Декодирует `%XX`; некорректные последовательности остаются как есть.
/// Невалидный UTF-8 заменяется на U+FFFD, как при `errors="replace"` в Python.
pub fn decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// То же плюс `+` -> пробел (аналог `unquote_plus`).
pub fn decode_plus(input: &str) -> String {
    decode(&input.replace('+', " "))
}

/// Двойное декодирование: прежний движок так боролся с двойным кодированием
/// обхода каталогов.
pub fn decode_twice(input: &str) -> String {
    decode(&decode(input))
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, decode_plus, decode_twice};

    #[test]
    fn decodes_simple_escapes() {
        assert_eq!(decode("a%20b"), "a b");
        assert_eq!(decode("%2e%2e%2f"), "../");
    }

    #[test]
    fn leaves_broken_escapes_alone() {
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%zz"), "%zz");
    }

    #[test]
    fn double_decoding_reveals_traversal() {
        assert_eq!(decode_twice("%252e%252e%252f"), "../");
    }

    #[test]
    fn plus_becomes_space() {
        assert_eq!(decode_plus("a+b%21"), "a b!");
    }

    #[test]
    fn decodes_multibyte_utf8() {
        assert_eq!(decode("%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82"), "привет");
    }
}
