pub const MAX_LABEL: usize = 63;
pub const MAX_NAME: usize = 255;
pub const POINTER_MASK: u8 = 0xC0;

pub fn encode(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > MAX_LABEL {
            return None;
        }
        if !label.is_ascii() {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    if out.len() > MAX_NAME {
        return None;
    }
    Some(out)
}

pub fn skip(wire: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let length = *wire.get(at)?;
        if length == 0 {
            return Some(at + 1);
        }
        if length & POINTER_MASK == POINTER_MASK {
            return if at + 2 <= wire.len() {
                Some(at + 2)
            } else {
                None
            };
        }
        if length as usize > MAX_LABEL {
            return None;
        }
        at = at.checked_add(1 + length as usize)?;
        if at > wire.len() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{encode, skip, MAX_LABEL};

    #[test]
    fn a_name_becomes_a_length_and_a_label_for_every_part_of_it() {
        assert_eq!(encode("a.bc").unwrap(), b"\x01a\x02bc\x00");
        assert_eq!(
            encode("example.org").unwrap(),
            b"\x07example\x03org\x00".to_vec()
        );
    }

    #[test]
    fn the_dot_a_name_may_end_with_is_not_a_label() {
        assert_eq!(encode("example.org."), encode("example.org"));
    }

    #[test]
    fn a_name_that_does_not_fit_the_format_is_refused() {
        assert_eq!(encode(""), None);
        assert_eq!(encode("a..b"), None);
        assert_eq!(encode(&"a".repeat(MAX_LABEL + 1)), None);
        assert_eq!(encode("россия.рф"), None);
        let too_long = vec!["abcdefghij"; 30].join(".");
        assert_eq!(encode(&too_long), None);
    }

    #[test]
    fn a_label_of_the_greatest_length_still_fits() {
        let longest = "a".repeat(MAX_LABEL);
        assert!(encode(&longest).is_some());
    }

    #[test]
    fn skipping_a_name_lands_on_the_byte_after_it() {
        let wire = b"\x07example\x03org\x00rest";
        assert_eq!(skip(wire, 0), Some(13));
        assert_eq!(&wire[13..], b"rest");
    }

    #[test]
    fn skipping_a_compressed_name_lands_after_the_pointer() {
        let wire = b"\xc0\x0crest";
        assert_eq!(skip(wire, 0), Some(2));
    }

    #[test]
    fn a_name_that_runs_off_the_end_of_the_message_is_refused_and_never_loops() {
        assert_eq!(skip(b"", 0), None);
        assert_eq!(skip(b"\x07exam", 0), None);
        assert_eq!(skip(b"\xc0", 0), None);
        assert_eq!(skip(b"\x07example\x03org", 0), None);
    }
}
