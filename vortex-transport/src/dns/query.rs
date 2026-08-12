use crate::dns::name;

pub const HEADER: [u8; 12] = [0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
pub const TYPE_A: u16 = 1;
pub const TYPE_TXT: u16 = 16;
pub const CLASS_IN: u16 = 1;

pub fn asking(host: &str, kind: u16) -> Option<Vec<u8>> {
    let question = name::encode(host)?;
    let mut out = Vec::with_capacity(HEADER.len() + question.len() + 4);
    out.extend_from_slice(&HEADER);
    out.extend_from_slice(&question);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{asking, HEADER, TYPE_A, TYPE_TXT};

    #[test]
    fn a_query_is_a_header_a_name_a_type_and_a_class() {
        let query = asking("example.org", TYPE_A).unwrap();
        assert_eq!(&query[..HEADER.len()], &HEADER);
        assert_eq!(
            &query[HEADER.len()..HEADER.len() + 13],
            b"\x07example\x03org\x00"
        );
        assert_eq!(&query[query.len() - 4..], &[0, 1, 0, 1]);
    }

    #[test]
    fn the_query_asks_for_the_kind_of_record_it_was_told_to() {
        let text = asking("example.org", TYPE_TXT).unwrap();
        assert_eq!(&text[text.len() - 4..], &[0, 16, 0, 1]);
    }

    #[test]
    fn the_header_says_one_question_and_asks_for_recursion() {
        let query = asking("a.b", TYPE_A).unwrap();
        assert_eq!(query[2] & 0x01, 0x01);
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1);
        assert_eq!(u16::from_be_bytes([query[6], query[7]]), 0);
    }

    #[test]
    fn a_name_that_is_not_a_name_produces_no_query() {
        assert_eq!(asking("", TYPE_A), None);
        assert_eq!(asking("a..b", TYPE_A), None);
    }
}
