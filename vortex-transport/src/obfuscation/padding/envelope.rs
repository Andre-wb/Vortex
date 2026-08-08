use crate::obfuscation::padding::header::{Header, HEADER_LEN};

pub fn pad(data: &[u8], padding: &[u8]) -> Option<Vec<u8>> {
    let header = Header::new(data.len(), padding.len())?;
    let mut envelope = Vec::with_capacity(header.envelope_len());
    envelope.extend_from_slice(&header.encode());
    envelope.extend_from_slice(data);
    envelope.extend_from_slice(padding);
    Some(envelope)
}

pub fn unpad(envelope: &[u8]) -> Option<&[u8]> {
    let header = Header::decode(envelope)?;
    if header.envelope_len() != envelope.len() {
        return None;
    }
    Some(&envelope[HEADER_LEN..HEADER_LEN + usize::from(header.real_len)])
}

#[cfg(test)]
mod tests {
    use super::{pad, unpad};
    use crate::obfuscation::padding::header::{HEADER_LEN, MAX_FIELD};

    #[test]
    fn what_was_padded_comes_back_whole() {
        let envelope = pad(b"Hello, Vortex!", &[0x00; 40]).unwrap();
        assert_eq!(envelope.len(), HEADER_LEN + 14 + 40);
        assert_eq!(unpad(&envelope), Some(&b"Hello, Vortex!"[..]));
    }

    #[test]
    fn an_empty_message_is_still_an_envelope() {
        let envelope = pad(b"", &[0xAA; 16]).unwrap();
        assert_eq!(unpad(&envelope), Some(&b""[..]));
    }

    #[test]
    fn a_message_that_does_not_fit_the_length_field_is_refused_instead_of_passed_through() {
        assert!(pad(&vec![0x41; MAX_FIELD + 1], &[0x00; 16]).is_none());
        assert!(pad(&vec![0x41; MAX_FIELD], &[0x00; 16]).is_some());
    }

    #[test]
    fn a_buffer_that_was_never_padded_is_refused_rather_than_returned_as_a_message() {
        let never_padded = vec![0x41; 70000];
        assert_eq!(unpad(&never_padded), None);
    }

    #[test]
    fn a_declared_length_that_does_not_match_the_buffer_is_refused() {
        let mut envelope = pad(b"body", &[0x00; 16]).unwrap();
        envelope.pop();
        assert_eq!(unpad(&envelope), None);
        let mut longer = pad(b"body", &[0x00; 16]).unwrap();
        longer.push(0x00);
        assert_eq!(unpad(&longer), None);
    }

    #[test]
    fn the_padding_length_is_part_of_what_is_checked() {
        let mut envelope = pad(b"body", &[0x00; 16]).unwrap();
        envelope[2] = 0x00;
        envelope[3] = 0x00;
        assert_eq!(unpad(&envelope), None);
    }

    #[test]
    fn a_buffer_shorter_than_the_header_is_not_an_envelope() {
        assert_eq!(unpad(&[0x00, 0x01]), None);
        assert_eq!(unpad(&[]), None);
    }

    #[test]
    fn the_message_sits_right_after_the_header() {
        let envelope = pad(b"abc", &[0xFF; 16]).unwrap();
        assert_eq!(&envelope[..HEADER_LEN], &[0x00, 0x03, 0x00, 0x10]);
        assert_eq!(&envelope[HEADER_LEN..HEADER_LEN + 3], b"abc");
    }
}
