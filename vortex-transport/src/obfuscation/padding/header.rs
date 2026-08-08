pub const HEADER_LEN: usize = 4;
pub const MAX_FIELD: usize = u16::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub real_len: u16,
    pub pad_len: u16,
}

impl Header {
    pub fn new(real_len: usize, pad_len: usize) -> Option<Self> {
        if real_len > MAX_FIELD || pad_len > MAX_FIELD {
            return None;
        }
        Some(Header {
            real_len: real_len as u16,
            pad_len: pad_len as u16,
        })
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN {
            return None;
        }
        Some(Header {
            real_len: u16::from_be_bytes([bytes[0], bytes[1]]),
            pad_len: u16::from_be_bytes([bytes[2], bytes[3]]),
        })
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let real = self.real_len.to_be_bytes();
        let pad = self.pad_len.to_be_bytes();
        [real[0], real[1], pad[0], pad[1]]
    }

    pub fn envelope_len(&self) -> usize {
        HEADER_LEN + usize::from(self.real_len) + usize::from(self.pad_len)
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, HEADER_LEN, MAX_FIELD};

    #[test]
    fn what_is_written_is_what_is_read_back() {
        let header = Header::new(1234, 321).unwrap();
        assert_eq!(Header::decode(&header.encode()), Some(header));
    }

    #[test]
    fn both_fields_are_big_endian_and_in_this_order() {
        assert_eq!(
            Header::new(1, 2).unwrap().encode(),
            [0x00, 0x01, 0x00, 0x02]
        );
    }

    #[test]
    fn a_field_that_does_not_fit_in_two_bytes_has_no_header() {
        assert!(Header::new(MAX_FIELD + 1, 16).is_none());
        assert!(Header::new(16, MAX_FIELD + 1).is_none());
        assert!(Header::new(MAX_FIELD, MAX_FIELD).is_some());
    }

    #[test]
    fn a_buffer_shorter_than_the_header_is_not_a_header() {
        assert!(Header::decode(&[0x00, 0x01, 0x00]).is_none());
        assert!(Header::decode(&[]).is_none());
    }

    #[test]
    fn the_envelope_length_counts_the_header_itself() {
        let header = Header::new(10, 20).unwrap();
        assert_eq!(header.envelope_len(), HEADER_LEN + 30);
    }
}
