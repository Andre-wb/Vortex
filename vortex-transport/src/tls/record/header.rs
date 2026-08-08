pub const RECORD_HEADER_LEN: usize = 5;
pub const MAX_RECORD_PAYLOAD: usize = 16640;

pub const CONTENT_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const CONTENT_ALERT: u8 = 0x15;
pub const CONTENT_HANDSHAKE: u8 = 0x16;
pub const CONTENT_APPLICATION_DATA: u8 = 0x17;

pub const LEGACY_VERSION_MAJOR: u8 = 0x03;
pub const RECORD_VERSION: [u8; 2] = [0x03, 0x03];

const CONTENT_TYPES: [u8; 4] = [
    CONTENT_CHANGE_CIPHER_SPEC,
    CONTENT_ALERT,
    CONTENT_HANDSHAKE,
    CONTENT_APPLICATION_DATA,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub content_type: u8,
    pub payload_len: usize,
}

pub fn parse(bytes: &[u8]) -> Option<RecordHeader> {
    if bytes.len() < RECORD_HEADER_LEN {
        return None;
    }
    let content_type = bytes[0];
    if !CONTENT_TYPES.contains(&content_type) || bytes[1] != LEGACY_VERSION_MAJOR {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    if payload_len > MAX_RECORD_PAYLOAD {
        return None;
    }
    Some(RecordHeader {
        content_type,
        payload_len,
    })
}

pub fn encode(content_type: u8, payload_len: usize) -> Option<[u8; RECORD_HEADER_LEN]> {
    if payload_len > MAX_RECORD_PAYLOAD {
        return None;
    }
    let length = (payload_len as u16).to_be_bytes();
    Some([
        content_type,
        RECORD_VERSION[0],
        RECORD_VERSION[1],
        length[0],
        length[1],
    ])
}

#[cfg(test)]
mod tests {
    use super::{
        encode, parse, RecordHeader, CONTENT_APPLICATION_DATA, MAX_RECORD_PAYLOAD,
        RECORD_HEADER_LEN,
    };

    #[test]
    fn reads_a_well_formed_header() {
        assert_eq!(
            parse(&[0x17, 0x03, 0x03, 0x00, 0x10]),
            Some(RecordHeader {
                content_type: CONTENT_APPLICATION_DATA,
                payload_len: 16,
            })
        );
    }

    #[test]
    fn refuses_an_unknown_content_type() {
        assert_eq!(parse(&[0x47, 0x03, 0x03, 0x00, 0x10]), None);
    }

    #[test]
    fn refuses_a_foreign_major_version() {
        assert_eq!(parse(&[0x17, 0x02, 0x03, 0x00, 0x10]), None);
    }

    #[test]
    fn refuses_a_payload_above_the_tls_ceiling() {
        assert_eq!(parse(&[0x17, 0x03, 0x03, 0xFF, 0xFF]), None);
        let at_ceiling = (MAX_RECORD_PAYLOAD as u16).to_be_bytes();
        assert!(parse(&[0x17, 0x03, 0x03, at_ceiling[0], at_ceiling[1]]).is_some());
    }

    #[test]
    fn refuses_a_header_that_is_not_there_yet() {
        assert_eq!(parse(&[0x17, 0x03, 0x03, 0x00]), None);
    }

    #[test]
    fn what_is_encoded_parses_back() {
        let header = encode(CONTENT_APPLICATION_DATA, 300).unwrap();
        assert_eq!(header.len(), RECORD_HEADER_LEN);
        assert_eq!(parse(&header).unwrap().payload_len, 300);
    }

    #[test]
    fn a_body_above_the_tls_ceiling_has_no_header() {
        assert!(encode(CONTENT_APPLICATION_DATA, MAX_RECORD_PAYLOAD).is_some());
        assert_eq!(
            encode(CONTENT_APPLICATION_DATA, MAX_RECORD_PAYLOAD + 1),
            None
        );
        assert_eq!(encode(CONTENT_APPLICATION_DATA, 70_000), None);
    }
}
