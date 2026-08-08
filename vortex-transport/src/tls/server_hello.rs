use crate::tls::record::header::{CONTENT_HANDSHAKE, RECORD_HEADER_LEN};

pub const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
pub const SERVER_RANDOM_LEN: usize = 32;
pub const RANDOM_OFFSET: usize = 4 + 2;

pub type ServerRandom = [u8; SERVER_RANDOM_LEN];

pub fn random(data: &[u8]) -> Option<ServerRandom> {
    let buffer = match data.first() {
        Some(&CONTENT_HANDSHAKE) => data.get(RECORD_HEADER_LEN..).unwrap_or(&[]),
        _ => data,
    };
    if buffer.first() != Some(&HANDSHAKE_SERVER_HELLO) {
        return None;
    }
    buffer
        .get(RANDOM_OFFSET..RANDOM_OFFSET + SERVER_RANDOM_LEN)?
        .try_into()
        .ok()
}

#[cfg(test)]
pub mod testing {
    use super::{HANDSHAKE_SERVER_HELLO, SERVER_RANDOM_LEN};

    pub fn server_hello(random: &[u8; SERVER_RANDOM_LEN]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(random);
        body.push(0x20);
        body.extend_from_slice(&[0x00; 32]);
        body.extend_from_slice(&[0x13, 0x01, 0x00]);
        body.extend_from_slice(&[0x00, 0x00]);

        let mut handshake = vec![HANDSHAKE_SERVER_HELLO];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        handshake
    }

    pub fn server_hello_record(random: &[u8; SERVER_RANDOM_LEN]) -> Vec<u8> {
        let handshake = server_hello(random);
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::random;
    use super::testing::{server_hello, server_hello_record};

    #[test]
    fn reads_the_random_from_a_tls_record() {
        let expected = [0x5A; 32];
        assert_eq!(random(&server_hello_record(&expected)), Some(expected));
    }

    #[test]
    fn accepts_a_bare_handshake_without_the_record_header() {
        let expected = [0x11; 32];
        assert_eq!(random(&server_hello(&expected)), Some(expected));
    }

    #[test]
    fn refuses_a_handshake_that_is_not_a_server_hello() {
        let mut hello = server_hello(&[0x22; 32]);
        hello[0] = 0x01;
        assert_eq!(random(&hello), None);
        assert_eq!(random(&[]), None);
    }

    #[test]
    fn a_truncated_hello_yields_nothing_without_panicking() {
        let record = server_hello_record(&[0x33; 32]);
        for cut in 0..record.len() {
            let _ = random(&record[..cut]);
        }
        assert_eq!(random(&record[..40]), None);
    }
}
