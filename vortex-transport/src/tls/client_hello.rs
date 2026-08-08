use crate::tls::byte_slice::{be_uint, clamped};
use crate::tls::extension::Extensions;
use crate::tls::record::header::{CONTENT_HANDSHAKE, RECORD_HEADER_LEN};

pub const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
pub const RANDOM_OFFSET: usize = 4 + 2 + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloBody<'a> {
    pub session_id: &'a [u8],
    buffer: &'a [u8],
    extensions_start: usize,
    extensions_end: usize,
}

impl<'a> ClientHelloBody<'a> {
    pub fn extensions(&self) -> Extensions<'a> {
        Extensions::new(self.buffer, self.extensions_start, self.extensions_end)
    }
}

pub fn parse(data: &[u8]) -> Option<ClientHelloBody<'_>> {
    let buffer = match data.first() {
        Some(&CONTENT_HANDSHAKE) => data.get(RECORD_HEADER_LEN..).unwrap_or(&[]),
        _ => data,
    };
    if buffer.len() < 4 || buffer[0] != HANDSHAKE_CLIENT_HELLO {
        return None;
    }

    let mut pos = RANDOM_OFFSET;
    if pos + 1 > buffer.len() {
        return None;
    }
    let session_id_len = buffer[pos] as usize;
    pos += 1;
    let session_id = clamped(buffer, pos, session_id_len);
    pos += session_id_len;

    if pos + 2 > buffer.len() {
        return None;
    }
    pos += 2 + be_uint(buffer, pos, 2);

    if pos + 1 > buffer.len() {
        return None;
    }
    pos += 1 + buffer[pos] as usize;

    if pos + 2 > buffer.len() {
        return None;
    }
    let extensions_end = buffer.len().min(pos + 2 + be_uint(buffer, pos, 2));

    Some(ClientHelloBody {
        session_id,
        buffer,
        extensions_start: pos + 2,
        extensions_end,
    })
}

#[cfg(test)]
pub mod testing {
    pub fn client_hello(session_id: &[u8], extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x00; 32]);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        handshake
    }

    pub fn tls_record(handshake: &[u8]) -> Vec<u8> {
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(handshake);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::parse;
    use super::testing::{client_hello, tls_record};

    fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn reads_the_session_id_from_a_tls_record() {
        let hello = client_hello(&[0xAB; 32], &[]);
        let record = tls_record(&hello);
        let parsed = parse(&record).unwrap();
        assert_eq!(parsed.session_id, &[0xAB; 32]);
    }

    #[test]
    fn accepts_a_bare_handshake_without_the_record_header() {
        let hello = client_hello(&[0xAB; 32], &[]);
        assert_eq!(parse(&hello).unwrap().session_id, &[0xAB; 32]);
    }

    #[test]
    fn hands_out_every_extension() {
        let mut extensions = extension(0x0000, b"sni");
        extensions.extend_from_slice(&extension(0x0033, b"share"));
        let hello = client_hello(&[0xAB; 32], &extensions);
        let record = tls_record(&hello);
        let parsed = parse(&record).unwrap();
        let kinds: Vec<usize> = parsed.extensions().map(|ext| ext.kind).collect();
        assert_eq!(kinds, vec![0x0000, 0x0033]);
    }

    #[test]
    fn rejects_records_that_are_not_a_client_hello() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00]).is_none());
        assert!(parse(&[0x02, 0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn a_truncated_hello_is_rejected_without_panicking() {
        let hello = client_hello(&[0xAB; 32], &extension(0x0033, b"share"));
        let record = tls_record(&hello);
        for cut in 0..record.len() {
            let _ = parse(&record[..cut]);
        }
    }

    #[test]
    fn a_session_id_longer_than_the_buffer_is_rejected() {
        let mut hello = client_hello(&[0xAB; 32], &[]);
        hello[4 + 2 + 32] = 0xFF;
        assert!(parse(&hello).is_none());
    }
}
