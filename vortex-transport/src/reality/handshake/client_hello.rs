use crate::reality::auth::sealed_auth::X25519_KEY_LEN;
use crate::reality::handshake::key_share::{x25519_from_extension, EXTENSION_KEY_SHARE};
use crate::tls::client_hello as tls_client_hello;
pub use crate::tls::client_hello::{HANDSHAKE_CLIENT_HELLO, RANDOM_OFFSET};
pub use crate::tls::record::header::{
    CONTENT_HANDSHAKE as TLS_HANDSHAKE_RECORD, RECORD_HEADER_LEN as TLS_RECORD_HEADER_LEN,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub session_id: Vec<u8>,
    pub key_share: Option<[u8; X25519_KEY_LEN]>,
}

pub fn parse(data: &[u8]) -> Option<ClientHello> {
    let body = tls_client_hello::parse(data)?;

    let mut key_share = None;
    for extension in body.extensions() {
        if extension.kind != EXTENSION_KEY_SHARE {
            continue;
        }
        if let Some(found) = x25519_from_extension(extension.body) {
            key_share = Some(found);
        }
    }

    Some(ClientHello {
        session_id: body.session_id.to_vec(),
        key_share,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse, ClientHello};
    use crate::tls::client_hello::testing::{client_hello, tls_record};

    fn key_share_extension(key: &[u8]) -> Vec<u8> {
        let mut entry = 0x001Du16.to_be_bytes().to_vec();
        entry.extend_from_slice(&(key.len() as u16).to_be_bytes());
        entry.extend_from_slice(key);

        let mut body = (entry.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&entry);

        let mut extension = 0x0033u16.to_be_bytes().to_vec();
        extension.extend_from_slice(&(body.len() as u16).to_be_bytes());
        extension.extend_from_slice(&body);
        extension
    }

    #[test]
    fn reads_session_id_and_key_share_from_a_tls_record() {
        let hello = client_hello(&[0xAB; 32], &key_share_extension(&[0xCD; 32]));
        let parsed = parse(&tls_record(&hello)).unwrap();
        assert_eq!(
            parsed,
            ClientHello {
                session_id: vec![0xAB; 32],
                key_share: Some([0xCD; 32]),
            }
        );
    }

    #[test]
    fn accepts_a_bare_handshake_without_the_record_header() {
        let hello = client_hello(&[0xAB; 32], &key_share_extension(&[0xCD; 32]));
        assert_eq!(parse(&hello).unwrap().key_share, Some([0xCD; 32]));
    }

    #[test]
    fn a_hello_without_key_share_parses_but_carries_no_key() {
        let hello = client_hello(&[0xAB; 32], &[]);
        let parsed = parse(&tls_record(&hello)).unwrap();
        assert_eq!(parsed.session_id, vec![0xAB; 32]);
        assert_eq!(parsed.key_share, None);
    }

    #[test]
    fn the_last_valid_key_share_extension_wins() {
        let mut extensions = key_share_extension(&[0x11; 32]);
        extensions.extend_from_slice(&key_share_extension(&[0x22; 32]));
        let hello = client_hello(&[0xAB; 32], &extensions);
        assert_eq!(
            parse(&tls_record(&hello)).unwrap().key_share,
            Some([0x22; 32])
        );
    }

    #[test]
    fn a_later_empty_key_share_does_not_erase_an_earlier_one() {
        let mut extensions = key_share_extension(&[0x11; 32]);
        extensions.extend_from_slice(&key_share_extension(&[0x22; 31]));
        let hello = client_hello(&[0xAB; 32], &extensions);
        assert_eq!(
            parse(&tls_record(&hello)).unwrap().key_share,
            Some([0x11; 32])
        );
    }

    #[test]
    fn rejects_records_that_are_not_a_client_hello() {
        assert_eq!(parse(&[]), None);
        assert_eq!(
            parse(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00]),
            None
        );
        assert_eq!(parse(&[0x02, 0x00, 0x00, 0x00]), None);
    }

    #[test]
    fn a_truncated_hello_is_rejected_without_panicking() {
        let hello = client_hello(&[0xAB; 32], &key_share_extension(&[0xCD; 32]));
        let record = tls_record(&hello);
        for cut in 0..record.len() {
            let _ = parse(&record[..cut]);
        }
    }

    #[test]
    fn a_session_id_longer_than_the_buffer_is_truncated() {
        let mut hello = client_hello(&[0xAB; 32], &[]);
        hello[4 + 2 + 32] = 0xFF;
        assert_eq!(parse(&hello), None);
    }
}
