use crate::trojan::request::header::{Header, CRLF};
use crate::trojan::secret::password_hash::PasswordHash;

pub fn encode(hash: &PasswordHash, header: &Header, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + payload.len());
    out.extend_from_slice(hash.to_hex().as_bytes());
    out.extend_from_slice(&CRLF);
    header.encode(&mut out);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::encode;
    use crate::trojan::request::header::Header;
    use crate::trojan::secret::password_hash::{PasswordHash, PASSWORD_HASH_HEX_LEN};

    fn hash() -> PasswordHash {
        PasswordHash::derive(b"testpass").unwrap()
    }

    #[test]
    fn the_hash_travels_as_lowercase_hex_in_front() {
        let request = encode(&hash(), &Header::connect("13.10.1.2", 443).unwrap(), b"");
        assert_eq!(
            &request[..PASSWORD_HASH_HEX_LEN],
            hash().to_hex().as_bytes()
        );
        assert_eq!(
            &request[PASSWORD_HASH_HEX_LEN..PASSWORD_HASH_HEX_LEN + 2],
            b"\r\n"
        );
    }

    #[test]
    fn the_payload_is_appended_untouched() {
        let payload = b"\x00\xff\r\nbinary";
        let request = encode(
            &hash(),
            &Header::connect("13.10.1.2", 443).unwrap(),
            payload,
        );
        assert_eq!(&request[request.len() - payload.len()..], payload);
    }

    #[test]
    fn the_frozen_shape_of_a_request_does_not_drift() {
        let request = encode(&hash(), &Header::connect("13.10.1.2", 443).unwrap(), b"hi");
        assert_eq!(
            hex::encode(&request[PASSWORD_HASH_HEX_LEN..]),
            "0d0a01010d0a010201bb0d0a6869"
        );
    }
}
