use crate::reality::auth::sealed_auth::X25519_KEY_LEN;
use crate::tls::byte_slice::{be_uint, clamped};

pub const EXTENSION_KEY_SHARE: usize = 0x0033;
pub const GROUP_X25519: usize = 0x001D;

pub fn x25519_from_extension(body: &[u8]) -> Option<[u8; X25519_KEY_LEN]> {
    let mut pos = 2usize;
    while pos + 4 <= body.len() {
        let group = be_uint(body, pos, 2);
        let key_len = be_uint(body, pos + 2, 2);
        let key = clamped(body, pos + 4, key_len);
        pos += 4 + key_len;
        if group == GROUP_X25519 && key.len() == X25519_KEY_LEN {
            return key.try_into().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::x25519_from_extension;

    fn entry(group: u16, key: &[u8]) -> Vec<u8> {
        let mut out = group.to_be_bytes().to_vec();
        out.extend_from_slice(&(key.len() as u16).to_be_bytes());
        out.extend_from_slice(key);
        out
    }

    fn extension(entries: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = entries.concat();
        let mut out = (payload.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&payload);
        out
    }

    #[test]
    fn finds_the_x25519_entry_among_others() {
        let body = extension(&[
            entry(0x0017, &[0x01; 65]),
            entry(0x001D, &[0x02; 32]),
            entry(0x0100, &[0x03; 1216]),
        ]);
        assert_eq!(x25519_from_extension(&body), Some([0x02; 32]));
    }

    #[test]
    fn ignores_an_x25519_entry_of_the_wrong_size() {
        let body = extension(&[entry(0x001D, &[0x02; 31])]);
        assert_eq!(x25519_from_extension(&body), None);
    }

    #[test]
    fn returns_nothing_when_no_group_matches() {
        let body = extension(&[entry(0x0017, &[0x01; 65])]);
        assert_eq!(x25519_from_extension(&body), None);
    }

    #[test]
    fn a_truncated_entry_stops_the_walk() {
        let body = vec![0x00, 0x24, 0x00, 0x1D, 0x00];
        assert_eq!(x25519_from_extension(&body), None);
    }
}
