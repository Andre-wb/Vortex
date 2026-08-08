use sha2::{Digest, Sha256};

pub const TOKEN_LEN: usize = 6;
pub const TOKEN_HEX_LEN: usize = TOKEN_LEN * 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeToken([u8; TOKEN_LEN]);

impl ProbeToken {
    pub fn derive(name: &str) -> ProbeToken {
        let digest = Sha256::digest(name.as_bytes());
        let mut token = [0u8; TOKEN_LEN];
        token.copy_from_slice(&digest[..TOKEN_LEN]);
        ProbeToken(token)
    }

    pub fn parse(value: &str) -> Option<ProbeToken> {
        if value.len() != TOKEN_HEX_LEN || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let mut token = [0u8; TOKEN_LEN];
        hex::decode_to_slice(value, &mut token).ok()?;
        Some(ProbeToken(token))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; TOKEN_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{ProbeToken, TOKEN_HEX_LEN};

    #[test]
    fn the_token_is_the_head_of_the_digest_of_the_name() {
        assert_eq!(ProbeToken::derive("reality").to_hex(), "d7ac1d220e6a");
        assert_eq!(ProbeToken::derive("tor").to_hex().len(), TOKEN_HEX_LEN);
    }

    #[test]
    fn two_transports_never_share_a_token() {
        let reality = ProbeToken::derive("reality");
        let trojan = ProbeToken::derive("trojan");
        assert_ne!(reality, trojan);
    }

    #[test]
    fn a_token_survives_the_trip_through_its_text() {
        let token = ProbeToken::derive("shadowtls");
        assert_eq!(ProbeToken::parse(&token.to_hex()), Some(token));
    }

    #[test]
    fn anything_that_is_not_twelve_hex_digits_is_not_a_token() {
        assert_eq!(ProbeToken::parse(""), None);
        assert_eq!(ProbeToken::parse("d7ac1d220e6"), None);
        assert_eq!(ProbeToken::parse("d7ac1d220e6a0"), None);
        assert_eq!(ProbeToken::parse("0xd7ac1d220e"), None);
        assert_eq!(ProbeToken::parse("d7ac1d220e6g"), None);
        assert_eq!(ProbeToken::parse("d7ac_1d220e6"), None);
        assert_eq!(ProbeToken::parse(" d7ac1d220e6a "), None);
    }

    #[test]
    fn the_case_of_the_text_does_not_change_the_token() {
        assert_eq!(
            ProbeToken::parse("D7AC1D220E6A"),
            ProbeToken::parse("d7ac1d220e6a")
        );
    }
}
