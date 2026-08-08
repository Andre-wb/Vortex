use sha2::{Digest, Sha224};
use subtle::{Choice, ConstantTimeEq};

pub const PASSWORD_HASH_LEN: usize = 28;
pub const PASSWORD_HASH_HEX_LEN: usize = PASSWORD_HASH_LEN * 2;

#[derive(Debug, Clone, Copy, Eq)]
pub struct PasswordHash([u8; PASSWORD_HASH_LEN]);

impl PasswordHash {
    pub fn derive(password: &[u8]) -> Option<Self> {
        if password.is_empty() {
            return None;
        }
        let mut bytes = [0u8; PASSWORD_HASH_LEN];
        bytes.copy_from_slice(&Sha224::digest(password));
        Some(PasswordHash(bytes))
    }

    pub fn parse_hex(digits: &[u8]) -> Option<Self> {
        if digits.len() != PASSWORD_HASH_HEX_LEN || !digits.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let mut bytes = [0u8; PASSWORD_HASH_LEN];
        hex::decode_to_slice(digits, &mut bytes).ok()?;
        Some(PasswordHash(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; PASSWORD_HASH_LEN] {
        &self.0
    }

    pub fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for PasswordHash {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(test)]
mod tests {
    use super::{PasswordHash, PASSWORD_HASH_HEX_LEN};

    #[test]
    fn an_empty_password_yields_no_hash_at_all() {
        assert_eq!(PasswordHash::derive(b""), None);
    }

    #[test]
    fn derivation_is_frozen() {
        assert_eq!(
            PasswordHash::derive(b"testpass").unwrap().to_hex(),
            "648db6019764b598f75ab6b7616d2e82563a00eb1531680e19ac4c6f"
        );
    }

    #[test]
    fn the_hex_a_client_sends_parses_back_to_the_derived_hash() {
        let derived = PasswordHash::derive(b"testpass").unwrap();
        assert_eq!(
            PasswordHash::parse_hex(derived.to_hex().as_bytes()),
            Some(derived)
        );
    }

    #[test]
    fn uppercase_hex_names_the_same_hash() {
        let derived = PasswordHash::derive(b"testpass").unwrap();
        let shouted = derived.to_hex().to_ascii_uppercase();
        assert_eq!(PasswordHash::parse_hex(shouted.as_bytes()), Some(derived));
    }

    #[test]
    fn only_fifty_six_hex_digits_parse() {
        let digits = vec![b'a'; PASSWORD_HASH_HEX_LEN];
        assert!(PasswordHash::parse_hex(&digits).is_some());
        assert!(PasswordHash::parse_hex(&digits[..PASSWORD_HASH_HEX_LEN - 1]).is_none());
        assert!(PasswordHash::parse_hex(b"").is_none());
    }

    #[test]
    fn what_python_called_hex_is_not_hex() {
        for candidate in [
            "0x8db6019764b598f75ab6b7616d2e82563a00eb1531680e19ac4c6f",
            "1_8db6019764b598f75ab6b7616d2e82563a00eb1531680e19ac4c6f",
            "+48db6019764b598f75ab6b7616d2e82563a00eb1531680e19ac4c6f",
            " 48db6019764b598f75ab6b7616d2e82563a00eb1531680e19ac4c6f",
        ] {
            assert_eq!(candidate.len(), PASSWORD_HASH_HEX_LEN);
            assert!(PasswordHash::parse_hex(candidate.as_bytes()).is_none());
        }
    }
}
