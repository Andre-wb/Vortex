use crate::ports::random_source::RandomSource;

pub const SALT_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSalt([u8; SALT_LEN]);

impl SessionSalt {
    pub fn generate(random: &dyn RandomSource) -> Self {
        let mut bytes = [0u8; SALT_LEN];
        random.fill_bytes(&mut bytes);
        SessionSalt(bytes)
    }

    pub fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        SessionSalt(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let salt: [u8; SALT_LEN] = bytes.try_into().ok()?;
        Some(SessionSalt(salt))
    }

    pub fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionSalt, SALT_LEN};
    use crate::random::fixed_random::FixedRandom;
    use crate::random::os_random::OsRandom;

    #[test]
    fn a_prologue_of_the_wrong_length_is_not_a_salt() {
        assert!(SessionSalt::parse(&[0x01; SALT_LEN - 1]).is_none());
        assert!(SessionSalt::parse(&[0x01; SALT_LEN + 1]).is_none());
        assert!(SessionSalt::parse(&[]).is_none());
        assert!(SessionSalt::parse(&[0x01; SALT_LEN]).is_some());
    }

    #[test]
    fn the_salt_is_the_bytes_it_was_given() {
        let random = FixedRandom::new(vec![0x0A; SALT_LEN]).with_filler(0x00);
        assert_eq!(SessionSalt::generate(&random).as_bytes(), &[0x0A; SALT_LEN]);
    }

    #[test]
    fn two_sessions_do_not_get_the_same_salt() {
        let random = OsRandom::new();
        assert_ne!(
            SessionSalt::generate(&random),
            SessionSalt::generate(&random)
        );
    }

    #[test]
    fn the_prologue_is_as_long_as_the_key_it_protects() {
        assert_eq!(SALT_LEN, 32);
    }
}
