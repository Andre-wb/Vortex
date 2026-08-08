use crate::ports::random_source::RandomSource;

pub const SESSION_ID_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionId([u8; SESSION_ID_LEN]);

impl SessionId {
    pub fn from_bytes(bytes: [u8; SESSION_ID_LEN]) -> Self {
        SessionId(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(SessionId)
    }

    pub fn generate(random: &dyn RandomSource) -> Self {
        let mut bytes = [0u8; SESSION_ID_LEN];
        random.fill_bytes(&mut bytes);
        SessionId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SESSION_ID_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionId, SESSION_ID_LEN};
    use crate::random::fixed_random::FixedRandom;

    #[test]
    fn takes_its_bytes_from_the_random_source() {
        let random = FixedRandom::new(vec![]).with_filler(0x5A);
        assert_eq!(
            SessionId::generate(&random),
            SessionId::from_bytes([0x5A; SESSION_ID_LEN])
        );
    }

    #[test]
    fn only_an_exact_length_parses() {
        assert!(SessionId::parse(&[0x01; SESSION_ID_LEN]).is_some());
        assert!(SessionId::parse(&[0x01; SESSION_ID_LEN - 1]).is_none());
        assert!(SessionId::parse(&[0x01; SESSION_ID_LEN + 1]).is_none());
        assert!(SessionId::parse(&[]).is_none());
    }
}
