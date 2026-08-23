#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimeKey {
    pub key_id: i64,
    pub public_key: Vec<u8>,
}

impl OneTimeKey {
    pub fn new(key_id: i64, public_key: impl Into<Vec<u8>>) -> OneTimeKey {
        OneTimeKey {
            key_id,
            public_key: public_key.into(),
        }
    }
}
