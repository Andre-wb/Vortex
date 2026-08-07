#[derive(Clone, Debug, PartialEq)]
pub struct FetchedMessage {
    ciphertext: String,
    bucketed_at: f64,
}

impl FetchedMessage {
    pub fn new(ciphertext: String, bucketed_at: f64) -> Self {
        FetchedMessage {
            ciphertext,
            bucketed_at,
        }
    }

    pub fn ciphertext(&self) -> &str {
        &self.ciphertext
    }

    pub fn bucketed_at(&self) -> f64 {
        self.bucketed_at
    }
}
