#[derive(Clone, Debug, PartialEq)]
pub struct StoredMessage {
    ciphertext: String,
    deposited_at: f64,
}

impl StoredMessage {
    pub fn new(ciphertext: String, deposited_at: f64) -> Self {
        StoredMessage {
            ciphertext,
            deposited_at,
        }
    }

    pub fn ciphertext(&self) -> &str {
        &self.ciphertext
    }

    pub fn deposited_at(&self) -> f64 {
        self.deposited_at
    }

    pub fn stored_bytes(&self) -> usize {
        self.ciphertext.len()
    }

    pub fn is_visible_at(&self, now: f64, since: f64, ttl_secs: f64) -> bool {
        self.deposited_at > since && (now - self.deposited_at) < ttl_secs
    }

    pub fn is_expired_at(&self, now: f64, ttl_secs: f64) -> bool {
        (now - self.deposited_at) >= ttl_secs
    }
}

#[cfg(test)]
mod tests {
    use super::StoredMessage;

    const TTL: f64 = 7200.0;

    fn message(deposited_at: f64) -> StoredMessage {
        StoredMessage::new("aabb".to_string(), deposited_at)
    }

    #[test]
    fn a_message_is_visible_until_the_ttl_elapses() {
        assert!(message(1000.0).is_visible_at(1000.0 + TTL - 0.5, 0.0, TTL));
        assert!(!message(1000.0).is_visible_at(1000.0 + TTL, 0.0, TTL));
    }

    #[test]
    fn a_message_at_or_before_the_since_mark_is_hidden() {
        assert!(!message(1000.0).is_visible_at(1000.0, 1000.0, TTL));
        assert!(message(1000.0).is_visible_at(1000.0, 999.9, TTL));
    }

    #[test]
    fn expiry_and_visibility_agree_on_the_ttl_boundary() {
        let msg = message(1000.0);
        assert!(!msg.is_expired_at(1000.0 + TTL - 0.5, TTL));
        assert!(msg.is_expired_at(1000.0 + TTL, TTL));
    }

    #[test]
    fn the_stored_size_counts_the_ciphertext_characters() {
        assert_eq!(message(0.0).stored_bytes(), 4);
    }
}
