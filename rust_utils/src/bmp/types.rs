//! BMP data types.

use std::time::SystemTime;

/// A single message stored in a blind mailbox.
#[derive(Clone, Debug)]
pub struct MailboxMessage {
    /// Hex-encoded encrypted payload.
    pub ciphertext: String,
    /// Unix timestamp (seconds since epoch) when deposited.
    pub timestamp: f64,
    /// Payload size in bytes (ciphertext.len() / 2).
    pub size: usize,
}

impl MailboxMessage {
    pub fn new(ciphertext: String) -> Self {
        let size = ciphertext.len() / 2;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self { ciphertext, timestamp, size }
    }

    /// Check if this message has expired.
    pub fn is_expired(&self, ttl_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        (now - self.timestamp) >= ttl_secs as f64
    }
}

/// Statistics about the BMP store.
#[derive(Clone, Debug, Default)]
pub struct BmpStats {
    pub active_mailboxes: usize,
    pub total_messages: usize,
    pub total_deposited: u64,
    pub total_fetched: u64,
    pub total_expired: u64,
}
