pub const DEFAULT_MIN_CIPHERTEXT_CHARS: usize = 24;
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 65536;
pub const DEFAULT_MAX_MESSAGES_PER_MAILBOX: usize = 200;
pub const DEFAULT_MAX_MAILBOXES: usize = 100_000;
pub const DEFAULT_MAX_STORED_BYTES: usize = 512 * 1024 * 1024;
pub const DEFAULT_TTL_SECS: f64 = 7200.0;
pub const DEFAULT_BUCKET_SECS: u64 = 300;
pub const DEFAULT_MAX_BATCH: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StorageConfig {
    pub min_ciphertext_chars: usize,
    pub max_message_bytes: usize,
    pub max_messages_per_mailbox: usize,
    pub max_mailboxes: usize,
    pub max_stored_bytes: usize,
    pub ttl_secs: f64,
    pub bucket_secs: u64,
    pub max_batch: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            min_ciphertext_chars: DEFAULT_MIN_CIPHERTEXT_CHARS,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_messages_per_mailbox: DEFAULT_MAX_MESSAGES_PER_MAILBOX,
            max_mailboxes: DEFAULT_MAX_MAILBOXES,
            max_stored_bytes: DEFAULT_MAX_STORED_BYTES,
            ttl_secs: DEFAULT_TTL_SECS,
            bucket_secs: DEFAULT_BUCKET_SECS,
            max_batch: DEFAULT_MAX_BATCH,
        }
    }
}

impl StorageConfig {
    pub fn new() -> Self {
        StorageConfig::default()
    }

    pub fn min_ciphertext_chars(mut self, chars: usize) -> Self {
        self.min_ciphertext_chars = chars;
        self
    }

    pub fn max_message_bytes(mut self, bytes: usize) -> Self {
        self.max_message_bytes = bytes;
        self
    }

    pub fn max_messages_per_mailbox(mut self, messages: usize) -> Self {
        self.max_messages_per_mailbox = messages;
        self
    }

    pub fn max_mailboxes(mut self, mailboxes: usize) -> Self {
        self.max_mailboxes = mailboxes;
        self
    }

    pub fn max_stored_bytes(mut self, bytes: usize) -> Self {
        self.max_stored_bytes = bytes;
        self
    }

    pub fn ttl_secs(mut self, seconds: f64) -> Self {
        self.ttl_secs = seconds;
        self
    }

    pub fn bucket_secs(mut self, seconds: u64) -> Self {
        self.bucket_secs = seconds;
        self
    }

    pub fn max_batch(mut self, mailboxes: usize) -> Self {
        self.max_batch = mailboxes;
        self
    }

    pub fn max_ciphertext_chars(&self) -> usize {
        self.max_message_bytes * 2
    }
}

#[cfg(test)]
mod tests {
    use super::StorageConfig;

    #[test]
    fn the_defaults_match_the_python_module() {
        let config = StorageConfig::default();
        assert_eq!(config.min_ciphertext_chars, 24);
        assert_eq!(config.max_message_bytes, 64 * 1024);
        assert_eq!(config.max_messages_per_mailbox, 200);
        assert_eq!(config.ttl_secs, 7200.0);
        assert_eq!(config.bucket_secs, 300);
        assert_eq!(config.max_batch, 100);
    }

    #[test]
    fn a_deposit_is_measured_in_hex_characters() {
        assert_eq!(StorageConfig::default().max_ciphertext_chars(), 131072);
    }
}
