//! Blind Mailbox Store — the core in-memory message store.
//! Thread-safe via parking_lot::RwLock for maximum throughput.

use std::collections::HashMap;

use parking_lot::RwLock;
use sha2::{Digest, Sha256};

use crate::bmp::constants::{MAX_MSG_SIZE, MAX_MSGS_PER_BOX, TIMESTAMP_BUCKET_SECS, TTL_SECONDS};
use crate::bmp::mailbox_id::compute_mailbox_ids;
use crate::bmp::room_secrets::RoomSecretStore;
use crate::bmp::types::{BmpStats, MailboxMessage};

/// In-memory blind mailbox store.
/// Design: server stores ONLY mailbox_id → [messages].
/// No user IDs, no room IDs — complete metadata privacy.
pub struct BlindMailboxStore {
    boxes: RwLock<HashMap<String, Vec<MailboxMessage>>>,
    total_deposited: RwLock<u64>,
    total_fetched: RwLock<u64>,
    total_expired: RwLock<u64>,
}

impl BlindMailboxStore {
    pub fn new() -> Self {
        Self {
            boxes: RwLock::new(HashMap::new()),
            total_deposited: RwLock::new(0),
            total_fetched: RwLock::new(0),
            total_expired: RwLock::new(0),
        }
    }

    /// Deposit an encrypted message into a mailbox. Returns true on success.
    pub fn deposit(&self, mailbox_id: &str, ciphertext: &str) -> bool {
        if ciphertext.len() > MAX_MSG_SIZE * 2 {
            return false; // hex = 2x bytes
        }

        let msg = MailboxMessage::new(ciphertext.to_string());
        let mut boxes = self.boxes.write();
        let box_msgs = boxes.entry(mailbox_id.to_string()).or_default();

        // Enforce per-box limit
        if box_msgs.len() >= MAX_MSGS_PER_BOX {
            box_msgs.remove(0); // remove oldest
        }

        box_msgs.push(msg);
        *self.total_deposited.write() += 1;
        true
    }

    /// Fetch messages from a single mailbox since a timestamp.
    pub fn fetch(&self, mailbox_id: &str, since_ts: f64) -> Vec<(String, f64)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let boxes = self.boxes.read();
        let Some(box_msgs) = boxes.get(mailbox_id) else {
            *self.total_fetched.write() += 1;
            return vec![];
        };

        let result: Vec<(String, f64)> = box_msgs
            .iter()
            .filter(|m| m.timestamp > since_ts && (now - m.timestamp) < TTL_SECONDS as f64)
            .map(|m| {
                // Bucket timestamp to TIMESTAMP_BUCKET_SECS windows
                let bucketed = (m.timestamp as u64 / TIMESTAMP_BUCKET_SECS * TIMESTAMP_BUCKET_SECS) as f64;
                (m.ciphertext.clone(), bucketed)
            })
            .collect();

        *self.total_fetched.write() += 1;
        result
    }

    /// Fetch messages from multiple mailboxes in one call.
    /// Returns HashMap<mailbox_id, Vec<(ciphertext, bucketed_timestamp)>>.
    /// Only includes mailboxes that have messages (empty = omitted).
    pub fn fetch_batch(
        &self,
        mailbox_ids: &[String],
        since_ts: f64,
    ) -> HashMap<String, Vec<(String, f64)>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let boxes = self.boxes.read();
        let mut result = HashMap::new();

        for mb_id in mailbox_ids.iter().take(crate::bmp::constants::MAX_BATCH) {
            if let Some(box_msgs) = boxes.get(mb_id.as_str()) {
                let msgs: Vec<(String, f64)> = box_msgs
                    .iter()
                    .filter(|m| m.timestamp > since_ts && (now - m.timestamp) < TTL_SECONDS as f64)
                    .map(|m| {
                        let bucketed =
                            (m.timestamp as u64 / TIMESTAMP_BUCKET_SECS * TIMESTAMP_BUCKET_SECS) as f64;
                        (m.ciphertext.clone(), bucketed)
                    })
                    .collect();

                if !msgs.is_empty() {
                    result.insert(mb_id.clone(), msgs);
                }
            }
        }

        *self.total_fetched.write() += 1;
        result
    }

    /// Garbage collect expired messages. Returns count removed.
    pub fn gc(&self) -> u64 {
        let mut boxes = self.boxes.write();
        let mut removed: u64 = 0;

        boxes.retain(|_, msgs| {
            let before = msgs.len();
            msgs.retain(|m| !m.is_expired(TTL_SECONDS));
            removed += (before - msgs.len()) as u64;
            !msgs.is_empty()
        });

        *self.total_expired.write() += removed;
        removed
    }

    /// Get store statistics.
    pub fn stats(&self) -> BmpStats {
        let boxes = self.boxes.read();
        let total_messages: usize = boxes.values().map(|v| v.len()).sum();
        BmpStats {
            active_mailboxes: boxes.len(),
            total_messages,
            total_deposited: *self.total_deposited.read(),
            total_fetched: *self.total_fetched.read(),
            total_expired: *self.total_expired.read(),
        }
    }

    /// Deposit an envelope for a room (looks up secret, computes mailbox IDs).
    /// Returns true if at least one deposit succeeded.
    pub fn deposit_envelope(
        &self,
        room_id: i64,
        envelope_data: &str,
        secrets: &RoomSecretStore,
    ) -> bool {
        let secret = match secrets.get(room_id) {
            Some(s) => s,
            None => return false,
        };

        let mailbox_ids = compute_mailbox_ids(&secret, None);
        let mut ok = false;
        for mb_id in &mailbox_ids {
            if self.deposit(mb_id, envelope_data) {
                ok = true;
            }
        }
        ok
    }

    /// Compute push wake signal category for a mailbox ID.
    /// SHA256(mailbox_id) mod 256.
    pub fn wake_category(mailbox_id: &str) -> u8 {
        let hash = Sha256::digest(mailbox_id.as_bytes());
        hash[0]
    }
}

impl Default for BlindMailboxStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deposit_and_fetch() {
        let store = BlindMailboxStore::new();
        assert!(store.deposit("box1", "aabbccdd"));
        let msgs = store.fetch("box1", 0.0);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, "aabbccdd");
    }

    #[test]
    fn test_fetch_empty() {
        let store = BlindMailboxStore::new();
        let msgs = store.fetch("nonexistent", 0.0);
        assert!(msgs.is_empty());
    }

    #[test]
    fn test_max_size_rejected() {
        let store = BlindMailboxStore::new();
        let big = "a".repeat(MAX_MSG_SIZE * 2 + 2);
        assert!(!store.deposit("box1", &big));
    }

    #[test]
    fn test_per_box_limit() {
        let store = BlindMailboxStore::new();
        for i in 0..250 {
            store.deposit("box1", &format!("msg{}", i));
        }
        let msgs = store.fetch("box1", 0.0);
        assert_eq!(msgs.len(), MAX_MSGS_PER_BOX);
    }

    #[test]
    fn test_batch_fetch() {
        let store = BlindMailboxStore::new();
        store.deposit("a", "msg_a");
        store.deposit("b", "msg_b");

        let ids = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let result = store.fetch_batch(&ids, 0.0);
        assert_eq!(result.len(), 2); // "c" is empty → omitted
        assert!(result.contains_key("a"));
        assert!(result.contains_key("b"));
    }

    #[test]
    fn test_gc() {
        let store = BlindMailboxStore::new();
        // Insert with past timestamp (manually)
        {
            let mut boxes = store.boxes.write();
            boxes.entry("old".to_string()).or_default().push(MailboxMessage {
                ciphertext: "expired".to_string(),
                timestamp: 0.0, // Unix epoch = definitely expired
                size: 7,
            });
        }
        let removed = store.gc();
        assert_eq!(removed, 1);
        assert!(store.fetch("old", 0.0).is_empty());
    }

    #[test]
    fn test_stats() {
        let store = BlindMailboxStore::new();
        store.deposit("a", "111");
        store.deposit("a", "222");
        store.deposit("b", "333");
        let s = store.stats();
        assert_eq!(s.active_mailboxes, 2);
        assert_eq!(s.total_messages, 3);
        assert_eq!(s.total_deposited, 3);
    }

    #[test]
    fn test_wake_category() {
        let cat = BlindMailboxStore::wake_category("test_mailbox_id");
        assert!(cat <= 255); // u8 always true, but validates the function runs
    }
}
