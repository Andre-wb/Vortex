//! Mailbox ID derivation with per-pair rotation jitter and clock skew tolerance.
//! Must produce identical output to JavaScript (bmp-client.js) and Python (blind_mailbox.py).

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::bmp::constants::{CLOCK_SKEW_EPOCHS, ROTATION_JITTER, ROTATION_PERIOD};

type HmacSha256 = Hmac<Sha256>;

/// Compute per-pair rotation jitter (0..599 seconds) from shared secret.
/// Each conversation pair rotates at a different time within the hour.
pub fn pair_jitter(secret_hex: &str) -> u16 {
    let secret = match hex::decode(secret_hex) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let mut mac = HmacSha256::new_from_slice(&secret).expect("HMAC key length");
    mac.update(b"jitter");
    let result = mac.finalize().into_bytes();
    ((result[0] as u16) << 8 | result[1] as u16) % ROTATION_JITTER
}

/// Compute a single mailbox ID for the given epoch.
fn compute_for_epoch(secret_bytes: &[u8], epoch: u64) -> String {
    let epoch_bytes = epoch.to_be_bytes();
    let mut mac = HmacSha256::new_from_slice(secret_bytes).expect("HMAC key length");
    mac.update(&epoch_bytes);
    let result = mac.finalize().into_bytes();
    hex::encode(&result[..16])
}

/// Compute mailbox ID from BMP secret with per-pair rotation jitter.
/// Returns a single 32-char hex string.
pub fn compute_mailbox_id(secret_hex: &str, timestamp: Option<f64>) -> String {
    let ts = timestamp.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    });
    let secret = match hex::decode(secret_hex) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let jitter = pair_jitter(secret_hex) as f64;
    let adjusted_ts = ts - jitter;
    let epoch = (adjusted_ts / ROTATION_PERIOD as f64) as u64;
    compute_for_epoch(&secret, epoch)
}

/// Compute mailbox IDs for current + adjacent epochs (clock skew tolerance).
/// Returns 3 IDs: [prev_epoch, current, next_epoch].
pub fn compute_mailbox_ids(secret_hex: &str, timestamp: Option<f64>) -> Vec<String> {
    let ts = timestamp.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    });
    let secret = match hex::decode(secret_hex) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let jitter = pair_jitter(secret_hex) as f64;
    let adjusted_ts = ts - jitter;
    let epoch = (adjusted_ts / ROTATION_PERIOD as f64) as i64;

    let mut ids = Vec::with_capacity(3);
    for e in (epoch - CLOCK_SKEW_EPOCHS)..=(epoch + CLOCK_SKEW_EPOCHS) {
        let safe_epoch = e.max(0) as u64;
        ids.push(compute_for_epoch(&secret, safe_epoch));
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pair_jitter_deterministic() {
        let secret = "a".repeat(64);
        let j1 = pair_jitter(&secret);
        let j2 = pair_jitter(&secret);
        assert_eq!(j1, j2);
        assert!(j1 < ROTATION_JITTER);
    }

    #[test]
    fn test_mailbox_id_length() {
        let secret = "ab".repeat(32);
        let id = compute_mailbox_id(&secret, Some(1000000.0));
        assert_eq!(id.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn test_different_epochs_different_ids() {
        let secret = "cd".repeat(32);
        let id1 = compute_mailbox_id(&secret, Some(0.0));
        let id2 = compute_mailbox_id(&secret, Some(7200.0)); // 2 hours later
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_clock_skew_returns_3_ids() {
        let secret = "ef".repeat(32);
        let ids = compute_mailbox_ids(&secret, Some(100000.0));
        assert_eq!(ids.len(), 3);
        // All should be unique (different epochs)
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
    }

    #[test]
    fn test_same_epoch_same_id() {
        let secret = "11".repeat(32);
        let id1 = compute_mailbox_id(&secret, Some(1000.0));
        let id2 = compute_mailbox_id(&secret, Some(1001.0)); // 1 second later, same epoch
        assert_eq!(id1, id2);
    }
}
