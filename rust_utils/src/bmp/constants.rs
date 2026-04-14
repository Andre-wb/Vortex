//! BMP protocol constants.
//! Must match JavaScript (bmp-client.js) and Python (blind_mailbox.py) values exactly.

/// Mailbox ID rotation period (seconds). Each pair rotates hourly.
pub const ROTATION_PERIOD: u64 = 3600;

/// Per-pair rotation jitter range (0..ROTATION_JITTER seconds).
pub const ROTATION_JITTER: u16 = 600;

/// Clock skew tolerance: accept ±N epochs when computing mailbox IDs.
pub const CLOCK_SKEW_EPOCHS: i64 = 1;

/// Message time-to-live (seconds). Expired messages are garbage collected.
pub const TTL_SECONDS: u64 = 7200;

/// Maximum ciphertext size per deposit (bytes, before hex encoding).
pub const MAX_MSG_SIZE: usize = 65536;

/// Maximum messages stored per individual mailbox.
pub const MAX_MSGS_PER_BOX: usize = 200;

/// Maximum mailbox IDs per batch fetch request.
pub const MAX_BATCH: usize = 100;

/// Garbage collection interval (seconds).
pub const GC_INTERVAL_SECS: u64 = 300;

/// Standard rate limit: operations per IP per 60 seconds.
pub const RATE_LIMIT_PER_MIN: u32 = 600;

/// Fast-poll rate limit (for WebRTC signaling): operations per IP per 60 seconds.
pub const FAST_RATE_LIMIT: u32 = 3000;

/// Timestamp bucketing window (seconds) to prevent timing-based fingerprinting.
pub const TIMESTAMP_BUCKET_SECS: u64 = 300;
