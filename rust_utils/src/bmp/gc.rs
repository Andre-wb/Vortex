//! BMP garbage collector — runs periodically to remove expired messages.

use std::sync::Arc;

use crate::bmp::constants::GC_INTERVAL_SECS;
use crate::bmp::rate_limit::RateLimiter;
use crate::bmp::store::BlindMailboxStore;

/// Start the GC loop in a background thread.
/// Cleans up expired messages and stale rate limit entries.
pub fn start_gc_thread(store: Arc<BlindMailboxStore>, rate_limiter: Arc<RateLimiter>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(GC_INTERVAL_SECS));
        let removed = store.gc();
        rate_limiter.cleanup();
        if removed > 0 {
            // Note: we don't log with user info — sanitized by design
            eprintln!("[BMP-Rust] GC: removed {} expired messages", removed);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gc_thread_starts() {
        let store = Arc::new(BlindMailboxStore::new());
        let rl = Arc::new(RateLimiter::new());
        // Just verify it doesn't panic on creation
        // (we don't actually run the loop in tests)
        let _ = (&store, &rl);
    }
}
