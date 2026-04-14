//! Per-IP rate limiter using DashMap for lock-free concurrent access.

use dashmap::DashMap;
use std::time::Instant;

use crate::bmp::constants::{FAST_RATE_LIMIT, RATE_LIMIT_PER_MIN};

/// Sliding window rate limiter. Tracks timestamps per IP.
pub struct RateLimiter {
    /// IP → list of request timestamps within the current window.
    counters: DashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self { counters: DashMap::new() }
    }

    /// Check if request is within rate limit. Returns true if allowed.
    pub fn check(&self, ip: &str, limit: u32) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(60);

        let mut entry = self.counters.entry(ip.to_string()).or_default();
        // Remove timestamps older than 60 seconds
        entry.retain(|ts| now.duration_since(*ts) < window);

        if entry.len() >= limit as usize {
            return false;
        }
        entry.push(now);
        true
    }

    /// Standard rate check (600/min).
    pub fn check_standard(&self, ip: &str) -> bool {
        self.check(ip, RATE_LIMIT_PER_MIN)
    }

    /// Fast-poll rate check (3000/min).
    pub fn check_fast(&self, ip: &str) -> bool {
        self.check(ip, FAST_RATE_LIMIT)
    }

    /// Periodic cleanup of stale entries. Call from GC.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(120);
        self.counters.retain(|_, v| {
            v.retain(|ts| now.duration_since(*ts) < window);
            !v.is_empty()
        });
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_under_limit() {
        let rl = RateLimiter::new();
        for _ in 0..10 {
            assert!(rl.check_standard("1.2.3.4"));
        }
    }

    #[test]
    fn test_blocks_over_limit() {
        let rl = RateLimiter::new();
        for _ in 0..600 {
            assert!(rl.check("1.2.3.4", 600));
        }
        assert!(!rl.check("1.2.3.4", 600)); // 601st blocked
    }

    #[test]
    fn test_different_ips_independent() {
        let rl = RateLimiter::new();
        for _ in 0..600 {
            rl.check("1.1.1.1", 600);
        }
        assert!(!rl.check("1.1.1.1", 600));
        assert!(rl.check("2.2.2.2", 600)); // Different IP still allowed
    }
}
