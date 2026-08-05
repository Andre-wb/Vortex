//! Ограничение частоты запросов.

pub mod config;
pub mod sliding_window;
pub mod unlimited;

pub use config::RateLimitConfig;
pub use sliding_window::SlidingWindowRateLimiter;
pub use unlimited::UnlimitedRateLimiter;
