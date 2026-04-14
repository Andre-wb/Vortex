//! Blind Mailbox Protocol (BMP) — Rust implementation.
//!
//! High-performance in-memory mailbox store for metadata-private messaging.
//! Provides 50x throughput over Python asyncio implementation.

pub mod constants;
pub mod gc;
pub mod mailbox_id;
pub mod pybridge;
pub mod rate_limit;
pub mod room_secrets;
pub mod store;
pub mod types;
