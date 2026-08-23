pub mod envelope;
pub mod key;
pub mod port;

pub use envelope::{open, seal, seal_with};
pub use key::derive_key;
pub use port::stealth_udp_port;

pub const NONCE_LEN: usize = 8;
pub const KEY_LEN: usize = 32;
pub const MIN_ENVELOPE_LEN: usize = NONCE_LEN + 1;
