pub mod local;
pub mod subnet;

pub use local::is_loopback;
pub use subnet::subnet_broadcast;

pub const GLOBAL_BROADCAST: &str = "255.255.255.255";
