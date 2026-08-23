pub const SESSION_LIFETIME_SECONDS: f64 = 24.0 * 3600.0;

pub const DEFAULT_CHUNK_BYTES: u64 = 1024 * 1024;
pub const MIN_CHUNK_BYTES: u64 = 64 * 1024;
pub const MAX_CHUNK_BYTES: u64 = 10 * 1024 * 1024;

pub const MAX_CHUNKS: u32 = 10_240;

pub const MAX_IDENTIFIER_LENGTH: usize = 64;
pub const MAX_FILE_NAME_LENGTH: usize = 255;
