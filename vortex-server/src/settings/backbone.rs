use vortex_redis::config::{RedisConfig, DEFAULT_KEY_PREFIX, DEFAULT_POOL_SIZE};

use crate::settings::environment;

pub fn from_environment() -> RedisConfig {
    let url = environment::text_or("REDIS_URL", "");
    let pool_size = environment::text("REDIS_POOL_SIZE")
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_POOL_SIZE);
    let prefix = environment::text_or("REDIS_CHANNEL_PREFIX", DEFAULT_KEY_PREFIX);
    RedisConfig::new(url)
        .pool_size(pool_size)
        .key_prefix(prefix)
}

#[cfg(test)]
mod tests {
    use super::from_environment;

    #[test]
    fn an_unset_url_leaves_the_node_in_single_process_mode() {
        std::env::remove_var("REDIS_URL");
        assert!(!from_environment().is_configured());
    }
}
