use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use vortex_redis::backbone::RedisBackbone;
use vortex_redis::config::RedisConfig;

pub const DEFAULT_TEST_URL: &str = "redis://127.0.0.1:6379/9";

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn unique_prefix(suite: &str) -> String {
    let index = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    format!("vortex-test:{suite}:{pid}:{index}")
}

pub fn backbone(prefix: &str) -> Option<Arc<RedisBackbone>> {
    let required = std::env::var("VORTEX_TEST_REDIS_URL").ok();
    let url = required
        .clone()
        .unwrap_or_else(|| DEFAULT_TEST_URL.to_string());
    let config = RedisConfig::new(url.clone()).key_prefix(prefix.to_string());

    match RedisBackbone::connect(config) {
        Ok(backbone) => Some(backbone),
        Err(error) if required.is_some() => {
            panic!("VORTEX_TEST_REDIS_URL={url} задан, но Redis недоступен: {error}")
        }
        Err(error) => {
            eprintln!("Redis по адресу {url} недоступен ({error}) — проверка пропущена");
            None
        }
    }
}
