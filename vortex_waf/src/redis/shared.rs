//! Общий backbone WAF: подключается один раз на процесс до сборки движка.

use std::sync::Arc;

use parking_lot::RwLock;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

static BACKBONE: RwLock<Option<Arc<RedisBackbone>>> = RwLock::new(None);

pub fn backbone() -> Option<Arc<RedisBackbone>> {
    BACKBONE.read().clone()
}

pub fn is_shared() -> bool {
    BACKBONE.read().is_some()
}

pub fn connect(config: RedisConfig) -> Result<(), BackboneError> {
    let backbone = RedisBackbone::connect(config)?;
    *BACKBONE.write() = Some(backbone);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{backbone, is_shared};

    #[test]
    fn without_a_connection_the_engine_stays_in_process_memory() {
        assert!(backbone().is_none());
        assert!(!is_shared());
    }
}
