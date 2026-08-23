use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use fred::prelude::*;

use crate::availability::Availability;
use crate::config::RedisConfig;
use crate::error::{BackboneError, Result};
use crate::keys::KeySpace;
use crate::runtime;

pub struct RedisBackbone {
    pool: Pool,
    config: RedisConfig,
    availability: Availability,
}

impl RedisBackbone {
    pub fn connect(config: RedisConfig) -> Result<Arc<Self>> {
        runtime::block_on(RedisBackbone::connect_async(config))
    }

    pub async fn connect_async(config: RedisConfig) -> Result<Arc<Self>> {
        if !config.is_configured() {
            return Err(BackboneError::Unconfigured);
        }

        let parsed =
            Config::from_url(&config.url).map_err(|err| BackboneError::Connect(err.to_string()))?;
        let command_timeout = Duration::from_secs(config.command_timeout_secs.max(1));
        let connect_timeout = Duration::from_secs(config.connect_timeout_secs.max(1));

        let pool = Builder::from_config(parsed)
            .with_connection_config(|connection| {
                connection.connection_timeout = connect_timeout;
                connection.internal_command_timeout = command_timeout;
            })
            .set_policy(ReconnectPolicy::new_exponential(0, 100, 5_000, 2))
            .build_pool(config.pool_size)
            .map_err(|err| BackboneError::Connect(err.to_string()))?;

        let opened = async {
            pool.init().await?;
            let _: () = pool.ping(None).await?;
            Ok::<(), Error>(())
        }
        .await;
        opened.map_err(|err| BackboneError::Connect(err.to_string()))?;

        let availability = Availability::new(Duration::from_secs(config.recovery_secs.max(1)));
        Ok(Arc::new(RedisBackbone {
            pool,
            config,
            availability,
        }))
    }

    pub fn config(&self) -> &RedisConfig {
        &self.config
    }

    pub fn key_space(&self, domain: &'static str) -> KeySpace {
        KeySpace::new(self.config.key_prefix.clone(), domain)
    }

    pub fn is_degraded(&self) -> bool {
        self.availability.is_degraded()
    }

    pub fn outages(&self) -> u64 {
        self.availability.failures()
    }

    pub fn execute<T, F, Fut>(&self, what: &str, operation: F) -> Result<T>
    where
        F: FnOnce(Pool) -> Fut,
        Fut: Future<Output = std::result::Result<T, Error>>,
    {
        runtime::block_on(self.execute_async(what, operation))
    }

    pub async fn execute_async<T, F, Fut>(&self, what: &str, operation: F) -> Result<T>
    where
        F: FnOnce(Pool) -> Fut,
        Fut: Future<Output = std::result::Result<T, Error>>,
    {
        if self.availability.is_degraded() {
            return Err(BackboneError::Degraded);
        }

        match operation(self.pool.clone()).await {
            Ok(value) => {
                self.availability.note_success();
                Ok(value)
            }
            Err(err) => {
                self.availability.note_failure();
                log::warn!("Redis: {what} не выполнено ({err}) — переход на память процесса");
                Err(BackboneError::Command(err.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RedisBackbone;
    use crate::config::RedisConfig;
    use crate::error::BackboneError;

    #[test]
    fn an_unconfigured_backbone_refuses_to_connect() {
        assert_eq!(
            RedisBackbone::connect(RedisConfig::default()).err(),
            Some(BackboneError::Unconfigured)
        );
    }

    #[test]
    fn a_malformed_url_is_reported_as_a_connection_error() {
        let error = RedisBackbone::connect(RedisConfig::new("not-a-url")).err();
        assert!(matches!(error, Some(BackboneError::Connect(_))));
    }
}
