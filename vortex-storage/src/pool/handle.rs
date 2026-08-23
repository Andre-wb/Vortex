use std::time::Duration;

use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::config::dsn::PgConfig;
use crate::error::{Result, StorageError};

#[derive(Debug, Clone)]
pub struct PgHandle {
    pool: PgPool,
}

impl PgHandle {
    pub async fn connect(config: &PgConfig) -> Result<PgHandle> {
        if !config.is_configured() {
            return Err(StorageError::Unconfigured);
        }
        let pool = PgPoolOptions::new()
            .max_connections(config.pool_size)
            .acquire_timeout(Duration::from_secs(config.connect_timeout_secs))
            .connect(config.url.trim())
            .await
            .map_err(|error| StorageError::Connect(error.to_string()))?;
        Ok(PgHandle { pool })
    }

    pub fn from_pool(pool: PgPool) -> PgHandle {
        PgHandle { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::PgHandle;
    use crate::config::dsn::PgConfig;
    use crate::error::StorageError;

    #[test]
    fn connecting_without_a_url_is_refused_before_any_socket_is_opened() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("рантайм не поднялся");
        let refusal = runtime.block_on(async {
            PgHandle::connect(&PgConfig::default())
                .await
                .map(|_| ())
                .unwrap_err()
        });
        assert_eq!(refusal, StorageError::Unconfigured);
    }
}
