use async_trait::async_trait;

use crate::error::Result;
use crate::prekey::one_time::key::OneTimeKey;
use crate::time::stamp::Stamp;

#[async_trait]
pub trait OneTimeKeys: Send + Sync {
    async fn add_many(
        &self,
        user_id: i64,
        device_id: Option<i64>,
        keys: &[OneTimeKey],
        at: Stamp,
    ) -> Result<u64>;

    async fn take_one(&self, user_id: i64, device_id: Option<i64>) -> Result<Option<OneTimeKey>>;

    async fn available(&self, user_id: i64, device_id: Option<i64>) -> Result<i64>;
}
