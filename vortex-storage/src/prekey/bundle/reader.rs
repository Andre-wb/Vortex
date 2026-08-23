use async_trait::async_trait;

use crate::error::Result;
use crate::prekey::bundle::record::BundleRecord;

#[async_trait]
pub trait BundleReader: Send + Sync {
    async fn newest_of_user(&self, user_id: i64) -> Result<Option<BundleRecord>>;

    async fn of_device(&self, user_id: i64, device_id: Option<i64>)
        -> Result<Option<BundleRecord>>;

    async fn all_of_user(&self, user_id: i64) -> Result<Vec<BundleRecord>>;
}
