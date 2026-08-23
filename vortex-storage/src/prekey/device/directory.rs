use async_trait::async_trait;

use crate::error::Result;

#[async_trait]
pub trait DeviceDirectory: Send + Sync {
    async fn device_of(&self, user_id: i64, client_device_id: &str) -> Result<Option<i64>>;
}
