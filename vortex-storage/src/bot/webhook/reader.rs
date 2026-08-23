use async_trait::async_trait;

use crate::bot::webhook::record::WebhookRecord;
use crate::error::Result;

#[async_trait]
pub trait WebhookReader: Send + Sync {
    async fn of_bot(&self, bot_id: i64) -> Result<Option<WebhookRecord>>;
}
