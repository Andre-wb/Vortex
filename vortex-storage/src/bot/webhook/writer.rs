use async_trait::async_trait;

use crate::bot::webhook::record::WebhookRecord;
use crate::error::Result;

#[async_trait]
pub trait WebhookWriter: Send + Sync {
    async fn save(&self, webhook: &WebhookRecord) -> Result<()>;

    async fn forget(&self, bot_id: i64) -> Result<bool>;
}
