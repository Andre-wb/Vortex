use async_trait::async_trait;

use crate::bot::webhook::postgres::row::WebhookRow;
use crate::bot::webhook::reader::WebhookReader;
use crate::bot::webhook::record::WebhookRecord;
use crate::error::Result;
use crate::ids::column_id;
use crate::pool::handle::PgHandle;
use crate::time::stamp::Stamp;

#[derive(Debug, Clone)]
pub struct PgWebhookReader {
    handle: PgHandle,
}

impl PgWebhookReader {
    pub fn new(handle: PgHandle) -> PgWebhookReader {
        PgWebhookReader { handle }
    }
}

#[async_trait]
impl WebhookReader for PgWebhookReader {
    async fn of_bot(&self, bot_id: i64) -> Result<Option<WebhookRecord>> {
        let bot = column_id(bot_id)?;
        let row = sqlx::query_as!(
            WebhookRow,
            r#"
            SELECT bot_id, url, secret, events, created_at
            FROM bot_webhooks
            WHERE bot_id = $1
            "#,
            bot
        )
        .fetch_optional(self.handle.pool())
        .await?;
        let epoch = Stamp::from_unix(0, 0)?;
        Ok(row.map(|row| row.into_record(epoch)))
    }
}
