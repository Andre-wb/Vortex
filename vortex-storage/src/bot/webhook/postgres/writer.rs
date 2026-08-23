use async_trait::async_trait;

use crate::bot::webhook::record::WebhookRecord;
use crate::bot::webhook::writer::WebhookWriter;
use crate::error::Result;
use crate::ids::column_id;
use crate::pool::handle::PgHandle;

#[derive(Debug, Clone)]
pub struct PgWebhookWriter {
    handle: PgHandle,
}

impl PgWebhookWriter {
    pub fn new(handle: PgHandle) -> PgWebhookWriter {
        PgWebhookWriter { handle }
    }
}

#[async_trait]
impl WebhookWriter for PgWebhookWriter {
    async fn save(&self, webhook: &WebhookRecord) -> Result<()> {
        let bot = column_id(webhook.bot_id)?;
        sqlx::query!(
            r#"
            INSERT INTO bot_webhooks (bot_id, url, secret, events, created_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (bot_id) DO UPDATE
            SET url = EXCLUDED.url,
                secret = EXCLUDED.secret,
                events = EXCLUDED.events,
                created_at = EXCLUDED.created_at
            "#,
            bot,
            webhook.url,
            webhook.secret,
            webhook.events,
            webhook.created_at.reading()
        )
        .execute(self.handle.pool())
        .await?;
        Ok(())
    }

    async fn forget(&self, bot_id: i64) -> Result<bool> {
        let bot = column_id(bot_id)?;
        let removed = sqlx::query!(
            r#"
            DELETE FROM bot_webhooks
            WHERE bot_id = $1
            "#,
            bot
        )
        .execute(self.handle.pool())
        .await?;
        Ok(removed.rows_affected() > 0)
    }
}
