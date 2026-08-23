use async_trait::async_trait;

use crate::bot::inline::results::InlineResults;
use crate::error::Result;
use crate::ids::column_id;
use crate::pool::handle::PgHandle;
use crate::time::stamp::Stamp;

#[derive(Debug, Clone)]
pub struct PgInlineResults {
    handle: PgHandle,
}

impl PgInlineResults {
    pub fn new(handle: PgHandle) -> PgInlineResults {
        PgInlineResults { handle }
    }
}

#[async_trait]
impl InlineResults for PgInlineResults {
    async fn of_bot(&self, bot_id: i64) -> Result<Option<String>> {
        let bot = column_id(bot_id)?;
        let row = sqlx::query!(
            r#"
            SELECT results
            FROM bot_inline_results
            WHERE bot_id = $1
            "#,
            bot
        )
        .fetch_optional(self.handle.pool())
        .await?;
        Ok(row.map(|row| row.results.unwrap_or_else(|| "[]".to_owned())))
    }

    async fn remember(&self, bot_id: i64, results: &str, at: Stamp) -> Result<()> {
        let bot = column_id(bot_id)?;
        sqlx::query!(
            r#"
            INSERT INTO bot_inline_results (bot_id, results, updated_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (bot_id) DO UPDATE
            SET results = EXCLUDED.results,
                updated_at = EXCLUDED.updated_at
            "#,
            bot,
            results,
            at.reading()
        )
        .execute(self.handle.pool())
        .await?;
        Ok(())
    }

    async fn keep_newest(&self, ceiling: i64) -> Result<u64> {
        let dropped = sqlx::query!(
            r#"
            DELETE FROM bot_inline_results
            WHERE id IN (
                SELECT id
                FROM bot_inline_results
                ORDER BY updated_at DESC, id DESC
                OFFSET $1
            )
            "#,
            ceiling
        )
        .execute(self.handle.pool())
        .await?;
        Ok(dropped.rows_affected())
    }
}
