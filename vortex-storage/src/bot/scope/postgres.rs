use async_trait::async_trait;

use crate::bot::scope::grants::ScopeGrants;
use crate::error::Result;
use crate::ids::column_id;
use crate::pool::handle::PgHandle;

#[derive(Debug, Clone)]
pub struct PgScopeGrants {
    handle: PgHandle,
}

impl PgScopeGrants {
    pub fn new(handle: PgHandle) -> PgScopeGrants {
        PgScopeGrants { handle }
    }
}

#[async_trait]
impl ScopeGrants for PgScopeGrants {
    async fn granted_to(&self, bot_id: i64) -> Result<Vec<String>> {
        let bot = column_id(bot_id)?;
        let rows = sqlx::query!(
            r#"
            SELECT scope
            FROM bot_scopes
            WHERE bot_id = $1
            ORDER BY id
            "#,
            bot
        )
        .fetch_all(self.handle.pool())
        .await?;
        Ok(rows.into_iter().map(|row| row.scope).collect())
    }

    async fn replace(&self, bot_id: i64, scopes: &[String]) -> Result<()> {
        let bot = column_id(bot_id)?;
        let mut transaction = self.handle.pool().begin().await?;

        sqlx::query!(
            r#"
            DELETE FROM bot_scopes
            WHERE bot_id = $1
            "#,
            bot
        )
        .execute(&mut *transaction)
        .await?;

        if !scopes.is_empty() {
            sqlx::query!(
                r#"
                INSERT INTO bot_scopes (bot_id, scope)
                SELECT $1, granted.scope
                FROM UNNEST($2::varchar[]) AS granted(scope)
                ON CONFLICT (bot_id, scope) DO NOTHING
                "#,
                bot,
                scopes
            )
            .execute(&mut *transaction)
            .await?;
        }

        transaction.commit().await?;
        Ok(())
    }
}
