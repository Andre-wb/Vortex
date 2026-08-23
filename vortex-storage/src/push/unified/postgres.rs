use async_trait::async_trait;

use crate::error::Result;
use crate::ids::column_id;
use crate::pool::handle::PgHandle;
use crate::push::unified::directory::UnifiedPushDirectory;
use crate::push::unified::subscription::UnifiedSubscription;
use crate::time::stamp::Stamp;

#[derive(Debug, Clone)]
pub struct PgUnifiedPushDirectory {
    handle: PgHandle,
}

impl PgUnifiedPushDirectory {
    pub fn new(handle: PgHandle) -> PgUnifiedPushDirectory {
        PgUnifiedPushDirectory { handle }
    }
}

#[async_trait]
impl UnifiedPushDirectory for PgUnifiedPushDirectory {
    async fn of_user(&self, user_id: i64) -> Result<Vec<UnifiedSubscription>> {
        let owner = column_id(user_id)?;
        let rows = sqlx::query!(
            r#"
            SELECT endpoint, app_id, created_at, failures, active
            FROM unified_push_subscriptions
            WHERE user_id = $1
            ORDER BY id
            "#,
            owner
        )
        .fetch_all(self.handle.pool())
        .await?;

        let epoch = Stamp::from_unix(0, 0)?;
        Ok(rows
            .into_iter()
            .map(|row| UnifiedSubscription {
                user_id,
                endpoint: row.endpoint,
                app_id: row.app_id,
                created_at: row.created_at.map(Stamp::from_reading).unwrap_or(epoch),
                failures: i64::from(row.failures),
                active: row.active,
            })
            .collect())
    }

    async fn register(&self, subscription: &UnifiedSubscription) -> Result<()> {
        let owner = column_id(subscription.user_id)?;
        let failures = column_id(subscription.failures)?;
        sqlx::query!(
            r#"
            INSERT INTO unified_push_subscriptions (user_id, endpoint, app_id, created_at, failures, active)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (user_id, endpoint) DO UPDATE
            SET app_id = EXCLUDED.app_id,
                created_at = EXCLUDED.created_at,
                failures = EXCLUDED.failures,
                active = EXCLUDED.active
            "#,
            owner,
            subscription.endpoint,
            subscription.app_id,
            subscription.created_at.reading(),
            failures,
            subscription.active
        )
        .execute(self.handle.pool())
        .await?;
        Ok(())
    }

    async fn unregister(&self, user_id: i64, endpoint: &str) -> Result<bool> {
        let owner = column_id(user_id)?;
        let removed = sqlx::query!(
            r#"
            DELETE FROM unified_push_subscriptions
            WHERE user_id = $1 AND endpoint = $2
            "#,
            owner,
            endpoint
        )
        .execute(self.handle.pool())
        .await?;
        Ok(removed.rows_affected() > 0)
    }

    async fn record_delivery(
        &self,
        user_id: i64,
        endpoint: &str,
        failures: i64,
        active: bool,
    ) -> Result<()> {
        let owner = column_id(user_id)?;
        let counted = column_id(failures)?;
        sqlx::query!(
            r#"
            UPDATE unified_push_subscriptions
            SET failures = $3, active = $4
            WHERE user_id = $1 AND endpoint = $2
            "#,
            owner,
            endpoint,
            counted,
            active
        )
        .execute(self.handle.pool())
        .await?;
        Ok(())
    }
}
