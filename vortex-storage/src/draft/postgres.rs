use async_trait::async_trait;

use crate::draft::drafts::Drafts;
use crate::draft::record::DraftRecord;
use crate::error::Result;
use crate::ids::column_id;
use crate::pool::handle::PgHandle;
use crate::time::stamp::Stamp;

#[derive(Debug, Clone)]
pub struct PgDrafts {
    handle: PgHandle,
}

impl PgDrafts {
    pub fn new(handle: PgHandle) -> PgDrafts {
        PgDrafts { handle }
    }
}

#[async_trait]
impl Drafts for PgDrafts {
    async fn of_member(&self, user_id: i64, room_id: i64) -> Result<Option<DraftRecord>> {
        let owner = column_id(user_id)?;
        let room = column_id(room_id)?;
        let row = sqlx::query!(
            r#"
            SELECT text, updated_at
            FROM message_drafts
            WHERE user_id = $1 AND room_id = $2
            "#,
            owner,
            room
        )
        .fetch_optional(self.handle.pool())
        .await?;

        let epoch = Stamp::from_unix(0, 0)?;
        Ok(row.map(|row| DraftRecord {
            user_id,
            room_id,
            text: row.text,
            updated_at: row.updated_at.map(Stamp::from_reading).unwrap_or(epoch),
        }))
    }

    async fn save(&self, draft: &DraftRecord) -> Result<()> {
        let owner = column_id(draft.user_id)?;
        let room = column_id(draft.room_id)?;
        sqlx::query!(
            r#"
            INSERT INTO message_drafts (user_id, room_id, text, updated_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, room_id) DO UPDATE
            SET text = EXCLUDED.text,
                updated_at = EXCLUDED.updated_at
            "#,
            owner,
            room,
            draft.text,
            draft.updated_at.reading()
        )
        .execute(self.handle.pool())
        .await?;
        Ok(())
    }

    async fn clear(&self, user_id: i64, room_id: i64) -> Result<bool> {
        let owner = column_id(user_id)?;
        let room = column_id(room_id)?;
        let removed = sqlx::query!(
            r#"
            DELETE FROM message_drafts
            WHERE user_id = $1 AND room_id = $2
            "#,
            owner,
            room
        )
        .execute(self.handle.pool())
        .await?;
        Ok(removed.rows_affected() > 0)
    }

    async fn forget_untouched_since(&self, cutoff: Stamp) -> Result<u64> {
        let removed = sqlx::query!(
            r#"
            DELETE FROM message_drafts
            WHERE updated_at < $1
            "#,
            cutoff.reading()
        )
        .execute(self.handle.pool())
        .await?;
        Ok(removed.rows_affected())
    }
}
