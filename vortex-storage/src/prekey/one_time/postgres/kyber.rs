use async_trait::async_trait;

use crate::error::Result;
use crate::ids::{column_id, optional_column_id};
use crate::pool::handle::PgHandle;
use crate::prekey::one_time::key::OneTimeKey;
use crate::prekey::one_time::keys::OneTimeKeys;
use crate::time::stamp::Stamp;

#[derive(Debug, Clone)]
pub struct PgKyberKeys {
    handle: PgHandle,
}

impl PgKyberKeys {
    pub fn new(handle: PgHandle) -> PgKyberKeys {
        PgKyberKeys { handle }
    }
}

#[async_trait]
impl OneTimeKeys for PgKyberKeys {
    async fn add_many(
        &self,
        user_id: i64,
        device_id: Option<i64>,
        keys: &[OneTimeKey],
        at: Stamp,
    ) -> Result<u64> {
        if keys.is_empty() {
            return Ok(0);
        }
        let owner = column_id(user_id)?;
        let device = optional_column_id(device_id)?;
        let mut key_ids = Vec::with_capacity(keys.len());
        let mut publics = Vec::with_capacity(keys.len());
        for key in keys {
            key_ids.push(column_id(key.key_id)?);
            publics.push(key.public_key.clone());
        }
        let inserted = sqlx::query!(
            r#"
            INSERT INTO onetime_kyber_prekeys (
                user_id, device_id, key_id, public_key, used, created_at
            )
            SELECT $1, $2, added.key_id, added.public_key, false, $5
            FROM UNNEST($3::int4[], $4::bytea[]) AS added(key_id, public_key)
            "#,
            owner,
            device,
            &key_ids,
            &publics,
            at.reading()
        )
        .execute(self.handle.pool())
        .await?;
        Ok(inserted.rows_affected())
    }

    async fn take_one(&self, user_id: i64, device_id: Option<i64>) -> Result<Option<OneTimeKey>> {
        let owner = column_id(user_id)?;
        let device = optional_column_id(device_id)?;
        let taken = sqlx::query!(
            r#"
            UPDATE onetime_kyber_prekeys
            SET used = true
            WHERE id = (
                SELECT id
                FROM onetime_kyber_prekeys
                WHERE user_id = $1 AND device_id IS NOT DISTINCT FROM $2 AND used = false
                ORDER BY id
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING key_id, public_key
            "#,
            owner,
            device
        )
        .fetch_optional(self.handle.pool())
        .await?;
        Ok(taken.map(|row| OneTimeKey::new(i64::from(row.key_id), row.public_key)))
    }

    async fn available(&self, user_id: i64, device_id: Option<i64>) -> Result<i64> {
        let owner = column_id(user_id)?;
        let device = optional_column_id(device_id)?;
        let counted = sqlx::query!(
            r#"
            SELECT COUNT(*) AS "left!"
            FROM onetime_kyber_prekeys
            WHERE user_id = $1 AND device_id IS NOT DISTINCT FROM $2 AND used = false
            "#,
            owner,
            device
        )
        .fetch_one(self.handle.pool())
        .await?;
        Ok(counted.left)
    }
}
