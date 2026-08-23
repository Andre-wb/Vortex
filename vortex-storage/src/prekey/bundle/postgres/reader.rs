use async_trait::async_trait;

use crate::error::Result;
use crate::ids::{column_id, optional_column_id};
use crate::pool::handle::PgHandle;
use crate::prekey::bundle::postgres::row::BundleRow;
use crate::prekey::bundle::reader::BundleReader;
use crate::prekey::bundle::record::BundleRecord;

#[derive(Debug, Clone)]
pub struct PgBundleReader {
    handle: PgHandle,
}

impl PgBundleReader {
    pub fn new(handle: PgHandle) -> PgBundleReader {
        PgBundleReader { handle }
    }
}

#[async_trait]
impl BundleReader for PgBundleReader {
    async fn newest_of_user(&self, user_id: i64) -> Result<Option<BundleRecord>> {
        let owner = column_id(user_id)?;
        let row = sqlx::query_as!(
            BundleRow,
            r#"
            SELECT id, user_id, device_id, identity_key, signed_prekey, signed_prekey_sig,
                   signed_prekey_id, identity_key_ed, identity_key_sig, supports_v2,
                   device_x3dh_pub, device_sign_pub, device_cert_sig, client_device_id,
                   device_kyber_pub, device_kyber_sig, device_kyber_id, created_at, updated_at
            FROM prekey_bundles
            WHERE user_id = $1
            ORDER BY updated_at DESC, id DESC
            LIMIT 1
            "#,
            owner
        )
        .fetch_optional(self.handle.pool())
        .await?;
        Ok(row.map(BundleRow::into_record))
    }

    async fn of_device(
        &self,
        user_id: i64,
        device_id: Option<i64>,
    ) -> Result<Option<BundleRecord>> {
        let owner = column_id(user_id)?;
        let device = optional_column_id(device_id)?;
        let row = sqlx::query_as!(
            BundleRow,
            r#"
            SELECT id, user_id, device_id, identity_key, signed_prekey, signed_prekey_sig,
                   signed_prekey_id, identity_key_ed, identity_key_sig, supports_v2,
                   device_x3dh_pub, device_sign_pub, device_cert_sig, client_device_id,
                   device_kyber_pub, device_kyber_sig, device_kyber_id, created_at, updated_at
            FROM prekey_bundles
            WHERE user_id = $1 AND device_id IS NOT DISTINCT FROM $2
            ORDER BY id
            LIMIT 1
            "#,
            owner,
            device
        )
        .fetch_optional(self.handle.pool())
        .await?;
        Ok(row.map(BundleRow::into_record))
    }

    async fn all_of_user(&self, user_id: i64) -> Result<Vec<BundleRecord>> {
        let owner = column_id(user_id)?;
        let rows = sqlx::query_as!(
            BundleRow,
            r#"
            SELECT id, user_id, device_id, identity_key, signed_prekey, signed_prekey_sig,
                   signed_prekey_id, identity_key_ed, identity_key_sig, supports_v2,
                   device_x3dh_pub, device_sign_pub, device_cert_sig, client_device_id,
                   device_kyber_pub, device_kyber_sig, device_kyber_id, created_at, updated_at
            FROM prekey_bundles
            WHERE user_id = $1
            ORDER BY device_id, id
            "#,
            owner
        )
        .fetch_all(self.handle.pool())
        .await?;
        Ok(rows.into_iter().map(BundleRow::into_record).collect())
    }
}
