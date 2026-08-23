use async_trait::async_trait;
use vortex_proto::prekey::bundle::stored::StoredBundle;

use crate::error::Result;
use crate::ids::{column_id, optional_column_id};
use crate::pool::handle::PgHandle;
use crate::prekey::bundle::writer::{BundleWriter, SaveOutcome};
use crate::time::stamp::Stamp;

#[derive(Debug, Clone)]
pub struct PgBundleWriter {
    handle: PgHandle,
}

impl PgBundleWriter {
    pub fn new(handle: PgHandle) -> PgBundleWriter {
        PgBundleWriter { handle }
    }
}

#[async_trait]
impl BundleWriter for PgBundleWriter {
    async fn save(&self, user_id: i64, bundle: &StoredBundle, at: Stamp) -> Result<SaveOutcome> {
        let owner = column_id(user_id)?;
        let device = optional_column_id(bundle.device_id)?;
        let signed_prekey_id = column_id(bundle.signed_prekey_id)?;
        let kyber_id = optional_column_id(bundle.device_kyber_id)?;
        let moment = at.reading();

        let mut transaction = self.handle.pool().begin().await?;

        let updated = sqlx::query!(
            r#"
            UPDATE prekey_bundles
            SET identity_key = $3,
                signed_prekey = $4,
                signed_prekey_sig = $5,
                signed_prekey_id = $6,
                identity_key_ed = $7,
                identity_key_sig = $8,
                supports_v2 = $9,
                device_x3dh_pub = $10,
                device_sign_pub = $11,
                device_cert_sig = $12,
                client_device_id = $13,
                device_kyber_pub = $14,
                device_kyber_sig = $15,
                device_kyber_id = $16,
                updated_at = $17
            WHERE id = (
                SELECT id
                FROM prekey_bundles
                WHERE user_id = $1 AND device_id IS NOT DISTINCT FROM $2
                ORDER BY id
                LIMIT 1
                FOR UPDATE
            )
            RETURNING id
            "#,
            owner,
            device,
            bundle.identity_key.as_slice(),
            bundle.signed_prekey.as_slice(),
            bundle.signed_prekey_sig.as_slice(),
            signed_prekey_id,
            bundle.identity_key_ed.as_deref(),
            bundle.identity_key_sig.as_deref(),
            bundle.supports_v2,
            bundle.device_x3dh_pub.as_deref(),
            bundle.device_sign_pub.as_deref(),
            bundle.device_cert_sig.as_deref(),
            bundle.client_device_id.as_deref(),
            bundle.device_kyber_pub.as_deref(),
            bundle.device_kyber_sig.as_deref(),
            kyber_id,
            moment
        )
        .fetch_optional(&mut *transaction)
        .await?;

        let outcome = match updated {
            Some(row) => SaveOutcome::Updated(i64::from(row.id)),
            None => {
                let created = sqlx::query!(
                    r#"
                    INSERT INTO prekey_bundles (
                        user_id, device_id, identity_key, signed_prekey, signed_prekey_sig,
                        signed_prekey_id, identity_key_ed, identity_key_sig, supports_v2,
                        device_x3dh_pub, device_sign_pub, device_cert_sig, client_device_id,
                        device_kyber_pub, device_kyber_sig, device_kyber_id, created_at, updated_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                            $17, $17)
                    RETURNING id
                    "#,
                    owner,
                    device,
                    bundle.identity_key.as_slice(),
                    bundle.signed_prekey.as_slice(),
                    bundle.signed_prekey_sig.as_slice(),
                    signed_prekey_id,
                    bundle.identity_key_ed.as_deref(),
                    bundle.identity_key_sig.as_deref(),
                    bundle.supports_v2,
                    bundle.device_x3dh_pub.as_deref(),
                    bundle.device_sign_pub.as_deref(),
                    bundle.device_cert_sig.as_deref(),
                    bundle.client_device_id.as_deref(),
                    bundle.device_kyber_pub.as_deref(),
                    bundle.device_kyber_sig.as_deref(),
                    kyber_id,
                    moment
                )
                .fetch_one(&mut *transaction)
                .await?;
                SaveOutcome::Created(i64::from(created.id))
            }
        };

        transaction.commit().await?;
        Ok(outcome)
    }
}
