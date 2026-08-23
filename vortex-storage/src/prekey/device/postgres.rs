use async_trait::async_trait;

use crate::error::Result;
use crate::ids::column_id;
use crate::pool::handle::PgHandle;
use crate::prekey::device::directory::DeviceDirectory;

#[derive(Debug, Clone)]
pub struct PgDeviceDirectory {
    handle: PgHandle,
}

impl PgDeviceDirectory {
    pub fn new(handle: PgHandle) -> PgDeviceDirectory {
        PgDeviceDirectory { handle }
    }
}

#[async_trait]
impl DeviceDirectory for PgDeviceDirectory {
    async fn device_of(&self, user_id: i64, client_device_id: &str) -> Result<Option<i64>> {
        let owner = column_id(user_id)?;
        let found = sqlx::query!(
            r#"
            SELECT id
            FROM user_devices
            WHERE user_id = $1 AND client_device_id = $2
            ORDER BY id
            LIMIT 1
            "#,
            owner,
            client_device_id
        )
        .fetch_optional(self.handle.pool())
        .await?;
        Ok(found.map(|row| i64::from(row.id)))
    }
}
